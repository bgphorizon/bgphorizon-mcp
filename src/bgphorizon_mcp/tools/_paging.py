"""Shared API reads: paging over the detections endpoints (detections tool and
health_check) and the session-weighted upstream mix (paths, visibility, locate)."""

from __future__ import annotations

import datetime as _dt
from typing import Any, Optional

from ..client import BGPHorizonClient
from ..common import parse_when, rfc3339, warning
from . import _shape

# The /api/v1 gateway caps a detections page at 500.
PAGE_SIZE = 500


class DetectionsUnavailable(Exception):
    """The gateway returned its empty placeholder (pagination.limit == 0) instead of a
    result page: the requested detection type is not available to this caller. Callers
    that would otherwise report "none found" must omit the result instead."""


def fetch_detections(
    client: BGPHorizonClient,
    *,
    asn: Optional[int],
    prefix: Optional[str],
    params: dict[str, Any],
    offset: int = 0,
    max_incidents: int = 1000,
) -> tuple[list[dict], Optional[int], Optional[int]]:
    """Read incidents from `offset` until `max_incidents` are collected or the result
    set ends. Returns (incidents, total, next_offset); next_offset is None when every
    matching incident from `offset` on was read.

    The offset advances by the page size *requested*, not by how many incidents came
    back: the gateway drops incidents the caller's plan cannot see after paging, so a
    page can be short (or empty) without being the last one. Advancing by the returned
    count would re-read or skip incidents."""
    incidents: list[dict] = []
    total: Optional[int] = None
    pos = offset
    while len(incidents) < max_incidents:
        limit = min(PAGE_SIZE, max_incidents - len(incidents))
        page_params = {**params, "offset": pos, "limit": limit}
        if asn is not None:
            resp = client.detections_asn(asn, **page_params)
        else:
            resp = client.detections_prefix(prefix, **page_params)
        pag = resp.get("pagination") or {}
        page = resp.get("incidents", []) or []
        if pos == offset and not page and not pag.get("limit"):
            raise DetectionsUnavailable()
        total = pag.get("total", total)
        incidents.extend(page)
        pos += limit
        if total is None:
            if len(page) < limit:
                return incidents, total, None
        elif pos >= total:
            return incidents, total, None
    return incidents, total, pos


# /prefix/upstreams reads raw events and accepts at most 31 days.
UPSTREAMS_MAX_DAYS = 31


def session_upstreams(
    client: BGPHorizonClient,
    prefix: str,
    start: str,
    end: str,
    *,
    origin_as: Optional[int] = None,
    paths: Optional[list[dict]] = None,
) -> tuple[list[dict], Optional[float], list[dict]]:
    """Upstream mix for a prefix with one vote per collector session. Returns
    (upstreams, direct_share, warnings). A window longer than the endpoint allows is
    cut to its last 31 days, with a warning. If the call fails and overview `paths`
    are given, falls back to their update-weighted mix and says so."""
    warnings: list[dict] = []
    t_end = parse_when(end, end_of_day=True)
    t_start = parse_when(start)
    floor = t_end - _dt.timedelta(days=UPSTREAMS_MAX_DAYS) + _dt.timedelta(seconds=1)
    if t_start < floor:
        t_start = floor
        warnings.append(
            warning(
                "upstreams_window_cut",
                f"The upstream mix covers the last {UPSTREAMS_MAX_DAYS} days of the window "
                f"(from {t_start.date().isoformat()}).",
            )
        )
    params: dict[str, Any] = {"from": rfc3339(t_start), "to": rfc3339(t_end)}
    if origin_as is not None:
        params["origin_as"] = origin_as
    try:
        resp = client.prefix_upstreams(prefix, **params)
    except Exception:  # noqa: BLE001
        if paths is None:
            return [], None, warnings
        warnings.append(
            warning(
                "upstreams_by_updates",
                "The per-session upstream mix was unavailable, so shares are of observed "
                "updates over the top paths. One peer that sends many updates can dominate "
                "them; do not quote them as the prefix's transit mix.",
            )
        )
        return _shape.aggregate_upstreams(paths), _shape.direct_share(paths), warnings
    ups = [
        {
            "asn": u.get("asn"),
            "origin_as": u.get("origin_as"),
            "sessions": u.get("sessions"),
            "share": u.get("share"),
        }
        for u in resp.get("upstreams") or []
    ]
    return ups, resp.get("direct_share"), warnings
