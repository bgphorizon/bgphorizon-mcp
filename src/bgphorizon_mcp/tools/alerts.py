"""Alert tools (2) — the caller's own monitoring, shaped for report writing.

Everything else in this server investigates the global routing table. These two
answer "what did *my* watchlist catch, and over what period" — the raw material
for an incident write-up or a weekly summary.

Both take a window rather than making the model compute dates: `window="today"`
is the common case ("pull down all alerts fired today"), and the server returns
the resolved absolute window in `meta` so the write-up can state it exactly.
"""

from __future__ import annotations

from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import BGPHorizonClient
from ..common import meta, warning

# A window this wide almost certainly means the caller wanted a narrower one; we
# still serve it, but say so, because a "daily report" over 90 days is wrong.
_WIDE_WINDOW_DAYS = 31

# Detection types that are informational by design. A report that leads with them
# reads as alarming when nothing alarming happened.
_INFORMATIONAL = {"roa_change", "irr_change", "new_prefix", "unregistered_route"}


def _window_params(window: str, start: str | None, end: str | None) -> dict:
    """Explicit start/end wins; otherwise the shorthand goes to the API as-is.

    The API understands dates, RFC3339, relative windows (24h/7d) and "today", so
    shorthand is passed through rather than resolved here — one parser, server-side.

    The tool parameters are `start`/`end` rather than `from`/`to` because `from` is
    a Python keyword: FastMCP would publish it in the schema and then fail to bind
    it at call time. `start`/`end` is also what every other tool here uses.
    """
    if start or end:
        return {"from": start, "to": end}
    return {"from": window}


def register_alert_tools(mcp: FastMCP, client: BGPHorizonClient) -> None:

    # -- my_alerts -----------------------------------------------------------
    @mcp.tool()
    def my_alerts(
        window: Annotated[
            str,
            Field(description='Window to pull: "today", a relative span like "24h"/"7d"/"30d", or a date. Ignored when from/to are given.'),
        ] = "today",
        start: Annotated[Optional[str], Field(description="Explicit window start (YYYY-MM-DD or RFC3339). Overrides `window`.")] = None,
        end: Annotated[Optional[str], Field(description="Explicit window end (YYYY-MM-DD or RFC3339).")] = None,
        detection_type: Annotated[Optional[str], Field(description="Restrict to one detection type, e.g. rpki_invalid_asn.")] = None,
        severity: Annotated[Optional[str], Field(description="Restrict to one severity: info, low, medium, high, critical.")] = None,
        monitor_id: Annotated[Optional[str], Field(description="Restrict to a single monitor.")] = None,
        include_dismissed: Annotated[bool, Field(description="Include alerts already dismissed from the feed. True for a complete record of what fired.")] = True,
        limit: Annotated[int, Field(description="Maximum alerts to return (max 1000).", ge=1, le=1000)] = 200,
    ) -> dict:
        """Alerts YOUR monitors fired over a window — the input to an incident
        report or a daily/weekly summary. Returns the alerts themselves plus
        breakdowns by detection type, severity and monitor, so a write-up can
        lead with totals and drill into specifics without a second call.

        This is your own alert history, not a platform-wide search: it covers
        only prefixes and ASNs you monitor. Use `detections` or `notable_events`
        for anything outside your watchlist."""
        params = _window_params(window, start, end)
        params.update(
            {
                "detection_type": detection_type,
                "severity": severity,
                "monitor_id": monitor_id,
                "include_dismissed": "true" if include_dismissed else None,
                "limit": limit,
            }
        )
        data = client.notifications(**params)

        alerts = data.get("alerts", []) or []
        summary = data.get("summary", {}) or {}
        by_type = summary.get("by_detection_type", []) or []
        total = data.get("total", len(alerts))
        win = data.get("window", {}) or {}

        warnings: list[dict] = []
        if not alerts:
            warnings.append(
                warning(
                    "no_alerts_in_window",
                    "No alerts fired in this window. That is a finding in itself — say so "
                    "plainly rather than widening the window to manufacture material.",
                )
            )
        if data.get("truncated"):
            warnings.append(
                warning(
                    "truncated",
                    f"{total} alerts matched but only {len(alerts)} were returned. Totals in "
                    "`summary` cover the whole window; the `alerts` list does not. Raise `limit` "
                    "or narrow the window before quoting per-alert detail as complete.",
                    total=total,
                    returned=len(alerts),
                )
            )
        # An alert list dominated by informational types is a quiet period, not
        # an incident; leading with a raw count would misrepresent it.
        informational = sum(c.get("count", 0) for c in by_type if c.get("key") in _INFORMATIONAL)
        if total and informational / total >= 0.8:
            warnings.append(
                warning(
                    "mostly_informational",
                    f"{informational} of {total} alerts are informational types "
                    f"({', '.join(sorted(_INFORMATIONAL))}) rather than security anomalies. "
                    "Report this as a quiet window with registry churn, not as an incident.",
                )
            )
        noisiest = (summary.get("by_monitor") or [])[:1]
        if noisiest and total and noisiest[0].get("count", 0) / total >= 0.5:
            n = noisiest[0]
            warnings.append(
                warning(
                    "single_monitor_dominates",
                    f"{n.get('count')} of {total} alerts come from one monitor "
                    f"({n.get('name')}). Attribute the volume to that watch before "
                    "describing a network-wide event.",
                )
            )

        return {
            "window": win,
            "totals": {
                "alerts": total,
                "returned": len(alerts),
                "by_detection_type": by_type,
                "by_severity": summary.get("by_severity", []),
                "by_monitor": summary.get("by_monitor", []),
            },
            "alerts": alerts,
            "warnings": warnings,
            "meta": meta("monitoring", window=win, include_dismissed=include_dismissed),
        }

    # -- my_monitors ---------------------------------------------------------
    @mcp.tool()
    def my_monitors(
        window: Annotated[
            str,
            Field(description='Window the per-monitor alert counts are computed over: "today", "7d", "30d", or a date.'),
        ] = "7d",
        start: Annotated[Optional[str], Field(description="Explicit window start. Overrides `window`.")] = None,
        end: Annotated[Optional[str], Field(description="Explicit window end.")] = None,
        scope: Annotated[str, Field(description='"mine" (default) or "org" for monitors teammates share with your organization.')] = "mine",
        resource: Annotated[Optional[str], Field(description='Restrict to "prefix" or "asn" monitors.')] = None,
        status: Annotated[Optional[str], Field(description='Restrict to "enabled" or "paused".')] = None,
        detection_type: Annotated[Optional[str], Field(description="Only monitors subscribing to this detection type.")] = None,
        q: Annotated[Optional[str], Field(description="Substring of the monitor name, prefix or ASN.")] = None,
        limit: Annotated[int, Field(description="Maximum monitors to return (max 2000).", ge=1, le=2000)] = 500,
    ) -> dict:
        """YOUR watchlist, with each monitor's alert volume over a window — what
        you're covering and which watches are noisy. Use it to scope a report
        ("these 266 prefixes were under watch"), to find monitors worth tuning,
        or to spot coverage gaps before an audit.

        Pair with `my_alerts` for the alerts themselves."""
        params = _window_params(window, start, end)
        params.update(
            {
                "scope": scope,
                "resource": resource,
                "status": status,
                "detection_type": detection_type,
                "q": q,
                "limit": limit,
            }
        )
        data = client.monitors(**params)

        monitors = data.get("monitors", []) or []
        total = data.get("total", len(monitors))
        win = data.get("window", {}) or {}

        active = [m for m in monitors if m.get("enabled")]
        paused = len(monitors) - len(active)
        noisy = sorted(monitors, key=lambda m: m.get("alerts_in_window", 0), reverse=True)
        quiet = [m for m in monitors if not m.get("alerts_in_window")]

        warnings: list[dict] = []
        if paused:
            warnings.append(
                warning(
                    "paused_monitors",
                    f"{paused} of {len(monitors)} monitors are paused and fired nothing by "
                    "definition. Exclude them from coverage claims.",
                    paused=paused,
                )
            )
        if monitors and len(quiet) == len(monitors):
            warnings.append(
                warning(
                    "no_activity",
                    "No monitor fired in this window. Coverage is not the same as activity — "
                    "state that nothing fired rather than implying nothing was watched.",
                )
            )
        # A watchlist where every monitor subscribes to everything is the usual
        # cause of alert fatigue, and the fix is a bulk edit in the web app.
        subscribed_all = [m for m in monitors if len(m.get("detection_types", []) or []) >= 14]
        if monitors and len(subscribed_all) / len(monitors) >= 0.9:
            warnings.append(
                warning(
                    "all_types_subscribed",
                    "Nearly every monitor subscribes to every detection type. If volume is the "
                    "complaint, the fix is removing the informational types "
                    f"({', '.join(sorted(_INFORMATIONAL))}) in bulk from the Monitors page, "
                    "not narrowing the window.",
                )
            )

        return {
            "window": win,
            "totals": {
                "monitors": total,
                "returned": len(monitors),
                "enabled": len(active),
                "paused": paused,
                "quiet_in_window": len(quiet),
                "prefix_monitors": sum(1 for m in monitors if m.get("resource_type") == "prefix"),
                "asn_monitors": sum(1 for m in monitors if m.get("resource_type") == "asn"),
            },
            "most_active": noisy[:10],
            "monitors": monitors,
            "warnings": warnings,
            "meta": meta("monitoring", window=win, scope=data.get("scope", scope)),
        }
