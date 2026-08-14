"""Shared helpers: response envelope, warnings, and small analytical utilities.

Design rule (see docs/mcp/SERVER-DESIGN.md): every tool response carries
``warnings[]`` and ``meta`` so a model cannot silently misread the data. The
warning codes here are the highest-leverage part of the whole server.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
from typing import Any, Iterable


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def meta(source: str, **extra: Any) -> dict:
    """Standard ``meta`` block. ``source`` is rollup | raw_events | registry | composed."""
    return {"source": source, "computed_at": now_iso(), **extra}


def warning(code: str, message: str, **fields: Any) -> dict:
    w = {"code": code, "message": message}
    w.update(fields)
    return w


# -- window parsing ----------------------------------------------------------

def default_window(from_: str | None, to: str | None, *, days: int = 30) -> tuple[str, str]:
    end = to or today().isoformat()
    if from_:
        return from_, end
    try:
        end_d = _dt.date.fromisoformat(end)
    except ValueError:
        end_d = today()
    start = (end_d - _dt.timedelta(days=days)).isoformat()
    return start, end


def parse_duration_days(window: str, *, default: int = 30) -> int:
    """Parse '30d' / '14d' / '90d' → integer days; bare ints accepted."""
    w = str(window).strip().lower()
    if w.endswith("d"):
        w = w[:-1]
    try:
        return max(1, int(w))
    except ValueError:
        return default


def window_from_shorthand(window: str, *, default_days: int = 30) -> tuple[str, str]:
    days = parse_duration_days(window, default=default_days)
    end = today()
    return (end - _dt.timedelta(days=days)).isoformat(), end.isoformat()


def parse_target(target: str) -> tuple[str, str]:
    """'asn:13335' | 'prefix:1.1.1.0/24' → ('asn'|'prefix', value)."""
    if ":" not in target:
        raise ValueError("target must be 'asn:<n>' or 'prefix:<cidr>'")
    kind, _, value = target.partition(":")
    kind = kind.strip().lower()
    if kind not in ("asn", "prefix"):
        raise ValueError("target must start with 'asn:' or 'prefix:'")
    return kind, value.strip()


def normalize_asn(asn: int | str) -> int:
    s = str(asn).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


# -- concentration -----------------------------------------------------------

def concentration_warning(concentration: dict | None) -> list[dict]:
    """Emit ``single_vantage_point`` when one collector dominates observations."""
    if not concentration:
        return []
    share = concentration.get("top_collector_share")
    top = concentration.get("top_collector")
    if isinstance(share, (int, float)) and share >= 0.5:
        pct = round(share * 100)
        return [
            warning(
                "single_vantage_point",
                f"{pct}% of observations come from one collector"
                + (f" ({top})" if top else "")
                + ". Treat volume changes as a possible measurement artifact until "
                "confirmed from other vantage points.",
            )
        ]
    return []


# -- prefix / address math ---------------------------------------------------

def prefix_addresses(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


def length_distribution(prefixes: Iterable[dict]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for p in prefixes:
        plen = p.get("prefix_len")
        if plen is None:
            cidr = p.get("cidr") or ""
            if "/" in cidr:
                plen = cidr.split("/", 1)[1]
        if plen is None:
            continue
        key = str(plen)
        dist[key] = dist.get(key, 0) + 1
    return dict(sorted(dist.items(), key=lambda kv: int(kv[0])))


def host_route_warning(dist: dict[str, int], *, v4_host_len: str = "32", v6_host_len: str = "128") -> list[dict]:
    hosts = dist.get(v4_host_len, 0) + dist.get(v6_host_len, 0)
    if hosts:
        return [
            warning(
                "host_routes_present",
                f"{hosts} host routes (/{v4_host_len} or /{v6_host_len}). These are "
                "widely filtered; exclude them from volume baselines.",
            )
        ]
    return []
