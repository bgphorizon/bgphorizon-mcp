"""Shared helpers: response envelope, warnings, and small analytical utilities.

Design rule (see docs/mcp/SERVER-DESIGN.md): every tool response carries
``warnings[]`` and ``meta`` so a model cannot silently misread the data. The
warning codes here do more to keep a model honest than anything else here.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import functools
import ipaddress
from typing import Any, Callable, Iterable, Iterator


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


# -- API warnings pass-through ------------------------------------------------
# The API marks partial results, windows that reach before the data, reduced
# vantage points and shortened history in each response's `warnings`. Before
# 2026-09-30 only 4 of 25 tools passed them on, so a report could not see them.
# Now the client records every response's warnings for the running tool call and
# api_tool() merges them into the tool's result.

_api_warnings: contextvars.ContextVar[list | None] = contextvars.ContextVar("api_warnings", default=None)


@contextlib.contextmanager
def quiet_api_warnings() -> Iterator[None]:
    """API reads inside this block do not add their warnings to the tool result. For
    follow-up checks on single prefixes inside a whole-network tool, where a
    prefix's own warning (e.g. direct_session_only) would read as being about the
    whole network. The tool reports what it concluded from those reads instead."""
    token = _api_warnings.set(None)
    try:
        yield
    finally:
        _api_warnings.reset(token)


def record_api_warnings(raw: Any) -> None:
    """Called by the client for every JSON response that carries warnings."""
    bucket = _api_warnings.get()
    if bucket is not None and raw:
        bucket.extend(normalize_warnings(raw))


def merge_warnings(result: Any, extra: list[dict]) -> Any:
    """Append `extra` to result["warnings"], skipping any already present."""
    if not isinstance(result, dict) or not extra:
        return result
    ws = result.get("warnings")
    if not isinstance(ws, list):
        ws = []
        result["warnings"] = ws
    seen = {(w.get("code"), w.get("message")) for w in ws if isinstance(w, dict)}
    for w in extra:
        key = (w.get("code"), w.get("message"))
        if key not in seen:
            ws.append(w)
            seen.add(key)
    return result


def api_tool(mcp: Any, **kwargs: Any) -> Callable:
    """Use in place of ``@mcp.tool()``: registers the tool and adds every warning the
    API returned during the call to the tool's own ``warnings``."""
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kw: Any) -> Any:
            bucket: list = []
            token = _api_warnings.set(bucket)
            try:
                result = fn(*args, **kw)
            finally:
                _api_warnings.reset(token)
            return merge_warnings(result, bucket)
        return mcp.tool(**kwargs)(wrapper)
    return deco


def normalize_warnings(raw: Any) -> list[dict]:
    """API responses carry warnings either as dicts or as "code: message" strings.
    Return them all as {code, message} dicts so every tool's warnings[] has one shape."""
    out: list[dict] = []
    for w in raw or []:
        if isinstance(w, dict):
            out.append(w)
        elif isinstance(w, str):
            code, sep, msg = w.partition(": ")
            if sep and code and " " not in code:
                out.append(warning(code, msg))
            else:
                out.append(warning("api_warning", w))
    return out


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


def parse_when(value: str, *, end_of_day: bool = False) -> _dt.datetime:
    """Parse an RFC3339 timestamp or a YYYY-MM-DD date (UTC). A bare date is the start of the
    day, or its last second when ``end_of_day``."""
    v = value.strip()
    try:
        if "T" in v:
            t = _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
            return t if t.tzinfo else t.replace(tzinfo=_dt.timezone.utc)
        d = _dt.date.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"expected YYYY-MM-DD or an RFC3339 timestamp, got {value!r}") from exc
    t = _dt.datetime(d.year, d.month, d.day, tzinfo=_dt.timezone.utc)
    return t + _dt.timedelta(days=1, seconds=-1) if end_of_day else t


def rfc3339(t: _dt.datetime) -> str:
    return t.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
