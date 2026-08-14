"""Investigation tools (12) — analysing a network you do not run.

Each tool is an analytical operation, not a REST route: it composes one or more
``/api/v1`` calls and annotates the result with ``warnings`` so the model cannot
silently misread it (persistence, vantage-point concentration, host routes, …).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import BGPHorizonClient
from ..common import (
    concentration_warning,
    default_window,
    host_route_warning,
    length_distribution,
    meta,
    normalize_asn,
    parse_target,
    prefix_addresses,
    warning,
    window_from_shorthand,
)
from . import _shape


def register_investigation_tools(mcp: FastMCP, client: BGPHorizonClient) -> None:

    # -- identify ------------------------------------------------------------
    @mcp.tool()
    def identify(
        asn: Optional[int] = None,
        prefix: Optional[str] = None,
        include: Optional[list[str]] = None,
    ) -> dict:
        """Who is this ASN or prefix? Registry, RPKI, IRR and PeeringDB in one call.

        The right first step in almost any investigation. Give either `asn` or
        `prefix`. `include` may list rdap, rpki, irr, peeringdb (whois is not yet
        available through the API)."""
        if asn is None and not prefix:
            raise ValueError("provide either asn or prefix")
        include = include or ["rdap", "rpki", "irr"]
        warnings: list[dict] = []

        if asn is not None:
            profile = client.entity_profile(asn=normalize_asn(asn))
            entity = str(normalize_asn(asn))
            kind = "asn"
        else:
            profile = client.entity_profile(prefix=prefix)
            entity = prefix
            kind = "prefix"

        overview = profile.get("overview") or {}
        rdap = profile.get("rdap") or {}
        rpki = profile.get("rpki") or {}
        irr = profile.get("irr") or {}
        pdb = profile.get("peeringdb") or {}

        observed_origins = {
            o.get("origin_as")
            for o in (overview.get("origins") or [])
            if o.get("origin_as") is not None
        }
        irr_objs = _shape.irr_objects(irr, observed_origins)
        for obj in irr_objs:
            if obj.get("stale"):
                warnings.append(
                    warning(
                        "irr_origin_mismatch",
                        f"IRR object names AS{obj['origin_as']} ({obj['source']}), "
                        "which was not observed announcing this prefix.",
                    )
                )

        rpki_origins = sorted(
            {r.get("origin_asn") for r in (rpki.get("records") or []) if r.get("origin_asn")}
        )
        result: dict[str, Any] = {
            "kind": kind,
            "entity": entity,
            "name": rdap.get("name") or overview.get("as_name"),
            "registrant": _shape.registrant_name(rdap),
            "registered": rdap.get("registration_date"),
            "last_changed": rdap.get("last_changed_date"),
            "abuse": _shape.abuse_email(rdap),
        }
        if kind == "asn":
            result["prefix_counts"] = {
                "v4": overview.get("prefixes_v4"),
                "v6": overview.get("prefixes_v6"),
            }
        if "rpki" in include:
            result["rpki"] = {
                "has_rpki": rpki.get("has_rpki", False),
                "roa_count": len(rpki.get("records") or []),
                "authorized_origins": rpki_origins,
            }
        if "irr" in include:
            result["irr"] = {"objects": irr_objs}
        if "peeringdb" in include:
            net = pdb.get("network") or {}
            result["peeringdb"] = {
                "name": net.get("name"),
                "info_type": net.get("info_type"),
                "ix_count": len(pdb.get("ix_participation") or []),
                "facilities": [
                    {"name": f.get("ix_name"), "city": f.get("ix_city"), "country": f.get("ix_country")}
                    for f in (pdb.get("ix_participation") or [])[:12]
                ],
            }
        if "whois" in include:
            warnings.append(
                warning(
                    "whois_unavailable",
                    "Direct RIR whois enrichment (org-type, mnt-routes, POC validation) "
                    "is not yet exposed through the API; RDAP fields are returned instead.",
                )
            )

        result["warnings"] = warnings
        result["meta"] = meta("registry")
        return result

    # -- inventory -----------------------------------------------------------
    @mcp.tool()
    def inventory(
        asn: int,
        start: Annotated[Optional[str], Field(description="YYYY-MM-DD")] = None,
        end: Optional[str] = None,
        classify: bool = True,
        min_prefix_len: Optional[int] = None,
    ) -> dict:
        """What does this ASN announce, and does it stick?

        Returns each prefix with a **server-computed** persistence classification
        (persistent | intermittent | transient). Do not infer persistence from
        first_seen — use this."""
        asn = normalize_asn(asn)
        start, end = default_window(start, end, days=30)
        pres = client.presence(asn=asn, **{"from": start, "to": end})
        ov = client.asn_overview(asn, start_date=start, end_date=end)

        prefixes = []
        addresses_v4 = 0
        for p in pres.get("prefixes", []):
            plen = p.get("prefix_len")
            if min_prefix_len is not None and plen is not None and plen < min_prefix_len:
                continue
            origins = sorted(
                {
                    o
                    for day in (p.get("origins_by_day") or {}).values()
                    for o in (day.keys() if isinstance(day, dict) else day)
                }
            )
            entry = {
                "prefix": p.get("cidr"),
                "days_present": p.get("days_present"),
                "days_in_window": p.get("days_in_window"),
                "origins": [int(o) for o in origins],
            }
            if classify:
                entry["classification"] = p.get("classification")
            prefixes.append(entry)
            cidr = p.get("cidr") or ""
            if ":" not in cidr:
                addresses_v4 += prefix_addresses(cidr)

        dist = length_distribution(pres.get("prefixes", []))
        warnings = host_route_warning(dist)
        warnings += pres.get("warnings", []) if isinstance(pres.get("warnings"), list) else []

        return {
            "asn": asn,
            "totals": {
                "v4": ov.get("prefixes_v4"),
                "v6": ov.get("prefixes_v6"),
                "addresses_v4": addresses_v4,
            },
            "length_distribution": dist,
            "prefixes": prefixes,
            "warnings": warnings,
            "meta": meta("rollup"),
        }

    # -- timeline ------------------------------------------------------------
    @mcp.tool()
    def timeline(
        target: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
        granularity: Literal["day", "week"] = "day",
        group_by: Literal["none", "origin", "collector"] = "none",
    ) -> dict:
        """Counts over time for `target` (asn:13335 or prefix:1.1.1.0/24). Replaces
        bulk event downloads. `group_by=origin` at daily granularity is the handover
        chart. Hour granularity and peer/event_type grouping are not available (the
        underlying rollup is daily)."""
        kind, value = parse_target(target)
        start, end = default_window(start, end, days=30)
        params: dict[str, Any] = {"from": start, "to": end, "granularity": granularity}
        if group_by != "none":
            params["group_by"] = group_by
        ts = client.timeseries(f"{kind}:{value}", **params)

        points = ts.get("points", [])
        vals = [p.get("announcements", 0) for p in points]
        vals_sorted = sorted(vals)
        median = vals_sorted[len(vals_sorted) // 2] if vals_sorted else 0
        peak = max(vals) if vals else 0
        peak_at = next((p["t"] for p in points if p.get("announcements") == peak), None)

        warnings = concentration_warning(ts.get("concentration"))
        return {
            "target": target,
            "granularity": granularity,
            "group_by": group_by,
            "points": points,
            "summary": {
                "peak": peak,
                "peak_at": peak_at,
                "median": median,
                "total": ts.get("meta", {}).get("total", sum(vals)),
            },
            "concentration": ts.get("concentration"),
            "warnings": warnings,
            "meta": meta(ts.get("meta", {}).get("source", "rollup")),
        }

    # -- origin_history ------------------------------------------------------
    @mcp.tool()
    def origin_history(
        prefix: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """Day-by-day origins for a prefix — THE persistence check. Returns each
        day's origin set, MOAS days, and classified transitions (handover vs
        episode vs intermittent). This is the direct fix for mistaking a transient
        blip for a migration."""
        start, end = default_window(start, end, days=60)
        pres = client.presence(prefix=prefix, **{"from": start, "to": end})
        target = pres.get("prefixes", [{}])
        obd = target[0].get("origins_by_day", {}) if target else {}
        if not obd:
            obd = pres.get("origins_by_day", {})

        days = _shape.days_from_origins_by_day(obd)
        transitions = _shape.transitions_from_days(days)
        distinct = sorted({o for d in days for o in d["origins"]})
        moas_days = sum(1 for d in days if d["moas"])

        warnings = pres.get("warnings", []) if isinstance(pres.get("warnings"), list) else []
        if not transitions and len(distinct) <= 1:
            warnings.append(
                warning(
                    "stable_origin",
                    "A single origin across the window — no handover or contest to narrate.",
                )
            )
        return {
            "prefix": prefix,
            "days": days,
            "transitions": transitions,
            "summary": {"distinct_origins": distinct, "moas_days": moas_days},
            "warnings": warnings,
            "meta": meta("rollup"),
        }

    # -- reachability --------------------------------------------------------
    @mcp.tool()
    def reachability(
        prefixes: list[str],
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """How many observing peers had no route, and when. Returns an event-driven
        series plus server-computed outage windows (>=5% of peers routeless). Accepts
        multiple prefixes so a multi-prefix event resolves in one call. Keep the
        window tight — this reads raw events."""
        start, end = default_window(start, end, days=1)
        results = []
        warnings: list[dict] = []
        for pfx in prefixes:
            r = client.reachability(pfx, **{"from": start, "to": end})
            summary = r.get("summary", {})
            results.append(
                {
                    "prefix": r.get("cidr", pfx),
                    "series": r.get("series", []),
                    "windows": summary.get("windows", []),
                    "peers_tracked": summary.get("peers_tracked"),
                    "peak_pct": summary.get("peak_pct"),
                    "peak_at": summary.get("peak_at"),
                }
            )
        if len(prefixes) > 1:
            warnings.append(
                warning(
                    "multi_prefix",
                    "Series are per-prefix; a shared outage window appearing across all "
                    "prefixes points at a common upstream rather than a per-prefix issue.",
                )
            )
        out: dict[str, Any] = {"results": results, "warnings": warnings, "meta": meta("raw_events")}
        if len(results) == 1:
            out.update(results[0])
        return out

    # -- detections ----------------------------------------------------------
    @mcp.tool()
    def detections(
        asn: Optional[int] = None,
        prefix: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        detection_type: Optional[str] = None,
        anomalous_only: bool = True,
    ) -> dict:
        """Platform findings for an ASN or prefix, with direction made explicit.
        `direction` (queried_entity_is_invalid_party | queried_entity_is_baseline |
        third_party) tells you whether the queried entity is the offender or the
        victim — reading actor_as against baseline_asns by hand inverts conclusions."""
        if asn is None and not prefix:
            raise ValueError("provide either asn or prefix")
        start, end = default_window(start, end, days=90)
        params: dict[str, Any] = {"from": start, "to": end, "limit": 200}
        if detection_type:
            params["type"] = detection_type
        if anomalous_only:
            params["anomalous"] = "true"

        norm_asn = normalize_asn(asn) if asn is not None else None
        if norm_asn is not None:
            resp = client.detections_asn(norm_asn, **params)
        else:
            resp = client.detections_prefix(prefix, **params)

        incidents = resp.get("incidents", []) or []
        for inc in incidents:
            d = _shape.detection_direction(inc, norm_asn)
            if d:
                inc["direction"] = d
        return {
            "query": {"asn": norm_asn, "prefix": prefix, "anomalous_only": anomalous_only},
            "incidents": incidents,
            "counts_by_type": _shape.counts_by(incidents, "detection_type"),
            "counts_by_severity": _shape.counts_by(incidents, "severity"),
            "warnings": [],
            "meta": meta("registry", total=resp.get("pagination", {}).get("total")),
        }

    # -- paths ---------------------------------------------------------------
    @mcp.tool()
    def paths(
        prefix: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """Transit structure for a prefix with prepending resolved: immediate
        upstreams and their share, plus top paths with collapsed_path / prepend_count."""
        start, end = default_window(start, end, days=30)
        ov = client.prefix_overview(prefix, start_date=start, end_date=end)
        path_list = ov.get("paths", []) or []
        warnings = concentration_warning(ov.get("concentration"))
        return {
            "prefix": prefix,
            "upstreams": _shape.aggregate_upstreams(path_list),
            "paths": [
                {
                    "path_string": p.get("path_string"),
                    "count": p.get("count"),
                    "origin_as": p.get("origin_as"),
                    "upstream_as": p.get("upstream_as"),
                    "prepend_count": p.get("prepend_count"),
                    "collapsed_path": p.get("collapsed_path"),
                }
                for p in path_list
            ],
            "observations": _shape.prepend_observations(path_list),
            "concentration": ov.get("concentration"),
            "warnings": warnings,
            "meta": meta("rollup"),
        }

    # -- compare_windows -----------------------------------------------------
    @mcp.tool()
    def compare_windows(
        target: str,
        window_a: dict,
        window_b: dict,
        dimension: Literal["volume", "origin", "collector"] = "volume",
    ) -> dict:
        """Baseline (window_a) vs event (window_b) for a target. Each window is
        {from, to}. `dimension=volume` compares totals; origin/collector compares the
        per-group breakdown so a new origin or a shifted collector mix is obvious.
        (upstream/paths comparison is not available via the rollup — use `paths`.)"""
        kind, value = parse_target(target)
        gb = None if dimension == "volume" else dimension

        def fetch(win: dict) -> dict:
            p = {"from": win.get("from"), "to": win.get("to"), "granularity": "day"}
            if gb:
                p["group_by"] = gb
            return client.timeseries(f"{kind}:{value}", **p)

        a, b = fetch(window_a), fetch(window_b)

        def totals(ts: dict) -> dict:
            if not gb:
                return {"total": ts.get("meta", {}).get("total", 0)}
            agg: dict[str, int] = {}
            for pt in ts.get("points", []):
                for k, v in (pt.get("groups") or {}).items():
                    agg[k] = agg.get(k, 0) + v
            return dict(sorted(agg.items(), key=lambda kv: -kv[1]))

        ta, tb = totals(a), totals(b)
        warnings = concentration_warning(b.get("concentration"))
        result = {
            "target": target,
            "dimension": dimension,
            "window_a": {**window_a, "totals": ta},
            "window_b": {**window_b, "totals": tb},
        }
        if gb:
            appeared = sorted(set(tb) - set(ta))
            disappeared = sorted(set(ta) - set(tb))
            result["changes"] = {"appeared_in_b": appeared, "absent_in_b": disappeared}
        else:
            av, bv = ta["total"], tb["total"]
            result["changes"] = {
                "delta": bv - av,
                "ratio": round(bv / av, 3) if av else None,
            }
        result["warnings"] = warnings
        result["meta"] = meta("rollup")
        return result

    # -- locate --------------------------------------------------------------
    @mcp.tool()
    def locate(
        asn: Optional[int] = None,
        prefix: Optional[str] = None,
    ) -> dict:
        """Facility/IX intersection across an entity's upstreams — routing-only
        geolocation. Finds cities common to all upstreams' PeeringDB presence, which
        is far more reliable than GeoIP for leased/anycast space. Give a prefix (or an
        ASN, whose top prefix is used to derive upstreams)."""
        if asn is None and not prefix:
            raise ValueError("provide either asn or prefix")

        target_prefix = prefix
        if target_prefix is None:
            pres = client.presence(asn=normalize_asn(asn))
            plist = pres.get("prefixes", [])
            if not plist:
                raise ValueError("ASN announces no prefixes in the window")
            target_prefix = max(plist, key=lambda p: p.get("days_present", 0)).get("cidr")

        ov = client.prefix_overview(target_prefix)
        upstreams = _shape.aggregate_upstreams(ov.get("paths", []) or [])
        upstream_asns = [u["asn"] for u in upstreams[:6]]

        cities_per_upstream: dict[int, set[tuple[str, str]]] = {}
        facilities_by_city: dict[tuple[str, str], set[str]] = {}
        for up in upstream_asns:
            try:
                pdb = client.peeringdb_asn(up)
            except Exception:  # noqa: BLE001
                continue
            cities: set[tuple[str, str]] = set()
            for ix in pdb.get("ix_participation") or []:
                city = (ix.get("ix_city") or "", ix.get("ix_country") or "")
                if city != ("", ""):
                    cities.add(city)
                    facilities_by_city.setdefault(city, set()).add(ix.get("ix_name") or "")
            cities_per_upstream[up] = cities

        common = (
            set.intersection(*cities_per_upstream.values())
            if cities_per_upstream
            else set()
        )
        all_common = [
            {"city": c[0], "country": c[1], "facilities": sorted(f for f in facilities_by_city[c] if f)}
            for c in sorted(common)
        ]
        assessment = None
        if all_common:
            best = all_common[0]
            assessment = {
                "most_probable": f"{best['city']}, {best['country']}",
                "confidence": "moderate" if len(upstream_asns) >= 2 else "low",
                "basis": "common to all observed upstreams' PeeringDB presence",
            }
        return {
            "target_prefix": target_prefix,
            "upstreams": upstream_asns,
            "facility_intersection": {"all_upstreams": all_common},
            "assessment": assessment,
            "warnings": [
                warning(
                    "geoip_unavailable",
                    "External GeoIP cross-checks are not wired into the API; this is a "
                    "routing-evidence estimate. Prefer it over commercial GeoIP for "
                    "leased or anycast space.",
                )
            ],
            "meta": meta("registry"),
        }

    # -- subprefixes ---------------------------------------------------------
    @mcp.tool()
    def subprefixes(
        prefix: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """Announced more-specifics inside a block, plus an estimate of unrouted
        space — allocated addresses never seen in the table, the easiest kind to
        announce unnoticed."""
        start, end = default_window(start, end, days=30)
        resp = client.prefix_subprefixes(prefix, start_date=start, end_date=end)
        subs = resp.get("subprefixes", []) or []
        unrouted = _shape.unrouted_estimate(prefix, subs)
        warnings = []
        if any(s.get("is_moas") for s in subs):
            warnings.append(
                warning("moas_subprefix", "One or more more-specifics have multiple origins (MOAS).")
            )
        return {
            "prefix": prefix,
            "subprefixes": subs,
            "count": len(subs),
            "unrouted_addresses_estimate": unrouted,
            "warnings": warnings,
            "meta": meta("rollup"),
        }

    # -- events_sample -------------------------------------------------------
    @mcp.tool()
    def events_sample(
        prefix: str,
        start: Annotated[str, Field(description="YYYY-MM-DD; window <= 24h")],
        end: str,
        limit: int = 200,
        origin_as: Optional[int] = None,
        peer_asn: Optional[int] = None,
        collector_id: Optional[str] = None,
        event_type: Optional[Literal["announcement", "withdrawal"]] = None,
    ) -> dict:
        """Bounded raw events for a NARROW window — last resort. Capped at 500 events;
        rejects windows over ~24h. Use only after timeline/reachability/origin_history
        have localised what you need to see at the message level."""
        import datetime as _dt

        try:
            fd = _dt.date.fromisoformat(start)
            td = _dt.date.fromisoformat(end)
        except ValueError as exc:
            raise ValueError("from/to must be YYYY-MM-DD dates") from exc
        if (td - fd).days > 1:
            raise ValueError(
                "window too wide for events_sample (max ~24h). Narrow it, or use "
                "timeline for counts over a longer period."
            )
        limit = max(1, min(limit, 500))
        params: dict[str, Any] = {"start_date": start, "end_date": end, "limit": limit}
        if event_type:
            params["event_type"] = event_type
        resp = client.prefix_events(prefix, **params)
        events = resp.get("events", []) or []

        def keep(e: dict) -> bool:
            if origin_as is not None and e.get("origin_as") != origin_as:
                return False
            if peer_asn is not None and e.get("peer_asn") != peer_asn:
                return False
            if collector_id and e.get("collector_id") != collector_id:
                return False
            return True

        events = [e for e in events if keep(e)][:limit]
        total = resp.get("pagination", {}).get("total", len(events))
        truncated = bool(resp.get("pagination", {}).get("has_more")) or total > len(events)
        warnings = []
        if truncated:
            warnings.append(
                warning(
                    "truncated",
                    f"Showing {len(events)} of ~{total} events. Narrow the window or add "
                    "filters (origin_as, peer_asn, collector_id) rather than reading more.",
                )
            )
        return {
            "prefix": prefix,
            "events": events,
            "returned": len(events),
            "truncated": truncated,
            "warnings": warnings,
            "meta": meta("raw_events"),
        }

    # -- platform_baseline ---------------------------------------------------
    @mcp.tool()
    def platform_baseline(
        window: str = "14d",
        by: Literal["type", "severity"] = "type",
    ) -> dict:
        """Is today unusual, platform-wide? Aggregates recent anomalous detections so
        you can tell an ordinary busy day from a real event. Call this BEFORE
        describing anything as anomalous — an apparent spike is often just the
        platform's normal volume."""
        start, end = window_from_shorthand(window, default_days=14)
        resp = client.detections_search(
            **{"start_date": start, "end_date": end, "limit": 500}
        )
        incidents = resp.get("incidents", []) or []
        total = resp.get("pagination", {}).get("total", len(incidents))
        field = "detection_type" if by == "type" else "severity"
        breakdown = _shape.counts_by(incidents, field)
        warnings = []
        if total > len(incidents):
            warnings.append(
                warning(
                    "sampled_baseline",
                    f"Baseline computed from the {len(incidents)} most recent of ~{total} "
                    "anomalous incidents in the window; treat proportions, not absolute counts.",
                )
            )
        return {
            "window": {"from": start, "to": end},
            "by": by,
            "total_incidents": total,
            "breakdown": breakdown,
            "warnings": warnings,
            "meta": meta("registry"),
        }
