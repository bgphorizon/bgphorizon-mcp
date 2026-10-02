"""Investigation tools (20): analyzing a network you do not run.

Each tool is an analytical operation, not a REST route: it composes one or more
``/api/v1`` calls and annotates the result with ``warnings`` so the model cannot
silently misread it (persistence, vantage-point concentration, host routes, …).
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import BGPHorizonClient
from ..common import (
    api_tool,
    concentration_warning,
    default_window,
    host_route_warning,
    length_distribution,
    meta,
    normalize_asn,
    normalize_warnings,
    parse_target,
    parse_when,
    prefix_addresses,
    rfc3339,
    warning,
)
from . import _paging, _shape
from ._paging import session_upstreams


# Above this many incidents `detections` returns compact rows unless format="full".
COMPACT_INCIDENTS_ABOVE = 200
# Most prefixes `bulk_registry(summary_only=True)` lists individually.
NOTABLE_PREFIXES_MAX = 200


def register_investigation_tools(mcp: FastMCP, client: BGPHorizonClient) -> None:

    # -- identify ------------------------------------------------------------
    @api_tool(mcp)
    def identify(
        asn: Optional[int] = None,
        prefix: Optional[str] = None,
        include: Optional[list[str]] = None,
    ) -> dict:
        """Who is this ASN or prefix? Registry, RPKI, IRR and PeeringDB in one call.

        The right first step in almost any investigation. Give either `asn` or
        `prefix`. `include` may list rdap, rpki, irr, peeringdb (whois is not yet
        available through the API). `country` is the registry's country code and `rir`
        the registry that answered; both are registry records, not where the network
        operates. For many prefixes or ASNs at once use `bulk_registry`."""
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
        # Sections the gateway could not load are listed, not silently empty; say so,
        # so "no ROA" / "no IRR object" is never inferred from a failed read.
        unavailable = profile.get("unavailable") or []
        if unavailable:
            warnings.append(warning(
                "sections_unavailable",
                f"Could not load: {', '.join(unavailable)}. Treat those parts as unknown, not "
                "as absent; retry or check them with bulk_registry.",
            ))
        for w in profile.get("warnings") or []:
            warnings.extend(normalize_warnings([w]))

        observed_origins = {
            o.get("origin_as")
            for o in (overview.get("origins") or [])
            if o.get("origin_as") is not None
        }
        irr_objs = _shape.irr_objects(irr, observed_origins)
        for obj in irr_objs:
            if not obj.get("current", True):
                warnings.append(
                    warning(
                        "irr_object_deleted",
                        f"IRR object for AS{obj['origin_as']} ({obj['source']}) was last present "
                        f"{obj.get('last_seen')}; it is no longer in the registry.",
                    )
                )
            elif obj.get("stale"):
                warnings.append(
                    warning(
                        "irr_origin_mismatch",
                        f"IRR object names AS{obj['origin_as']} ({obj['source']}), "
                        "which was not observed announcing this prefix.",
                    )
                )

        # Prefix lookups return every covering ROA (RFC 6811), including ones whose
        # max_length stops short of the prefix; only matches_length ones authorize it.
        # ASN lookups carry no flag: each of those ROAs authorizes the ASN.
        rpki_origins = sorted(
            {r.get("origin_asn") for r in (rpki.get("records") or [])
             if r.get("origin_asn") and r.get("matches_length", True)}
        )
        result: dict[str, Any] = {
            "kind": kind,
            "entity": entity,
            "name": rdap.get("name") or overview.get("as_name"),
            "registrant": _shape.registrant_name(rdap),
            "registered": rdap.get("registration_date"),
            "last_changed": rdap.get("last_changed_date"),
            "abuse": _shape.abuse_email(rdap),
            "country": rdap.get("country") or None,
            "rir": _shape.rir_from_rdap(rdap),
        }
        if kind == "asn":
            result["prefix_counts"] = {
                "v4": overview.get("prefixes_v4"),
                "v6": overview.get("prefixes_v6"),
            }
        if "rpki" in include:
            result["rpki"] = {
                "has_rpki": None if "rpki" in unavailable else rpki.get("has_rpki", False),
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
    @api_tool(mcp)
    def inventory(
        asn: int,
        start: Annotated[Optional[str], Field(description="YYYY-MM-DD")] = None,
        end: Optional[str] = None,
        classify: bool = True,
        min_prefix_len: Optional[int] = None,
        only: Optional[Literal["persistent", "intermittent", "transient"]] = None,
        summary_only: bool = False,
    ) -> dict:
        """What does this ASN announce, and does it stick?

        Returns each prefix with a **server-computed** persistence classification
        (persistent | intermittent | transient). Do not infer persistence from
        first_seen. Use this. Every row is originated by `asn`.

        Large networks return thousands of rows: pass `only` to keep one class, or
        `summary_only=true` for the counts without the list. To find what an ASN
        announced during a short incident compared with normal, use `origin_episode`
        rather than diffing inventories by hand."""
        asn = normalize_asn(asn)
        start, end = default_window(start, end, days=30)
        pres = client.presence(asn=asn, **{"from": start, "to": end})
        allp = pres.get("prefixes", []) or []

        # Totals describe everything the ASN originated, whatever `only` /
        # `min_prefix_len` keep in the list. Addresses are the union, so a /12 and the
        # /24s inside it are not counted twice. (Totals used to come from a separate
        # overview call, which could disagree with this list.)
        v4_nets = []
        for p in allp:
            cidr = p.get("cidr") or ""
            if cidr and ":" not in cidr:
                try:
                    v4_nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
        addresses_v4 = sum(n.num_addresses for n in ipaddress.collapse_addresses(v4_nets))

        prefixes = []
        by_class: dict[str, int] = {}
        for p in allp:
            plen = p.get("prefix_len")
            if min_prefix_len is not None and plen is not None and plen < min_prefix_len:
                continue
            cls = p.get("classification")
            by_class[cls] = by_class.get(cls, 0) + 1
            if only and cls != only:
                continue
            entry = {
                "prefix": p.get("cidr"),
                "days_present": p.get("days_present"),
                "days_in_window": p.get("days_in_window"),
                "first_seen": p.get("first_seen"),
                "last_seen": p.get("last_seen"),
            }
            if classify:
                entry["classification"] = cls
            prefixes.append(entry)

        dist = length_distribution(allp)
        warnings = host_route_warning(dist)
        warnings += normalize_warnings(pres.get("warnings"))

        out = {
            "asn": asn,
            "window": {"from": start, "to": end},
            "totals": {
                "v4": sum(1 for p in allp if ":" not in (p.get("cidr") or "")),
                "v6": sum(1 for p in allp if ":" in (p.get("cidr") or "")),
                "addresses_v4": addresses_v4,
                "listed": len(prefixes),
            },
            "by_classification": by_class,
            "length_distribution": dist,
            "warnings": warnings,
            "meta": meta("rollup"),
        }
        if not summary_only:
            out["prefixes"] = prefixes
        return out

    # -- timeline ------------------------------------------------------------
    @api_tool(mcp)
    def timeline(
        target: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
        granularity: Literal["day", "week", "hour", "10m", "1m"] = "day",
        group_by: Literal["none", "origin", "collector"] = "none",
    ) -> dict:
        """Counts over time for `target` (asn:13335 or prefix:1.1.1.0/24). Replaces
        bulk event downloads. `group_by=origin` at daily granularity is the handover
        chart.

        `hour`, `10m` and `1m` read raw events for a window of at most 72 hours; give
        `start`/`end` as RFC3339 (2026-06-27T05:30:00Z) or dates. For an ASN target the
        sub-day points also carry `prefixes`, the number of distinct prefixes it
        originated in each bucket, which is how a short leak shows up.

        Withdrawals carry no AS path, so for ASN targets they cannot be attributed to
        the ASN: `withdrawals` is then null, not zero. Use a prefix target, or
        `reachability`, for withdrawal behaviour."""
        kind, value = parse_target(target)
        sub_day = granularity in ("hour", "10m", "1m")
        if sub_day:
            t_end = parse_when(end, end_of_day=True) if end else None
            t_start = parse_when(start) if start else None
            params: dict[str, Any] = {"granularity": granularity}
            if t_start:
                params["from"] = rfc3339(t_start)
            if t_end:
                params["to"] = rfc3339(t_end)
        else:
            start, end = default_window(start, end, days=30)
            params = {"from": start, "to": end, "granularity": granularity}
        if group_by != "none":
            params["group_by"] = group_by
        ts = client.timeseries(f"{kind}:{value}", **params)

        ts_meta = ts.get("meta", {}) or {}
        withdrawals_ok = ts_meta.get("withdrawals_available", kind != "asn")
        points = ts.get("points", []) or []
        if not withdrawals_ok:
            for p in points:
                p["withdrawals"] = None
        vals = [p.get("announcements", 0) for p in points]
        vals_sorted = sorted(vals)
        median = vals_sorted[len(vals_sorted) // 2] if vals_sorted else 0
        peak = max(vals) if vals else 0
        peak_at = next((p["t"] for p in points if p.get("announcements") == peak), None)

        warnings = concentration_warning(ts.get("concentration"))
        if not withdrawals_ok:
            warnings.append(
                warning(
                    "withdrawals_unattributable",
                    "Withdrawals carry no AS path, so they cannot be attributed to an ASN; "
                    "withdrawal counts are omitted for ASN targets, not zero.",
                )
            )
        return {
            "target": target,
            "granularity": granularity,
            "group_by": group_by,
            "window": {"from": ts.get("from"), "to": ts.get("to")},
            "points": points,
            "summary": {
                "peak": peak,
                "peak_at": peak_at,
                "median": median,
                "total": ts_meta.get("total", sum(vals)),
            },
            "concentration": ts.get("concentration"),
            "warnings": warnings,
            "meta": meta(ts_meta.get("source", "rollup")),
        }

    # -- origin_history ------------------------------------------------------
    @api_tool(mcp)
    def origin_history(
        prefix: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """Day-by-day origins for a prefix. This is the persistence check. Returns each
        day's origin set, MOAS days, and classified transitions (handover vs
        episode vs intermittent). This is the direct fix for mistaking a transient
        blip for a migration."""
        start, end = default_window(start, end, days=60)
        pres = client.presence(prefix=prefix, **{"from": start, "to": end})
        target = pres.get("prefixes", [{}])
        obd = (target[0].get("origins_by_day") or {}) if target else {}
        if not obd:
            obd = (pres.get("origins_by_day") or {})

        days = _shape.days_from_origins_by_day(obd)
        transitions = _shape.transitions_from_days(days)
        distinct = sorted({o for d in days for o in d["origins"]})
        moas_days = sum(1 for d in days if d["moas"])

        warnings = normalize_warnings(pres.get("warnings"))
        if not transitions and len(distinct) <= 1:
            warnings.append(
                warning(
                    "stable_origin",
                    "A single origin across the window. No handover or contest to narrate.",
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
    @api_tool(mcp)
    def reachability(
        prefixes: list[str],
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """How many observing peers had no route, and when. Returns an event-driven
        series plus server-computed outage windows (>=5% of peers routeless). Accepts
        multiple prefixes so a multi-prefix event resolves in one call. Keep the
        window tight; this reads raw events."""
        start, end = default_window(start, end, days=1)
        results = []
        warnings: list[dict] = []
        for pfx in prefixes:
            r = client.reachability(pfx, **{"from": start, "to": end})
            summary = (r.get("summary") or {})
            results.append(
                {
                    "prefix": r.get("cidr", pfx),
                    "series": (r.get("series") or []),
                    "windows": (summary.get("windows") or []),
                    "peers_tracked": summary.get("peers_tracked"),
                    "peak_pct": summary.get("peak_pct"),
                    "peak_at": summary.get("peak_at"),
                }
            )
            # A prefix no ROA authorizes at its length (e.g. only an AS0 or a too-short
            # max_length ROA covers it) is dropped by validating networks all the time, so
            # its "routeless" peers are mostly filtering, not an outage.
            try:
                recs = (client.rpki_prefix(pfx) or {}).get("records") or []
            except Exception:  # noqa: BLE001
                recs = []
            if recs and not any(r.get("matches_length", True) and r.get("origin_asn") for r in recs):
                results[-1]["rpki"] = "invalid_for_every_origin"
                warnings.append(warning(
                    "rpki_invalid_prefix",
                    f"{pfx} is RPKI-invalid for every origin (its covering ROAs are AS0 or stop short "
                    "of its length), so networks performing origin validation drop it; routeless "
                    "peers and outage windows here mostly reflect that filtering, not an outage.",
                ))
        if len(prefixes) > 1:
            warnings.append(
                warning(
                    "multi_prefix",
                    "Series are per-prefix; a shared outage window appearing across all "
                    "prefixes points at a common upstream rather than a per-prefix issue.",
                )
            )
        # One prefix: its fields at the top level. Several: a `results` list. (Both forms
        # at once doubled the response.)
        out: dict[str, Any] = dict(results[0]) if len(results) == 1 else {"results": results}
        out.update({"warnings": warnings, "meta": meta("raw_events")})
        return out

    # -- global reach --------------------------------------------------------
    @api_tool(mcp)
    def global_reach(prefix: str) -> dict:
        """How globally reachable a prefix is: the share of full-table feeds that see it over a
        30-day footprint, classified global / regional / local, with a per-region penetration
        breakdown. Distinct from ``reachability`` (which tracks per-peer routeless windows over a
        tight time span). This answers "is this prefix propagated worldwide, or only in some
        regions?". A regional or local result can indicate a route leak, upstream filtering, or
        limited propagation. Region reflects the observing collector's location (a vantage proxy),
        not the announcing network's geography. Each feed counts in one region, so a region's
        ``seen`` never exceeds its ``feeds``. A region's ``pct`` is ``seen`` over ``baseline``
        (the feeds there a widely routed prefix typically reaches), so 100% means as visible as a
        typical global route in that region."""
        v = client.prefix_visibility(prefix)
        return {
            "prefix": v.get("prefix", prefix),
            "reach_pct": v.get("pct"),
            "class": v.get("class"),
            "seen_feeds": v.get("seen_feeds"),
            "total_feeds": v.get("total_feeds"),
            "window_days": v.get("window_days"),
            "regions": (v.get("regions") or []),
            "meta": meta("rollup", window_days=v.get("window_days", 30)),
        }

    # -- detections ----------------------------------------------------------
    @api_tool(mcp)
    def detections(
        asn: Optional[int] = None,
        prefix: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        detection_type: Optional[str] = None,
        anomalous_only: bool = True,
        prefix_status: Optional[str] = None,
        role: Optional[Literal["actor", "baseline"]] = None,
        state: Optional[Literal["active", "resolved"]] = None,
        max_incidents: Annotated[int, Field(ge=1, le=5000)] = 1000,
        offset: Annotated[int, Field(ge=0, description="Resume from this position; pass the previous call's next_offset")] = 0,
        summary_only: bool = False,
        format: Literal["auto", "full", "compact"] = "auto",
    ) -> dict:
        """Platform findings for an ASN or prefix, with direction made explicit.
        `direction` (queried_entity_is_invalid_party | queried_entity_is_baseline |
        queried_entity_announced_own_space | third_party) tells you whether the queried
        entity is the offender, the victim, or changing routes inside its own space.
        Reading actor_as against baseline_asns by hand inverts conclusions.

        Pages through the API until `max_incidents` or the end. `complete=true` means
        every matching incident was read, so counts in `summary` are exact. When false,
        `next_offset` is set: call again with the same arguments and `offset=next_offset`
        to read the next batch, repeating until `next_offset` is null. Counts and
        `summary` describe only the incidents in this call, so add batches up yourself or
        narrow (a shorter window or a `detection_type`) before stating a total.
        `summary_only=true` returns the aggregates without the incident list. Start with
        it on a busy entity, then narrow.

        `format`: "full" lists every incident with `details` as an object. "compact"
        returns `incidents_compact`, one row per incident under a shared column list and
        without `details`, about a fifth of the size. "auto" (default) is full up to 200
        incidents and compact above that. Look up a single prefix for the details.

        Filters: `detection_type`, `prefix_status` (established | new | new_more_specific
        | returned), `role` for an ASN (actor = it made the claim, baseline = its space
        was claimed), `state` (active | resolved)."""
        if asn is None and not prefix:
            raise ValueError("provide either asn or prefix")
        start, end = default_window(start, end, days=90)
        params: dict[str, Any] = {"from": start, "to": end, "limit": 500}
        if detection_type:
            params["type"] = detection_type
        if anomalous_only:
            params["anomalous"] = "true"
        if prefix_status:
            params["prefix_status"] = prefix_status
        if role and asn is not None:
            params["role"] = role
        if state:
            params["state"] = state

        norm_asn = normalize_asn(asn) if asn is not None else None
        try:
            incidents, total, next_offset = _paging.fetch_detections(
                client, asn=norm_asn, prefix=prefix, params=params, offset=offset, max_incidents=max_incidents
            )
        except _paging.DetectionsUnavailable:
            incidents, total, next_offset = [], 0, None

        for inc in incidents:
            _shape.parse_details(inc)
            d = _shape.detection_direction(inc, norm_asn)
            if d:
                inc["direction"] = d
        complete = offset == 0 and next_offset is None
        warnings: list[dict] = []
        if next_offset is not None:
            warnings.append(
                warning(
                    "incomplete",
                    f"Read positions {offset} to {next_offset} of {total} matching incidents. Counts "
                    f"below cover only those; call again with offset={next_offset} for the next "
                    "batch, or narrow the window or detection_type.",
                )
            )
        elif offset:
            warnings.append(
                warning(
                    "partial_from_offset",
                    f"This is the final batch, starting at offset {offset}; counts cover only it.",
                )
            )
        out: dict[str, Any] = {
            "query": {
                "asn": norm_asn, "prefix": prefix, "from": start, "to": end,
                "detection_type": detection_type, "anomalous_only": anomalous_only,
            },
            "total_matching": total,
            "offset": offset,
            "returned": len(incidents),
            "next_offset": next_offset,
            "complete": complete,
            "counts_by_type": _shape.counts_by(incidents, "detection_type"),
            "counts_by_severity": _shape.counts_by(incidents, "severity"),
            "summary": _shape.detections_summary(incidents),
            "warnings": warnings,
            "meta": meta("registry", total=total),
        }
        if not summary_only:
            if format == "compact" or (format == "auto" and len(incidents) > COMPACT_INCIDENTS_ABOVE):
                out["incidents_compact"] = _shape.compact_incidents(incidents)
                if format == "auto":
                    warnings.append(
                        warning(
                            "compact_incidents",
                            f"{len(incidents)} incidents are returned as compact rows without details. "
                            "Pass format='full' or narrow the query to see details.",
                        )
                    )
            else:
                out["incidents"] = incidents
        return out

    # -- paths ---------------------------------------------------------------
    @api_tool(mcp)
    def paths(
        prefix: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
        origin_as: Optional[int] = None,
    ) -> dict:
        """Transit structure for a prefix with prepending resolved: immediate
        upstreams, plus top paths with collapsed_path / prepend_count.

        `upstreams` count collector sessions (each session once, through the upstream
        in its latest announcement in the window; at most the last 31 days), so they
        are the prefix's transit mix. `direct_share` is the share of sessions that are
        the origin's own (the path is the origin alone). Path `count` is update volume,
        which one noisy peer can dominate: use it for which paths exist, not how common
        they are.

        Pass `origin_as` to see only one origin's paths. On a contested prefix the top
        paths otherwise all belong to the usual origin, and a short hijack's paths never
        make the list."""
        start, end = default_window(start, end, days=30)
        params: dict[str, Any] = {"start_date": start, "end_date": end}
        if origin_as is not None:
            params["origin_as"] = normalize_asn(origin_as)
        ov = client.prefix_overview(prefix, **params)
        path_list = ov.get("paths", []) or []
        warnings = concentration_warning(ov.get("concentration"))
        if origin_as is not None and not path_list:
            warnings.append(
                warning("no_paths_for_origin", f"No paths from AS{normalize_asn(origin_as)} in the window.")
            )
        upstreams, direct, up_warnings = session_upstreams(
            client, prefix, start, end,
            origin_as=normalize_asn(origin_as) if origin_as is not None else None,
            paths=path_list,
        )
        warnings.extend(up_warnings)
        # The upstreams endpoint warns direct_session_only itself; the update-weighted
        # fallback does not, so say it here in that case.
        if any(w["code"] == "upstreams_by_updates" for w in up_warnings) and path_list and direct == 1.0:
            warnings.append(
                warning(
                    "direct_session_only",
                    "Every observed path is the origin alone: the route was seen only on the "
                    "origin's own session with a route collector, and no other network was "
                    "seen propagating it.",
                )
            )
        return {
            "prefix": prefix,
            "origin_as": normalize_asn(origin_as) if origin_as is not None else None,
            "upstreams": upstreams,
            "direct_share": direct,
            "paths": [
                {
                    "path_string": p.get("path_string"),
                    "count": p.get("count"),
                    "origin_as": p.get("origin_as"),
                    "upstream_as": p.get("upstream_as") or None,
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

    # -- relationships -------------------------------------------------------
    @api_tool(mcp)
    def relationships(
        asn: int,
        start: Optional[str] = None,
        end: Optional[str] = None,
        max_per_group: Annotated[int, Field(ge=1, le=5000)] = 50,
    ) -> dict:
        """An ASN's transit hierarchy over a window: upstreams (its providers) and
        downstreams (its customers), plus observed neighbours whose relationship is
        unknown.

        Relationships are inferred provider->customer, Tier-1-anchored (~94% agreement
        with CAIDA). Peering is NOT inferred: `other_connections` are adjacencies we
        observed but cannot classify. Do not present them as confirmed peers. Results
        reflect the requested date window; relationships change over time.

        `data_through` is the newest day the relationship data covers. If the window ends
        later there is a `relationships_stale` warning, and if it lies entirely past the
        data the answer is for `served_window`. Say so when you cite it.

        This is the transit TOPOLOGY (who provides transit to whom). For observed USAGE,
        which of those upstreams carry the network's routes and how lopsided that
        is, use `path_diversity`. The two are complementary."""
        norm = normalize_asn(asn)
        start, end = default_window(start, end, days=30)
        resp = client.asn_relationships(norm, start_date=start, end_date=end)

        def shape(rows: list[dict]) -> list[dict]:
            return [
                {
                    "asn": r.get("asn"),
                    "name": r.get("name"),
                    "confidence": r.get("confidence"),
                    "vantage_count": r.get("vantage_count"),
                    "days_present": r.get("days_present"),
                }
                for r in (rows or [])
            ]

        rmeta = resp.get("meta") or {}
        rel_warnings = [
            warning(
                "peering_not_inferred",
                "Peering is not reliably inferable from routing data; "
                "other_connections are observed adjacencies of unknown type, not confirmed peers.",
            )
        ] + normalize_warnings(rmeta.get("warnings"))
        cut = {g: len(resp.get(g) or []) for g in ("upstreams", "downstreams", "other_connections")
               if len(resp.get(g) or []) > max_per_group}
        if cut:
            rel_warnings.append(warning(
                "lists_truncated",
                "Listed the first " + str(max_per_group) + " of " +
                ", ".join(f"{n} {g}" for g, n in cut.items()) +
                " (strongest first); `counts` cover all. Raise max_per_group for more.",
            ))
        return {
            "asn": norm,
            "window": {"from": start, "to": end},
            "served_window": {"from": rmeta.get("served_from"), "to": rmeta.get("served_to")},
            "data_through": rmeta.get("data_through"),
            "upstreams": shape(resp.get("upstreams"))[:max_per_group],
            "downstreams": shape(resp.get("downstreams"))[:max_per_group],
            "other_connections": shape(resp.get("other_connections"))[:max_per_group],
            "counts": {
                "upstreams": resp.get("upstream_count"),
                "downstreams": resp.get("downstream_count"),
                "other_connections": resp.get("other_connection_count"),
                "neighbors": resp.get("neighbor_count"),
            },
            "warnings": rel_warnings,
            "meta": meta("rollup", method=rmeta.get("method")),
        }

    # -- path_diversity ------------------------------------------------------
    @api_tool(mcp)
    def path_diversity(
        asn: int,
        prefix: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """How an origin's announcements FAN OUT through its upstreams toward our
        collectors: the observed propagation / path-diversity tree, weighted by how
        many vantage points take each branch.

        Built ONLY from real observed AS paths (no inference), so it answers with high
        confidence: which upstreams carry this network's routes, and how
        lopsided that is. Each level-1 branch's `share` is the fraction of vantage points
        (of the `total_vantage_points` that see the origin) that reach it via that
        upstream, counted as DISTINCT collector+peer feeds. Shares are per-upstream
        coverage, not a partition. A network reached through several upstreams will have
        several high shares, so they can sum past 1.0. One dominant upstream with the rest
        low = effectively single-threaded; several high shares = redundant transit.
        `is_tier1` marks where a branch reaches the Tier-1 core.

        Pass `prefix` (a CIDR the ASN originates) to scope the tree to ONE prefix, useful
        for a MOAS prefix or to check a specific route's redundancy; the % then reflects
        just that prefix's paths.

        NOT a traceroute: this is the control-plane spread of routes across upstreams as
        seen from route collectors, not the data-plane path a packet takes (peering and
        IXP handoffs are invisible to collectors). `diverse=false` means the origin is
        single-threaded or too thinly observed for a meaningful diversity view; read
        `reason`. Default window is 14 days (current routing); widen it for more history."""
        norm = normalize_asn(asn)
        start, end = default_window(start, end, days=14)
        resp = client.asn_propagation(norm, prefix=prefix, start_date=start, end_date=end)

        nodes = resp.get("nodes") or []
        edges = resp.get("edges") or []
        name_of = {n.get("asn"): n.get("name") for n in nodes}
        tier1_of = {n.get("asn"): bool(n.get("is_tier1")) for n in nodes}

        # Level-1 branches (direct upstreams of the origin) = the headline signal.
        direct = sorted(
            (e for e in edges if e.get("inner") == norm),
            key=lambda e: e.get("share") or 0,
            reverse=True,
        )
        upstreams = [
            {
                "asn": e.get("outer"),
                "name": name_of.get(e.get("outer")),
                "share": round(e.get("share") or 0, 3),
                "vantage_points": e.get("feeds"),
                "is_tier1": tier1_of.get(e.get("outer"), False),
            }
            for e in direct
        ]

        warnings = [
            warning(
                "observed_not_traceroute",
                "Control-plane route spread across upstreams as seen from collectors. "
                "not a data-plane/traceroute path. Peering and IXP handoffs are not visible.",
            )
        ]
        if not resp.get("diverse"):
            warnings.append(
                warning(
                    "not_diverse",
                    resp.get("reason")
                    or "Origin is single-threaded or too thinly observed for a diversity view.",
                )
            )
        if resp.get("truncated"):
            warnings.append(
                warning("truncated", "Tree truncated for legibility (large/complex origin).")
            )

        return {
            "asn": norm,
            "prefix": resp.get("prefix") or prefix,
            "window": {"from": start, "to": end},
            "diverse": resp.get("diverse", False),
            "reason": resp.get("reason"),
            "total_vantage_points": resp.get("total_feeds"),
            "upstreams": upstreams,
            "tree": {"nodes": nodes, "edges": edges, "max_level": resp.get("max_level")},
            "warnings": warnings,
            "meta": meta("raw_events", method=(resp.get("meta") or {}).get("method")),
        }

    # -- translate_communities -----------------------------------------------
    @api_tool(mcp)
    def translate_communities(communities: list[str]) -> dict:
        """Translate raw BGP community strings (e.g. "3356:2065", "1299:2731") into their
        meaning, from a dictionary harvested from operators' own IRR objects, NLNOG, and the
        IANA/RFC well-knowns.

        Each result carries: `known` (false means no published definition; do not guess a meaning),
        `category` (informational | action), `subtype` (geo | prepend | localpref | blackhole |
        no-export | relationship | …), `description`, optional geo, and the OWNER AS (the left
        side) with its resolved name, which is useful even when the community itself is
        unknown ("it's AS3356/Lumen's community"). `inferred=true` marks a meaning taken from a
        near-universal CONVENTION (e.g. any `:666`/`:9999` = blackhole) rather than something
        the owner published. Present those as conventional, not authoritative. `matched_by`
        shows the wildcard pattern that matched, when it wasn't an exact literal."""
        cleaned = [c.strip() for c in (communities or []) if c and c.strip()]
        if not cleaned:
            raise ValueError("provide at least one community, e.g. ['3356:2065']")
        resp = client.communities_translate(",".join(cleaned[:512]))

        out = []
        for r in (resp.get("results") or []):
            entry = {
                "community": r.get("community"),
                "known": r.get("known", False),
                "owner_asn": r.get("owner_asn"),
                "owner_name": r.get("owner_name"),
            }
            if r.get("known"):
                entry.update({
                    "category": r.get("category"),
                    "subtype": r.get("subtype"),
                    "description": r.get("description"),
                })
                geo = ", ".join(x for x in (r.get("geo_city"), r.get("geo_country")) if x)
                if geo:
                    entry["geo"] = geo
                if r.get("inferred"):
                    entry["inferred"] = True  # from a convention, not published
                if r.get("matched_by"):
                    entry["matched_by"] = r.get("matched_by")
                if r.get("source"):
                    entry["source"] = r.get("source")
            out.append(entry)

        return {
            "results": out,
            "warnings": [
                warning(
                    "unknown_communities_not_guessed",
                    "Communities with known=false have no published definition; the owner AS is "
                    "still named. Do not invent a meaning for them.",
                )
            ],
            "meta": meta("composed", **{k: v for k, v in (resp.get("meta") or {}).items() if k in ("dictionary_size", "attribution")}),
        }

    # -- compare_windows -----------------------------------------------------
    @api_tool(mcp)
    def compare_windows(
        target: str,
        window_a: dict,
        window_b: dict,
        dimension: Literal["volume", "origin", "collector"] = "volume",
    ) -> dict:
        """Baseline (window_a) vs event (window_b) for a target. Each window is
        {from, to}. `dimension=volume` compares totals; origin/collector compares the
        per-group breakdown so a new origin or a shifted collector mix is obvious.
        (upstream/paths comparison is not available via the rollup; use `paths`.)"""
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
                return {"total": (ts.get("meta") or {}).get("total", 0)}
            agg: dict[str, int] = {}
            for pt in (ts.get("points") or []):
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
    @api_tool(mcp)
    def locate(
        asn: Optional[int] = None,
        prefix: Optional[str] = None,
    ) -> dict:
        """Where is this network or prefix physically reached? Routing-only geolocation
        from three kinds of evidence, strongest first:

        1. Geo-ingress communities: upstream networks tag routes with where they received
           them (e.g. "LAX1 - Los Angeles"); weighted by observations over 30 days.
        2. The origin's own PeeringDB facilities.
        3. Cities common to 2+ upstreams' PeeringDB IX presence (weak on its own).

        `assessment.classification` is `concentrated` (one place carries most of the
        evidence), `regional`, `distributed` (many places: anycast or a multi-site
        network, so no single location), or `insufficient_evidence`. Never picks a
        place without evidence for it. Prefer it over GeoIP for leased or anycast space."""
        if asn is None and not prefix:
            raise ValueError("provide either asn or prefix")
        warnings: list[dict] = []
        origin = normalize_asn(asn) if asn is not None else None

        # 1. Geo-ingress (prefix-scoped when a prefix is given).
        try:
            geo = client.prefix_geo_ingress(prefix) if prefix else client.asn_geo_ingress(origin)
        except Exception:  # noqa: BLE001
            geo = {}
            warnings.append(warning("geo_ingress_unavailable", "Geo-ingress evidence could not be read."))
        points = [p for p in (geo.get("points") or []) if p.get("lat") or p.get("lon")]
        total_obs = sum(p.get("total_obs") or 0 for p in points) or 0
        ingress = []
        for p in sorted(points, key=lambda x: -(x.get("total_obs") or 0))[:10]:
            carriers = sorted({c.get("owner_as") for c in (p.get("communities") or []) if c.get("owner_as")})
            ingress.append({
                "city": p.get("city") or None, "country": p.get("country") or None,
                "observations": p.get("total_obs"),
                "share": round((p.get("total_obs") or 0) / total_obs, 3) if total_obs else None,
                "carriers": carriers,
            })

        # Origin ASN for the PeeringDB and upstream evidence.
        ov: dict = {}
        target_prefix = prefix
        if prefix:
            try:
                ov = client.prefix_overview(prefix)
                origins = ov.get("origins") or []
                if origin is None and origins:
                    origin = origins[0].get("origin_as")
            except Exception:  # noqa: BLE001
                ov = {}

        # 2. The origin's own PeeringDB facilities.
        own_facilities: list[dict] = []
        if origin:
            try:
                pdb = client.peeringdb_asn(origin)
                for f in pdb.get("facilities") or []:
                    if f.get("city"):
                        own_facilities.append({"facility": f.get("fac_name"), "city": f.get("city"),
                                               "country": f.get("country")})
            except Exception:  # noqa: BLE001
                pass

        # 3. Upstream IX intersection (only meaningful with 2+ upstreams).
        upstream_asns: list[int] = []
        common_cities: list[dict] = []
        if prefix and ov:
            u_start, u_end = default_window(None, None, days=7)
            ups, _, _ = session_upstreams(client, prefix, u_start, u_end, origin_as=origin,
                                          paths=ov.get("paths") or [])
            upstream_asns = [u["asn"] for u in ups if (u.get("share") or 0) >= 0.01][:6]
        if len(upstream_asns) >= 2:
            per_up: list[set] = []
            for up in upstream_asns:
                try:
                    pdb = client.peeringdb_asn(up)
                except Exception:  # noqa: BLE001
                    continue
                per_up.append({(ix.get("ix_city") or "", ix.get("ix_country") or "")
                               for ix in (pdb.get("ix_participation") or []) if ix.get("ix_city")})
            if len(per_up) >= 2:
                common_cities = [{"city": c, "country": k} for c, k in sorted(set.intersection(*per_up))][:10]

        # Assessment from the ranked evidence; never by sort order.
        own_cities = {(f["city"] or "").lower() for f in own_facilities}
        top = ingress[0] if ingress else None
        top_share = (top or {}).get("share") or 0
        assessment: dict[str, Any]
        if top and top_share >= 0.5:
            assessment = {"classification": "concentrated", "most_probable": _place(top),
                          "confidence": "high" if (top.get("city") or "").lower() in own_cities else "moderate",
                          "basis": f"{int(top_share * 100)}% of geo-ingress observations"}
        elif top and len(ingress) >= 5 and top_share < 0.3:
            assessment = {"classification": "distributed", "most_probable": None, "confidence": "moderate",
                          "basis": f"routes enter at {len(points)} places with no dominant one "
                                   "(anycast or a multi-site network); see ingress"}
        elif top:
            leaders = [i for i in ingress if (i.get("share") or 0) >= top_share * 0.5][:3]
            assessment = {"classification": "regional", "most_probable": _place(top),
                          "alternatives": [_place(i) for i in leaders[1:]],
                          "confidence": "moderate" if len(leaders) <= 2 else "low",
                          "basis": "leading geo-ingress locations"}
        elif own_facilities:
            assessment = {"classification": "regional", "most_probable": None, "confidence": "low",
                          "basis": "no geo-ingress evidence; the network lists PeeringDB facilities (see own_facilities)"}
        else:
            assessment = {"classification": "insufficient_evidence", "most_probable": None, "confidence": None,
                          "basis": "no geo-ingress communities or PeeringDB presence for this network"}
        if len(upstream_asns) == 1:
            warnings.append(warning("single_upstream", "Only one upstream is visible, so the upstream "
                                    "intersection carries no location information."))
        warnings.append(warning(
            "routing_evidence", "Ingress shows where upstreams receive the routes, which for a customer "
            "network is usually its interconnection point, not necessarily where its hosts are."))
        return {
            "target": prefix or f"AS{origin}",
            "origin_as": origin,
            "assessment": assessment,
            "ingress": ingress,
            "own_facilities": own_facilities[:20],
            "own_facility_count": len(own_facilities),
            "upstreams": upstream_asns,
            "upstream_common_cities": common_cities,
            "warnings": warnings,
            "meta": meta("composed"),
        }

    # -- subprefixes ---------------------------------------------------------
    @api_tool(mcp)
    def subprefixes(
        prefix: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
        max_listed: Annotated[int, Field(ge=1, le=1000)] = 200,
    ) -> dict:
        """Announced more-specifics inside a block, plus an estimate of unrouted
        space: addresses in the block that no announcement covers, the easiest kind to
        announce unnoticed. If the block itself or a less-specific is announced, every
        address is routed and the estimate is 0 (`covered_by` names the route)."""
        start, end = default_window(start, end, days=30)
        resp = client.prefix_subprefixes(prefix, start_date=start, end_date=end, limit=1000)
        subs = resp.get("subprefixes", []) or []
        total_subs = resp.get("total") or len(subs)
        covered_by: list[str] = []
        try:
            covered_by = _shape.covering_announced(prefix, client.prefix_hierarchy(prefix))
        except Exception:  # noqa: BLE001
            pass
        announced = [s.get("cidr") for s in subs if s.get("cidr")] + covered_by
        gaps = _shape.unrouted_gaps(prefix, announced)
        unrouted = sum(prefix_addresses(g) for g in gaps)
        warnings = []
        if any(s.get("is_moas") for s in subs):
            warnings.append(
                warning("moas_subprefix", "One or more more-specifics have multiple origins (MOAS).")
            )
        if total_subs > len(subs) and not covered_by:
            warnings.append(
                warning(
                    "subprefixes_truncated",
                    f"Only {len(subs)} of {total_subs} more-specifics were fetched, so the "
                    "unrouted estimate may overstate the gap.",
                )
            )
        if len(subs) > max_listed:
            warnings.append(warning(
                "subprefixes_listed_partially",
                f"Listed the {max_listed} most-announced of {len(subs)} fetched more-specifics; "
                "`count` and the unrouted estimate use all of them. Raise max_listed for more.",
            ))
        return {
            "prefix": prefix,
            "subprefixes": subs[:max_listed],
            "count": total_subs,
            "covered_by": covered_by,
            "unrouted_addresses_estimate": unrouted,
            "unrouted_examples": gaps[:10],
            "warnings": warnings,
            "meta": meta("rollup"),
        }

    # -- events_sample -------------------------------------------------------
    @api_tool(mcp)
    def events_sample(
        prefix: str,
        start: Annotated[str, Field(description="YYYY-MM-DD or RFC3339 (2026-06-27T06:00:00Z); window <= 24h")],
        end: str,
        limit: int = 200,
        origin_as: Optional[int] = None,
        peer_asn: Optional[int] = None,
        collector_id: Optional[str] = None,
        event_type: Optional[Literal["announcement", "withdrawal"]] = None,
    ) -> dict:
        """Bounded raw events for a NARROW window, newest first. Use it last. Capped at
        500 events; rejects windows over 24h. Use only after timeline/reachability/
        origin_history/origin_reach have localised what you need to see at the message
        level.

        `start`/`end` may be dates (a date `end` includes the whole day) or RFC3339
        timestamps for a minutes-wide window. The origin/peer/collector/event_type
        filters are applied by the server, so a filtered request returns matching
        events even when the prefix has tens of thousands of others."""
        t_start = parse_when(start)
        t_end = parse_when(end, end_of_day=True)
        if t_end <= t_start:
            raise ValueError("end must be after start")
        if (t_end - t_start).total_seconds() > 86400 + 1:
            raise ValueError(
                "window too wide for events_sample (max 24h). Narrow it, or use "
                "timeline for counts over a longer period."
            )
        limit = max(1, min(limit, 500))
        fmt = "%Y-%m-%d %H:%M:%S"
        params: dict[str, Any] = {
            "start_date": t_start.strftime("%Y-%m-%d"),
            "end_date": t_end.strftime("%Y-%m-%d"),
            "timestamp_start": t_start.strftime(fmt),
            "timestamp_end": t_end.strftime(fmt),
            "limit": limit,
        }
        if event_type:
            params["event_type"] = event_type
        if origin_as is not None:
            params["origin_as"] = normalize_asn(origin_as)
        if peer_asn is not None:
            params["peer_asn"] = normalize_asn(peer_asn)
        if collector_id:
            params["collector_id"] = collector_id
        resp = client.prefix_events(prefix, **params)
        events = resp.get("events", []) or []
        pag = resp.get("pagination", {}) or {}
        total = pag.get("total", len(events))
        truncated = bool(pag.get("has_more")) or (isinstance(total, int) and total > len(events))
        warnings = []
        if truncated:
            warnings.append(
                warning(
                    "truncated",
                    f"Showing {len(events)} of ~{total} matching events. Narrow the window or add "
                    "filters (origin_as, peer_asn, collector_id) rather than reading more.",
                )
            )
        return {
            "prefix": prefix,
            "window": {"from": rfc3339(t_start), "to": rfc3339(t_end)},
            "events": events,
            "returned": len(events),
            "matching": total,
            "truncated": truncated,
            "warnings": warnings,
            "meta": meta("raw_events"),
        }

    # -- platform_baseline ---------------------------------------------------
    @api_tool(mcp)
    def platform_baseline(
        window: str = "14d",
        by: Literal["type", "severity"] = "type",
        day: Optional[str] = None,
    ) -> dict:
        """Is a day unusual, platform-wide? Exact daily counts of anomalous incidents by
        detection type (or severity) over the window, each series' median, and how `day`
        (default: the latest full day) compares with it. Call this BEFORE describing
        anything as anomalous. An apparent spike is often just the platform's normal
        volume."""
        days = max(2, min(90, int(str(window).rstrip("dD") or 14)))
        resp = client.detections_trends(window=f"{days}d", by=by)
        series: dict[str, dict[str, int]] = {}
        for p in resp.get("points", []) or []:
            series.setdefault(p.get("series"), {})[p.get("date")] = p.get("count", 0)
        dates = sorted({d for s_ in series.values() for d in s_})
        if not dates:
            return {"window_days": days, "by": by, "series": {}, "warnings": [warning("no_data", "No trend data for the window.")], "meta": meta("registry")}
        target = day or (dates[-2] if len(dates) > 1 else dates[-1])  # the last date is usually partial
        rows = {}
        for name, byday in series.items():
            vals = [byday.get(d, 0) for d in dates if d != target]
            vals_sorted = sorted(vals)
            med = vals_sorted[len(vals_sorted) // 2] if vals_sorted else 0
            v = byday.get(target, 0)
            rows[name] = {
                "day_count": v,
                "median": med,
                "ratio_to_median": round(v / med, 2) if med else None,
                "window_total": sum(byday.values()),
            }
        rows = dict(sorted(rows.items(), key=lambda kv: -kv[1]["window_total"]))
        warnings = []
        if target == dates[-1]:
            warnings.append(warning("partial_day", f"{target} is today (UTC) and still filling in; compare a complete day."))
        return {
            "window": {"from": dates[0], "to": dates[-1]},
            "by": by,
            "day": target,
            "series": rows,
            "daily": {name: [byday.get(d, 0) for d in dates] for name, byday in series.items()},
            "dates": dates,
            "warnings": warnings,
            "meta": meta("registry", exact=True),
        }

    # -- notable_events ------------------------------------------------------
    @api_tool(mcp)
    def notable_events(
        hours: Annotated[int, Field(ge=1, le=168)] = 24,
        limit: Annotated[int, Field(ge=1, le=100)] = 25,
        asn: Optional[int] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> dict:
        """What potentially notable BGP events are happening across the internet? Returns
        a scored feed of one network announcing address space that another network
        normally originates, which is what a hijack or route leak looks like. Events are
        ranked so the ones worth a human's attention float up: a more prominent victim
        network, more corroborating detectors, and more affected prefixes raise the
        score, while likely leaks (the two networks are related) and shared/leased
        address space are pushed down.

        Live feed by default (the last `hours`). For a past incident pass `start`/`end`
        (dates or RFC3339, within the last 90 days, at most 31 days wide) and/or `asn`
        (as announcer or usual origin). Scoped to an ASN, incidents with no known usual
        origin are kept and appear with `usual_origin_as: 0`.

        These are LEADS, not verdicts. Relationship inference is imperfect, so an
        event can be flagged when the two parties are the same operator.
        `announcing_as_allocated: false` means no RIR allocates the announcer: it is a
        forged or corrupted origin, not a network (null when unknown).
        Investigate before describing anything as a confirmed hijack: `identify`
        the two ASNs, run `origin_episode` for the announcer, and pull the affected
        prefix's history."""
        params: dict[str, Any] = {"window_hours": hours, "limit": limit}
        if asn is not None:
            params["asn"] = normalize_asn(asn)
        if start:
            params["start"] = rfc3339(parse_when(start))
        if end:
            params["end"] = rfc3339(parse_when(end, end_of_day=True))
        data = client.notable_events(**params)
        events = data.get("events") or []
        shaped = []
        for e in events:
            sp = e.get("sample_prefix")
            shaped.append(
                {
                    "announcing_as": e.get("actor_as"),
                    "usual_origin_as": e.get("victim_as"),
                    "prefix_count": e.get("prefix_count"),
                    "sample_prefix": (
                        f"{sp}/{e.get('sample_prefix_len')}" if sp else None
                    ),
                    "signals": e.get("detection_types") or [],
                    "victim_traffic": e.get("victim_traffic") or None,
                    "possible_leak": bool(e.get("likely_leak")),
                    "announcing_as_allocated": e.get("actor_allocated"),
                    "severity": e.get("severity"),
                    "score": round(e.get("score") or 0.0, 1),
                    "first_seen": e.get("first_seen"),
                    "last_seen": e.get("last_seen"),
                    "family": "ipv4" if e.get("is_v4") else "ipv6",
                }
            )
        warnings = [
            warning(
                "leads_not_verdicts",
                "Scored leads, not confirmed hijacks. `possible_leak` marks pairs "
                "our inferred relationships tie together; low-scoring events near "
                "the tail are often benign or misconfigurations.",
            )
        ]
        unallocated = sorted(
            {e["announcing_as"] for e in shaped if e["announcing_as_allocated"] is False}
        )
        if unallocated:
            warnings.append(
                warning(
                    "unallocated_announcer",
                    f"{len(unallocated)} announcing ASN(s) are not allocated by any RIR "
                    f"({', '.join(f'AS{a}' for a in unallocated[:10])}). These are not "
                    "networks: the origin was forged or corrupted, it is a routing "
                    "experiment, or a typo. Name the network that sent the route (the "
                    "ASN before it in the path, see `paths`) rather than the fake origin. "
                    "These events are ranked lower.",
                )
            )
        return {
            "window_hours": data.get("window_hours", hours),
            "count": len(shaped),
            "events": shaped,
            "warnings": warnings,
            "meta": meta("composed"),
        }

    # -- origin_episode ------------------------------------------------------
    @api_tool(mcp)
    def origin_episode(
        asn: int,
        start: Annotated[str, Field(description="First episode day, YYYY-MM-DD")],
        end: Optional[str] = None,
        baseline_days: Annotated[int, Field(ge=7, le=60)] = 28,
        after_days: Annotated[int, Field(ge=0, le=14)] = 3,
        list_prefixes: bool = True,
        min_peers: Annotated[int, Field(ge=0)] = 0,
        max_prefixes: Annotated[int, Field(ge=1, le=5000)] = 100,
        min_baseline_days: Annotated[int, Field(ge=1, le=28)] = 3,
    ) -> dict:
        """What did this ASN originate during a short window (up to 7 days) that it does
        not originate normally, and whose space was it? The first call for a suspected
        hijack or route leak by one network.

        The episode is compared with the `baseline_days` before it and the `after_days`
        after it. New prefixes are split into the ASN's own space (inside a block it
        announced before) and other networks' space.

        Each other-space prefix comes with its first and last announcement and the peers
        and collectors that saw it. If another AS originated the same prefix it is listed
        as a MOAS; otherwise you get the holder of the most specific covering block, as
        long as that block was held on 2 or more baseline days. Default routes and blocks
        shorter than /8 or /16 never count as holders.

        The summary counts conflicts the way public hijack monitors do: prefix and origin
        pairs by other ASes equal to or inside the leaked prefixes during the episode. Each
        other-space prefix also carries its own `conflicts` and `conflict_asns`, so you can
        see which prefixes the total comes from (nested prefixes each count what is under
        them, so these do not add up to the total).

        `summary.peer_buckets` counts the other-space prefixes by how many peers saw them. A
        leak that spread widely for some prefixes and barely for others shows as two groups.

        The listing puts other-space prefixes first, most widely seen first, and stops at
        `max_prefixes`. `min_peers` lists only prefixes seen by at least that many peers.
        Summary figures always cover every prefix.
        `carriers` are the ASes that passed the routes on, marked when one is an inferred
        provider of the ASN.

        Compare `summary.max_peers` with `summary.reference_peers` (the median for the
        ASN's own steady prefixes) rather than reading peer counts on their own. A prefix
        counts as normal only if the ASN originated it on at least `min_baseline_days`
        (default 3) comparison days, and only such blocks make "own space"; one announced
        on fewer days is still listed, with `baseline_days` saying how many, so a repeat
        announcement of someone else's space is not hidden by its earlier occurrence.
        `start`/`end` are dates; an RFC3339 time is accepted and its date used. Follow up
        with `origin_reach` on a few prefixes for the minute-by-minute propagation
        curve."""
        start, end = start[:10], (end[:10] if end else end)
        params: dict[str, Any] = {"from": start, "baseline_days": baseline_days, "after_days": after_days,
                                  "min_baseline_days": min_baseline_days}
        if end:
            params["to"] = end
        if min_peers:
            params["min_peers"] = min_peers
        resp = client.asn_episode(normalize_asn(asn), **params)
        warnings = normalize_warnings(resp.get("warnings"))
        summ = resp.get("summary") or {}
        if summ.get("new_other_space"):
            warnings.append(
                warning(
                    "registry_labels",
                    "Holder ASNs come from routing data (who announced the covering block), not "
                    "from registry allocation. Run identify or bulk_registry before naming owners.",
                )
            )
        out = {k: resp.get(k) for k in ("asn", "from", "to", "baseline_from", "baseline_to", "after_from", "after_to")}
        out.update({
            "summary": summ,
            "carriers": resp.get("carriers") or [],
            "holders": resp.get("holders") or [],
            "warnings": warnings,
            "meta": meta("rollup"),
        })
        if list_prefixes:
            listed = resp.get("prefixes") or []
            out["prefixes_available"] = len(listed)
            if len(listed) > max_prefixes:
                warnings.append(
                    warning(
                        "prefixes_truncated",
                        f"Listing {max_prefixes} of {len(listed)} prefixes, most widely seen first. "
                        "Raise max_prefixes or set min_peers to see others; the summary covers all.",
                    )
                )
                listed = listed[:max_prefixes]
            out["prefixes"] = listed
        return out

    # -- origin_reach --------------------------------------------------------
    @api_tool(mcp)
    def origin_reach(
        prefix: str,
        origin_as: int,
        start: Annotated[str, Field(description="RFC3339 (2026-06-27T05:50:00Z) or YYYY-MM-DD")],
        end: str,
        interval_seconds: Annotated[int, Field(ge=10, le=3600)] = 60,
    ) -> dict:
        """How far did one origin's route for a prefix propagate, and when? A propagation
        curve: at each step, how many collector sessions carried a route for the prefix
        from `origin_as`, and what share of full-table feeds that is (the same
        denominator as global_reach). The summary gives the peak, when it happened, and
        the first and last moment any session carried it. Separate waves show up as
        separate humps. Window at most 48 hours; this reads raw events.

        Built for a NEW route (a hijack, a leak). Only BGP updates are stored, so a session
        that has carried a long-established route since before the lookback and sent no
        update is invisible, and the curve undercounts: a `route_predates_window` warning
        says so. For an established route's reach use `global_reach`."""
        resp = client.prefix_origin_reach(
            prefix,
            origin_as=normalize_asn(origin_as),
            **{"from": rfc3339(parse_when(start)), "to": rfc3339(parse_when(end, end_of_day=True))},
            interval=interval_seconds,
        )
        series = resp.get("series") or []
        phases = []
        cur = None
        for p in series:
            if p.get("sessions", 0) > 0:
                if cur is None:
                    cur = {"from": p["t"], "to": p["t"], "peak_pct": p.get("pct", 0), "peak_sessions": p.get("sessions", 0)}
                else:
                    cur["to"] = p["t"]
                    if p.get("sessions", 0) > cur["peak_sessions"]:
                        cur["peak_sessions"], cur["peak_pct"] = p["sessions"], p.get("pct", 0)
            elif cur is not None:
                phases.append(cur)
                cur = None
        if cur is not None:
            phases.append(cur)
        warnings = normalize_warnings(resp.get("warnings"))
        if len(phases) > 1:
            warnings.append(
                warning(
                    "multiple_phases",
                    f"The route was carried in {len(phases)} separate periods; report them as phases, "
                    "not one continuous event. Phase edges are at the sampling interval's resolution.",
                )
            )
        return {
            "prefix": resp.get("prefix", prefix),
            "origin_as": resp.get("origin_as"),
            "window": {"from": resp.get("from"), "to": resp.get("to")},
            "interval_seconds": resp.get("interval_seconds"),
            "full_table_feeds": resp.get("full_table_feeds"),
            "summary": resp.get("summary"),
            "phases": phases,
            "series": series,
            "warnings": warnings,
            "meta": meta("raw_events"),
        }

    # -- bulk_registry -------------------------------------------------------
    @api_tool(mcp)
    def bulk_registry(
        prefixes: Optional[list[str]] = None,
        origin_asn: Optional[int] = None,
        asns: Optional[list[int]] = None,
        as_of: Annotated[Optional[str], Field(description="YYYY-MM-DD: judge RPKI/IRR against that day's data")] = None,
        summary_only: bool = False,
    ) -> dict:
        """RPKI, IRR and RDAP for many prefixes and ASNs in one go (batched 200 at a time).
        For each prefix: covering ROAs and, when `origin_asn` is given, the RPKI verdict
        for that origin (valid | invalid | not_found), IRR route-object origins and
        whether they include `origin_asn`, and the RDAP holder, country and RIR. For each
        ASN: RDAP name, country and RIR. Use it to state registry facts for a whole
        episode instead of sampling a handful.

        For a past incident always pass `as_of` (the incident day). Without it RPKI/IRR
        reflect the last 30 days. Holders often publish ROAs soon after an incident, and
        today's ROAs would then call the incident's routes RPKI-invalid when at the time
        they were not found. RDAP is always the current record.

        `summary` gives counts for the whole set: ROA coverage, IRR objects, the RPKI
        verdicts when `origin_asn` is given, and prefixes by RIR and country. With
        `summary_only=true` the per-prefix list is replaced by `notable_prefixes`: only the
        ones with a ROA, an IRR object naming `origin_asn`, or an error. Use it for a few
        hundred prefixes."""
        prefixes = [p.strip() for p in (prefixes or []) if p and p.strip()]
        asn_list = [normalize_asn(a) for a in (asns or [])]
        if not prefixes and not asn_list:
            raise ValueError("provide prefixes and/or asns")
        if len(prefixes) > 2000 or len(asn_list) > 2000:
            raise ValueError("at most 2000 prefixes and 2000 asns per call")
        origin = normalize_asn(origin_asn) if origin_asn is not None else None

        pfx_out: list[dict] = []
        asn_out: list[dict] = []
        counts = {"valid": 0, "invalid": 0, "not_found": 0}
        for i in range(0, max(len(prefixes), len(asn_list)), 200):
            chunk_p = prefixes[i:i + 200]
            chunk_a = asn_list[i:i + 200]
            if not chunk_p and not chunk_a:
                break
            body: dict[str, Any] = {"include": ["rpki", "irr", "rdap"]}
            if as_of:
                body["as_of"] = as_of
            if chunk_p:
                body["prefixes"] = chunk_p
            if chunk_a:
                body["asns"] = chunk_a
            resp = client.registry_bulk(body)
            for p in chunk_p:
                e = (resp.get("prefixes") or {}).get(p) or {}
                roas = ((e.get("rpki") or {}).get("records")) or []
                plen = int(p.split("/")[1]) if "/" in p else None
                entry: dict[str, Any] = {
                    "prefix": p,
                    "roas": [
                        {"prefix": r.get("cidr") or r.get("prefix"), "origin_asn": r.get("origin_asn"), "max_length": r.get("max_length")}
                        for r in roas
                    ],
                }
                err = e.get("error") or ""
                rpki_down = "rpki" in err.partition("unavailable:")[2]
                irr_down = "irr" in err.partition("unavailable:")[2]
                if origin is not None:
                    if rpki_down:
                        v = "unavailable"
                    elif not roas:
                        v = "not_found"
                    elif any(r.get("origin_asn") == origin and (r.get("max_length") is None or plen is None or r["max_length"] >= plen) for r in roas):
                        v = "valid"
                    else:
                        v = "invalid"
                    entry["rpki"] = v
                    counts[v] = counts.get(v, 0) + 1
                irr_recs = ((e.get("irr") or {}).get("records")) or []
                live = (lambda r: True) if as_of else _shape.irr_is_current
                irr_origins = sorted({r.get("origin_as") for r in irr_recs if r.get("origin_as") and live(r)})
                gone = sorted({r.get("origin_as") for r in irr_recs if r.get("origin_as") and not live(r)} - set(irr_origins))
                entry["irr_origins"] = None if irr_down else irr_origins  # None = could not be read
                if gone:
                    entry["irr_deleted_origins"] = gone  # objects deleted within the last 30 days
                if origin is not None:
                    entry["irr_matches_origin"] = None if irr_down else (origin in irr_origins if irr_origins else None)
                entry["rdap"] = _registry_name(e)
                if e.get("error"):
                    entry["error"] = e["error"]
                pfx_out.append(entry)
            for a in chunk_a:
                e = (resp.get("asns") or {}).get(str(a)) or {}
                asn_out.append({"asn": a, **_registry_name(e)})
        out: dict[str, Any] = {
            "prefixes": pfx_out,
            "asns": asn_out,
            "warnings": [
                warning(
                    "registry_labels",
                    "Names and countries are registry records, often set at allocation; use them as "
                    "identifiers, not as statements about where or how the space is used today.",
                )
            ],
            "meta": meta("registry"),
        }
        out["registry_as_of"] = as_of or "last 30 days"
        if not as_of:
            out["warnings"].append(
                warning(
                    "current_registry_state",
                    "RPKI/IRR are the last 30 days' state. For an incident in the past, pass as_of.",
                )
            )
        if origin is not None:
            out["rpki_summary"] = {"origin_asn": origin, **counts, "checked": len(pfx_out)}
        out["summary"] = _shape.registry_summary(pfx_out)
        if summary_only:
            notable = [
                e for e in pfx_out
                if e.get("roas") or e.get("irr_matches_origin") or e.get("error")
            ]
            out["notable_prefixes"] = notable[:NOTABLE_PREFIXES_MAX]
            if len(notable) > NOTABLE_PREFIXES_MAX:
                out["warnings"].append(
                    warning(
                        "notable_truncated",
                        f"Listing {NOTABLE_PREFIXES_MAX} of {len(notable)} notable prefixes; "
                        "the summary covers all.",
                    )
                )
            del out["prefixes"]
        return out


def _registry_name(e: dict) -> dict:
    """Name, country and RIR for a bulk entry: the cached RDAP record, or, when none
    is cached, the stored name the API falls back to (IRR descr, PeeringDB, delegation
    data). `name_source` says which, so a label is never mistaken for a registration."""
    rd = e.get("rdap") or {}
    if rd:
        out = {
            "name": rd.get("Name") or rd.get("name"),
            "country": rd.get("Country") or rd.get("country") or None,
            "rir": _shape.rir_from_rdap(rd),
            "name_source": "rdap",
        }
        if e.get("rdap_approximate"):
            out["approximate"] = True
        return out
    fb = e.get("name_fallback") or {}
    return {
        "name": fb.get("name"),
        "country": fb.get("country_code") or None,
        "rir": fb.get("rir") or None,
        "name_source": fb.get("source") if fb.get("name") else None,
    }


def _place(p: dict) -> str | None:
    """"City, Country" for an ingress row, or just whichever is known."""
    parts = [x for x in (p.get("city"), p.get("country")) if x]
    return ", ".join(parts) or None
