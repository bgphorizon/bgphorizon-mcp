"""Operator tools (3): watching a network you own.

These answer "is my stuff correct and healthy?" and every finding carries
`remediation` in operator terms, so a model can hand an engineer an action list
rather than a data dump.
"""

from __future__ import annotations

import datetime as _dt
import contextvars
from concurrent.futures import ThreadPoolExecutor
from typing import Annotated, Any, Callable, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import BGPHorizonClient
from ..common import (
    api_tool,
    default_window,
    meta,
    normalize_asn,
    prefix_addresses,
    quiet_api_warnings,
    today,
    warning,
    window_from_shorthand,
)
from . import _paging, _shape
from ._paging import session_upstreams

# Aggregates checked for unrouted space (one cached RDAP read + one subprefixes call
# each). Transit and visibility cover every prefix and are not sampled.
_UNROUTED_SAMPLE = 32
# Of those, how many may be looked up live at their registry when not cached; the
# rest use cached registrations only. Live lookups count against the account's
# daily allowance, which one health check should not use up.
_UNROUTED_LIVE = 10
# MOAS incidents read per health check; beyond this the finding points at detections().
_MOAS_MAX_INCIDENTS = 5000
# Affected prefixes enriched with covering ROAs, IRR and RDAP holder (bulk, 200 per call).
_ENRICH_LIMIT = 1000
_ENRICH_CHUNK = 100
# Concurrent API reads per health_check phase.
_MAX_PARALLEL = 8
# Annotated rows listed per finding; counts and breakdowns always cover every prefix.
_LIST_LIMIT = 250
# Examples of no-action rows shown per finding in summary mode.
_EXAMPLES = 10


def register_operator_tools(mcp: FastMCP, client: BGPHorizonClient) -> None:

    # -- health_check --------------------------------------------------------
    @api_tool(mcp)
    def health_check(
        asn: int,
        window: str = "30d",
        checks: Optional[list[str]] = None,
        detail: Literal["summary", "full"] = "summary",
    ) -> dict:
        """Full hygiene and exposure audit for an ASN you control. The most
        valuable operator call. Checks RPKI (including RPKI-invalid routes) and IRR
        coverage, MOAS, ROA max-length exposure, transit, visibility and unrouted space,
        each with remediation phrased per group.

        Every affected prefix is counted and annotated (persistence, whose space it is),
        never dropped. `detail="summary"` (default) lists the rows that need action and
        summarizes the rest in `breakdown` and `other_examples`; `detail="full"` lists
        up to 250 rows per finding. Only the unrouted check samples (32 aggregates)."""
        asn = normalize_asn(asn)
        checks = checks or ["rpki", "irr", "moas", "maxlength", "transit", "visibility", "unrouted"]
        start, end = window_from_shorthand(window, default_days=30)

        # Phase 1: every independent read at once. health_check used to make these one
        # after another (with a sequential RDAP/subprefix loop), ~9 s of waiting for AS13335.
        _FULL = 100000
        want_moas = "moas" in checks
        want_transit = "transit" in checks or "visibility" in checks
        days_back = (today() - _dt.date.fromisoformat(start)).days + 1
        calls: dict[str, Callable[[], Any]] = {
            "presence": lambda: client.presence(asn=asn, **{"from": start, "to": end}),
            "rdap_asn": lambda: client.rdap_asn(asn),
        }
        if "rpki" in checks or "maxlength" in checks:
            calls["rpki"] = lambda: client.rpki_asn(asn, start_date=start, end_date=end, limit=_FULL)
        if "irr" in checks:
            calls["irr"] = lambda: client.irr_asn(asn, start_date=start, end_date=end, limit=_FULL)
        if want_transit:
            calls["transit"] = lambda: client.asn_prefix_transit(asn, **{"from": start, "to": end, "neighbors": 3})
        if "transit" in checks:
            calls["relationships"] = lambda: client.asn_relationships(asn)
        if want_moas:
            calls["moas"] = lambda: _paging.fetch_detections(
                client, asn=asn, prefix=None,
                params={"from": start, "to": end, "type": "moas_conflict"},
                max_incidents=_MOAS_MAX_INCIDENTS,
            )
            calls["trends"] = lambda: client.detections_trends(window=f"{days_back}d")
        got = _concurrently(calls)
        if isinstance(got["presence"], Exception):
            raise got["presence"]
        pres = got["presence"]
        prefixes = pres.get("prefixes", []) or []
        announced = [p.get("cidr") for p in prefixes if p.get("cidr")]
        announced_set = set(announced)
        total = len(announced_set)

        # The full record sets (coverage must count every distinct prefix, not a page);
        # the endpoints return per-observation rows, de-duplicated by CIDR below.
        rpki = _ok(got.get("rpki"), {})
        irr = _ok(got.get("irr"), {})

        findings: list[dict] = []
        score: dict[str, Any] = {}
        extra_warnings: list[dict] = []
        audit_context: dict[str, dict] = {}  # per-prefix RPKI/IRR state, for visibility reasons
        pres_by_cidr = {p.get("cidr"): p for p in prefixes if p.get("cidr")}
        if not total:
            # Without this an ASN that announced nothing reads as a clean audit.
            extra_warnings.append(warning(
                "no_prefixes",
                f"AS{asn} originated no prefixes between {start} and {end}, so the per-prefix "
                "checks had nothing to examine. This is not a clean result.",
            ))

        # The endpoint returns one row per observation; collapse to distinct ROAs
        # so counts aren't inflated by the observation history.
        roa_records = rpki.get("records", []) or []
        distinct_roas = list(
            {
                (r.get("cidr"), r.get("max_length"), r.get("origin_asn")): r
                for r in roa_records
                if r.get("cidr")
            }.values()
        )
        irr_routes = (irr.get("routes_v4", []) or []) + (irr.get("routes_v6", []) or [])

        # Work out every affected prefix first, then enrich them in one bulk pass
        # (covering ROAs of any origin, exact IRR objects, RDAP holder).
        missing: list[str] = []
        if "rpki" in checks:
            # Proper origin validation: a covering ROA (max_length >= announced
            # length) counts, not just an exact-CIDR ROA.
            _, missing = _shape.rpki_coverage(announced, distinct_roas, asn)
            missing = sorted(missing)
        loose = []
        if "maxlength" in checks:
            for r in distinct_roas:
                plen = r.get("prefix_len")
                ml = r.get("max_length")
                cidr = r.get("cidr") or ""
                host = 32 if ":" not in cidr else 128
                # Only flag max_length opened all the way to the host length on a
                # shorter ROA; that authorizes any more-specific and is a genuine
                # hijack surface. Ordinary max_length that covers real more-specifics
                # is normal and not flagged.
                if plen is not None and ml == host and plen < host:
                    loose.append({"cidr": cidr, "prefix_len": plen, "max_length": ml})
        missing_irr: list[str] = []
        if "irr" in checks:
            irr_cidrs = {r.get("cidr") for r in irr_routes}
            missing_irr = sorted(announced_set - irr_cidrs)

        # RDAP (the slow part on a cold cache) only where the holder decides the
        # remediation: ROAs. IRR rows get covering objects and object origins.
        rdap_targets = list(dict.fromkeys(missing + [x["cidr"] for x in loose]))[:_ENRICH_LIMIT]
        irr_targets = [c for c in missing_irr if c not in set(rdap_targets)][:_ENRICH_LIMIT]
        # Phase 2: bulk enrichment chunks and the unrouted RDAP reads, all at once.
        unrouted_aggs = _unrouted_aggregates(announced, pres_by_cidr) if "unrouted" in checks else []
        phase2: dict[str, Callable[[], Any]] = {}
        for i in range(0, len(rdap_targets), _ENRICH_CHUNK):
            chunk = rdap_targets[i:i + _ENRICH_CHUNK]
            phase2[f"bulk:r{i}"] = lambda chunk=chunk: _bulk(chunk, ["rpki", "irr", "rdap"])
        for i in range(0, len(irr_targets), _ENRICH_CHUNK):
            chunk = irr_targets[i:i + _ENRICH_CHUNK]
            phase2[f"bulk:i{i}"] = lambda chunk=chunk: _bulk(chunk, ["irr"])
        for i, cidr in enumerate(unrouted_aggs[:_UNROUTED_SAMPLE]):
            phase2[f"rdap:{cidr}"] = lambda cidr=cidr, live=i < _UNROUTED_LIVE: client.rdap_prefix(cidr, live=live)
        got2 = _concurrently(phase2)
        enriched: dict[str, dict] = {}
        for k, v in got2.items():
            if k.startswith("bulk:") and not isinstance(v, Exception):
                enriched.update(v)
        targets = rdap_targets + irr_targets
        if len(enriched) < len(targets):
            extra_warnings.append(warning(
                "annotation_partial",
                f"{len(targets) - len(enriched)} of {len(targets)} affected prefixes could not be "
                "checked for covering ROAs, IRR objects or holder. Those rows show state "
                "'not_checked' or no holder; check them with bulk_registry before relying on them.",
            ))
        asn_ident = _shape.asn_holder_identity(_ok(got.get("rdap_asn"), None))

        def base(cidr: str) -> dict:
            p = pres_by_cidr.get(cidr) or {}
            row: dict[str, Any] = {"prefix": cidr}
            if p:
                row["persistence"] = p.get("classification")
                row["days_present"] = p.get("days_present")
            e = enriched.get(cidr)
            if e is not None:
                row.update(_shape.prefix_holder(e.get("rdap"), asn_ident, e.get("name_fallback"),
                                                bool(e.get("rdap_approximate"))))
            return row

        # RPKI --------------------------------------------------------
        if "rpki" in checks:
            covered = total - len(missing)
            score["rpki_coverage"] = round(covered / total, 3) if total else None
            rows = []
            for cidr in missing:
                row = base(cidr)
                e = enriched.get(cidr)
                # A section the API could not read is "not_checked", never NotFound.
                if e is not None and "rpki" not in (e.get("error") or "").partition("unavailable:")[2]:
                    recs = ((e.get("rpki") or {}).get("records")) or []
                    row.update(_shape.rpki_state(recs, asn, _plen(cidr)))
                else:
                    row["state"] = "not_checked"
                rows.append(row)
            for r in rows:
                audit_context.setdefault(r["prefix"], {})["rpki"] = r.get("state")
            invalid = [r for r in rows if r.get("state") == "invalid"]
            not_found = [r for r in rows if r.get("state") != "invalid"]
            if invalid:
                findings.append(_rpki_invalid_finding(asn, invalid))
            if not_found:
                findings.append(_rpki_notfound_finding(asn, total, not_found, all_uncovered=len(missing) == total,
                                                       detail=detail))

        # ROA max-length exposure ---------------------------------------
        if loose:
            rows = []
            announced_nets = _shape.parse_nets(announced)
            for x in loose:
                row = base(x["cidr"])
                row.pop("persistence", None)
                row.pop("days_present", None)
                row["max_length"] = x["max_length"]
                inside = _shape.nets_inside(x["cidr"], announced_nets)
                row["announced_inside"] = len(inside)
                if inside:
                    row["suggested_max_length"] = max(n.prefixlen for n in inside)
                rows.append(row)
            findings.append(_maxlength_finding(asn, rows))

        # IRR coverage ---------------------------------------------------
        if "irr" in checks:
            score["irr_coverage"] = round((total - len(missing_irr)) / total, 3) if total else None
            if missing_irr:
                own_objects = _shape.CidrIndex([r.get("cidr") for r in irr_routes if r.get("cidr")])
                rows = []
                for cidr in missing_irr:
                    row = base(cidr)
                    cover = own_objects.containing(cidr, strict=True)
                    e = enriched.get(cidr)
                    others = sorted({
                        r.get("origin_as") for r in (((e or {}).get("irr") or {}).get("records") or [])
                        if r.get("origin_as") and _shape.irr_is_current(r)
                    } - {asn})
                    irr_down = "irr" in ((e or {}).get("error") or "").partition("unavailable:")[2]
                    if cover:
                        row["state"], row["covering_object"] = "covered_by_less_specific", cover
                    elif irr_down:
                        row["state"] = "not_checked"
                    elif others:
                        row["state"], row["object_origins"] = "other_origin_only", others
                    else:
                        row["state"] = "missing"
                    rows.append(row)
                for r in rows:
                    audit_context.setdefault(r["prefix"], {})["irr"] = r.get("state")
                findings.append(_irr_finding(asn, total, rows, detail))

        # MOAS -----------------------------------------------------------
        # From the detector's moas_conflict incidents (concurrent origination within its
        # 4h window), not the presence rollup: presence rows for an ASN only carry that
        # ASN's own origin, so they can never show a second one.
        moas_incidents: Optional[list[dict]] = None
        moas_res = got.get("moas")
        if isinstance(moas_res, _paging.DetectionsUnavailable):
            pass  # not available to this caller: omit the check, never "none"
        elif isinstance(moas_res, Exception):
            extra_warnings.append(warning("moas_unavailable", "Detections could not be read; the MOAS check was skipped."))
        elif moas_res is not None:
            moas_incidents, moas_total, moas_next = moas_res
        if moas_incidents is not None:
            for inc in moas_incidents:
                _shape.parse_details(inc)
            moas = _shape.moas_by_prefix(moas_incidents, asn)
            _label_origins(moas, asn_ident)
            anomalous = [m for m in moas if m["classification"] == "anomalous"]
            related = [m for m in moas if m["classification"] == "related"]
            score["prefixes_with_moas"] = len(moas)
            finding: dict[str, Any] = {
                "check": "moas",
                "severity": "high" if anomalous else ("medium" if related else ("low" if moas else "none")),
                "count": len(moas),
                # Steady rows (only baseline origins, e.g. a sibling ASN or anycast
                # partner) need no action and are summarized; a large network
                # otherwise returns hundreds of them (AS15169: 375 rows, 143 KB).
                **_listed(moas, detail, lambda m: m["classification"] != "steady"),
                "breakdown": {"classification": _shape.count_by(moas, "classification")},
                "detail": (
                    f"{len(moas)} prefix(es) were originated concurrently by another ASN: "
                    f"{len(anomalous)} with an origin outside the prefix's 30-day baseline and no "
                    f"known relation to it (anomalous), {len(related)} where that origin is a "
                    "baseline origin's provider or customer (related), "
                    f"{sum(m['classification'] == 'same_organization' for m in moas)} where it is "
                    "registered to the same organization, and "
                    f"{sum(m['classification'] == 'steady' for m in moas)} with only baseline origins "
                    "(steady, e.g. a customer or anycast partner)."
                    if moas else "No concurrent competing origins detected."
                ),
                "remediation": (
                    "For each anomalous origin, confirm whether it is authorized (a customer "
                    "announcing its own space, a DDoS scrubbing provider). If not, treat it as "
                    "a possible hijack: contact that origin's upstreams, and make sure a ROA for "
                    "the prefix exists so the other origin is RPKI-invalid. Related and "
                    "same-organization origins are likelier to be intended but still worth a "
                    "check that you knew about them; if they are routine, add them to the "
                    "monitor's trust set so they stop alerting. For steady ones, confirm the "
                    "arrangement is still intended."
                    if moas else ""
                ),
                "source": "detections",
            }
            if moas_next is not None:
                more = (
                    f"read {len(moas_incidents)} of {moas_total} moas_conflict incidents; use "
                    f"detections(asn={asn}, detection_type='moas_conflict', offset={moas_next}) "
                    "for the rest"
                )
                finding["note"] = f"{finding['note']} {more}" if finding.get("note") else more
            findings.append(finding)
            try:
                if days_back > 90:
                    extra_warnings.append(warning(
                        "detector_coverage_unverified",
                        "The MOAS check reads detector incidents; coverage can only be verified "
                        "for the last 90 days, so a 'none' before that is unconfirmed.",
                    ))
                trend = got.get("trends")
                if isinstance(trend, Exception):
                    raise trend
                gaps = _shape.detector_gap_days(trend.get("points") or [], start, end)
                if gaps:
                    extra_warnings.append(warning(
                        "detector_gap",
                        f"No detections were recorded platform-wide on {len(gaps)} day(s) in the "
                        f"window ({', '.join(gaps[:5])}{'...' if len(gaps) > 5 else ''}); MOAS "
                        "on those days would not appear.",
                    ))
            except Exception:  # noqa: BLE001
                extra_warnings.append(warning(
                    "detector_coverage_unverified",
                    "Could not confirm the detector ran for the whole window.",
                ))

        # Transit diversity + visibility (every prefix) ------------------
        # One per-ASN rollup query gives every prefix's first-hop neighbors and
        # reach, so nothing is sampled.
        if "transit" in checks or "visibility" in checks:
            transit = (_ok(got.get("transit"), {}) or {}).get("prefixes") or []
            if not transit and isinstance(got.get("transit"), Exception):
                extra_warnings.append(warning(
                    "transit_unavailable", "Per-prefix transit data could not be loaded; the transit "
                    "and visibility checks were skipped."))
            if "transit" in checks and transit:
                rels = _shape.relationship_map(_ok(got.get("relationships"), None))
                t = _shape.transit_analysis(transit, pres_by_cidr, rels)
                _verify_transit_rows(client, asn, t, start, end)
                score["single_homed_prefixes"] = sum(r.get("kind") == "single_homed" for r in t["rows"])
                if t["rows"]:
                    findings.append(_transit_finding(asn, len(transit), t, detail))
            if "visibility" in checks and transit:
                v = _shape.visibility_analysis(transit, pres_by_cidr, audit_context)
                if v["rows"]:
                    findings.append(_visibility_finding(v, detail))

        # Unrouted space (bounded sample of RDAP allocations) --------------
        # Space under a prefix this ASN announces is routed by definition, so the gap
        # is measured against the registered allocation (RDAP) that contains each
        # sampled aggregate: allocation minus every announcement inside or covering it.
        if "unrouted" in checks:
            all_aggregates = unrouted_aggs
            aggregates = all_aggregates[:_UNROUTED_SAMPLE]
            if len(all_aggregates) > _UNROUTED_SAMPLE:
                extra_warnings.append(warning(
                    "sampled_checks",
                    f"The unrouted check looked at {_UNROUTED_SAMPLE} of {len(all_aggregates)} "
                    "aggregates; use subprefixes on an allocation for an exhaustive view.",
                ))
            allocations: list[str] = []
            no_registration: list[str] = []
            for cidr in aggregates:
                rd = got2.get(f"rdap:{cidr}")
                if not isinstance(rd, dict):
                    continue
                if not rd.get("network_cidrs"):
                    no_registration.append(cidr)
                # network_cidrs is the registered block itself; prefix/prefix_len only
                # echo the query, so they cannot be used as the allocation.
                alloc = _shape.CidrIndex(rd.get("network_cidrs") or []).containing(cidr)
                if not alloc or alloc in allocations or (_plen(alloc) or 0) >= (_plen(cidr) or 0):
                    continue  # unknown, or registration no larger than the announced route
                allocations.append(alloc)
            if no_registration:
                extra_warnings.append(warning(
                    "unrouted_unchecked",
                    f"{len(no_registration)} sampled aggregate(s) have no registration record "
                    f"available (e.g. {', '.join(no_registration[:3])}), so their unrouted space "
                    f"was not checked. Up to {_UNROUTED_LIVE} are looked up live per run to "
                    "save the account's daily allowance; run identify on one for its record.",
                ))
            unrouted_findings = []

            def _alloc_view(alloc: str) -> tuple[list[str], dict]:
                cover = _shape.covering_announced(alloc, client.prefix_hierarchy(alloc))
                sub = {} if cover else client.prefix_subprefixes(alloc, start_date=start, end_date=end, limit=1000)
                return cover, sub

            views = _concurrently({a: (lambda a=a: _alloc_view(a)) for a in allocations})
            for alloc in allocations:
                if isinstance(views.get(alloc), Exception):
                    continue
                cover, sub = views[alloc]
                subs = [s.get("cidr") for s in (sub.get("subprefixes") or []) if s.get("cidr")]
                gaps = _shape.unrouted_gaps(alloc, subs + cover)
                un = sum(prefix_addresses(g) for g in gaps)
                if un > 0:
                    unrouted_findings.append({
                        "allocation": alloc,
                        "unrouted_addresses": un,
                        "gaps": gaps[:5],
                        "truncated": (sub.get("total") or 0) > len(subs),
                    })
            if unrouted_findings:
                worst = max(unrouted_findings, key=lambda x: x["unrouted_addresses"])
                findings.append(
                    {
                        "check": "unrouted",
                        "severity": "low",
                        "affected": [x["allocation"] for x in unrouted_findings],
                        "count": len(unrouted_findings),
                        "gaps": unrouted_findings,
                        "detail": f"Registered space that nobody announces, e.g. {worst['unrouted_addresses']} "
                        f"addresses in {worst['allocation']} (gaps include {', '.join(worst['gaps'][:3])}). "
                        "Unannounced space is the easiest to hijack unnoticed.",
                        "remediation": "Cover the allocation with ROAs whose max_length stops at the "
                        "prefixes you actually announce (or an AS0 ROA for space you do not use), so "
                        "an origin for the gaps would be RPKI-invalid.",
                        "note": "sampled",
                    }
                )

        return {
            "asn": asn,
            "prefixes_checked": total,
            "window": {"from": start, "to": end},
            "findings": findings,
            "score": score,
            "warnings": extra_warnings,
            "meta": meta("composed"),
        }

    def _label_origins(moas: list[dict], asn_ident: dict) -> None:
        """Name each other origin (RDAP) and mark those registered to the audited
        network's own organization. A prefix whose other origins are all siblings
        (Cloudflare's AS14789 next to AS13335) is 'same_organization', not anomalous;
        the detector's own flag stays in anomalous_origins."""
        others = sorted({o for m in moas for o in m["other_origins"]})
        names: dict[int, dict] = {}
        for i in range(0, len(others), 200):
            try:
                # Labels only: stored names are enough, so no live registry lookups
                # (those count against the account's daily allowance).
                resp = client.registry_bulk({"asns": others[i:i + 200], "include": ["rdap"], "rdap_live": False})
            except Exception:  # noqa: BLE001
                continue
            for a in others[i:i + 200]:
                e = (resp.get("asns") or {}).get(str(a)) or {}
                h = _shape.prefix_holder(e.get("rdap"), asn_ident, e.get("name_fallback"))
                if h.get("holder"):
                    names[a] = h
        for m in moas:
            m["other_origin_names"] = {str(o): names[o]["holder"] for o in m["other_origins"] if o in names}
            same = [o for o in m["other_origins"] if (names.get(o) or {}).get("holder_is_asn") is True]
            m["same_org_origins"] = same
            if m["classification"] == "anomalous" and same and set(m["other_origins"]) <= set(same):
                m["classification"] = "same_organization"

    def _bulk(chunk: list[str], include: list[str]) -> dict[str, dict]:
        """One bulk registry call: every covering ROA, exact IRR objects and/or the
        cached RDAP record (with a stored-name fallback) per prefix."""
        # Enrichment of up to _ENRICH_LIMIT prefixes: cached records and stored
        # names only, so one health check does not use the account's daily
        # allowance of live registry lookups.
        resp = client.registry_bulk({"prefixes": chunk, "include": include, "rdap_live": False})
        return {c: e for c in chunk if (e := (resp.get("prefixes") or {}).get(c)) is not None}

    # -- validate_announcement ----------------------------------------------
    @api_tool(mcp)
    def validate_announcement(
        prefix: str,
        origin_asn: int,
        check_holder: bool = True,
        as_of: Annotated[Optional[str], Field(description="YYYY-MM-DD: judge against the ROAs and IRR objects published on that day (for a past incident)")] = None,
    ) -> dict:
        """Pre-flight: will announcing `prefix` from `origin_asn` validate? Checks the
        covering ROA (and max-length), IRR route objects, which origins announced it in
        the last 7 days (or on `as_of`), and (because freshly transferred space keeps the
        old holder's ROAs) whether the registration changed recently. Returns verdict
        clear | warn | blocked.

        Without `as_of` the ROA and IRR state is the last two days'. With `as_of` it is
        that day's, which is what a report about a past incident should cite. For many
        prefixes at once use `bulk_registry` with `origin_asn`."""
        origin_asn = normalize_asn(origin_asn)
        plen = _plen(prefix)
        if as_of:
            ref_from = ref_to = as_of
            seen_from = seen_to = as_of
        else:
            ref_to = today().isoformat()
            ref_from = (today() - _dt.timedelta(days=1)).isoformat()
            seen_to = ref_to
            seen_from = (today() - _dt.timedelta(days=7)).isoformat()
        rpki = client.rpki_prefix(prefix, start_date=ref_from, end_date=ref_to)
        irr = client.irr_prefix(prefix, start_date=ref_from, end_date=ref_to)

        records = rpki.get("records", []) or []
        rpki_status: dict[str, Any]
        if not records:
            rpki_status = {
                "status": "unknown",
                "reason": "No ROA covers this prefix; origin validation will treat it as NotFound.",
            }
        else:
            authorizing = [
                r for r in records
                if r.get("origin_asn") == origin_asn
                and (r.get("max_length") is None or plen is None or r["max_length"] >= plen)
            ]
            if authorizing:
                rpki_status = {"status": "valid", "authorized_by": origin_asn}
            else:
                # Every covering ROA is returned (RFC 6811), so name each one: an AS0 ROA
                # or a max_length shorter than the announcement is the usual cause.
                covering = sorted(
                    {(r.get("cidr"), r.get("origin_asn"), r.get("max_length")) for r in records},
                    key=lambda x: (str(x[0]), x[1] or 0, x[2] or 0),
                )
                parts = [f"{c} AS{o} max /{m}" for c, o, m in covering]
                if all(o == 0 for _, o, _ in covering):
                    why = "the covering ROA(s) are AS0, the holder's 'do not route' marker"
                elif any(o == origin_asn for _, o, _ in covering):
                    why = f"AS{origin_asn} is authorized, but not at /{plen} (max_length too short)"
                else:
                    why = f"no covering ROA authorizes AS{origin_asn}"
                rpki_status = {
                    "status": "invalid",
                    "covering_roas": [{"cidr": c, "origin_asn": o, "max_length": m} for c, o, m in covering],
                    "reason": f"RPKI-invalid: {why} (covering: {'; '.join(parts)}).",
                    "would_be_rejected_by": "any network performing origin validation",
                }

        # A windowed lookup already returns only objects present in the window; the filter also
        # guards against a caller or cache handing back deleted objects.
        irr_records = [r for r in (irr.get("records", []) or []) if as_of or _shape.irr_is_current(r)]
        irr_origins = {r.get("origin_as") for r in irr_records}
        if not irr_records:
            irr_status = {"status": "missing", "detail": "No route object; IRR-based filters have nothing to match."}
        elif origin_asn in irr_origins:
            irr_status = {"status": "present", "origin_as": origin_asn}
        else:
            irr_status = {
                "status": "mismatch",
                "detail": f"IRR route objects name {sorted(o for o in irr_origins if o)}, not AS{origin_asn}.",
            }

        announced = []
        try:
            ov = client.prefix_overview(prefix, start_date=seen_from, end_date=seen_to)
            announced = [o.get("origin_as") for o in (ov.get("origins") or [])]
        except Exception:  # noqa: BLE001
            pass

        holder = None
        recently_transferred = False
        if check_holder:
            try:
                rdap = client.rdap_prefix(prefix)
                holder = {
                    "registrant": _shape.registrant_name(rdap),
                    "last_changed": rdap.get("last_changed_date"),
                }
                recently_transferred = _within_days(rdap.get("last_changed_date"), 90)
                holder["recently_transferred"] = recently_transferred
            except Exception:  # noqa: BLE001
                pass

        blockers: list[str] = []
        warns: list[str] = []
        if rpki_status["status"] == "invalid":
            blockers.append(rpki_status["reason"])
        if rpki_status["status"] == "unknown":
            warns.append(rpki_status["reason"])
        if irr_status["status"] in ("missing", "mismatch"):
            warns.append(irr_status["detail"])
        if recently_transferred:
            warns.append(
                "Space changed registered holder within 90 days. The previous holder's ROAs may "
                "still be published; confirm before announcing."
            )
        verdict = "blocked" if blockers else ("warn" if warns else "clear")

        return {
            "prefix": prefix,
            "origin_asn": origin_asn,
            "rpki": rpki_status,
            "irr": irr_status,
            "announced_by": {
                "window": {"from": seen_from, "to": seen_to},
                "origins": [c for c in announced if c is not None],
            },
            "registry_as_of": {"from": ref_from, "to": ref_to},
            "holder": holder,
            "verdict": verdict,
            "blockers": blockers,
            "warnings": [warning("validation", w) for w in warns],
            "meta": meta("composed"),
        }

    # -- visibility ----------------------------------------------------------
    @api_tool(mcp)
    def visibility(
        prefix: str,
        compare_to: Optional[list[str]] = None,
        window: str = "7d",
    ) -> dict:
        """Where can the internet see this prefix, and where can it not? Peer and
        collector reach, upstreams (collector sessions per upstream, at most the last 31
        days), and a ratio against sibling prefixes. Absolute peer counts mean little; a prefix seen by 40 peers when its
        siblings are seen by 330 is being filtered."""
        start, end = window_from_shorthand(window, default_days=7)
        ov = client.prefix_overview(prefix, start_date=start, end_date=end)
        peers = ov.get("unique_peers")
        upstreams, direct, up_warnings = session_upstreams(
            client, prefix, start, end, paths=ov.get("paths", []) or []
        )
        # Upstreams under 1% of sessions are stray paths, not transit.
        significant = [u for u in upstreams if (u.get("share") or 0) >= 0.01]

        baseline = None
        if compare_to:
            sib_peers = []
            for sib in compare_to:
                try:
                    sov = client.prefix_overview(sib, start_date=start, end_date=end)
                    if sov.get("unique_peers") is not None:
                        sib_peers.append(sov["unique_peers"])
                except Exception:  # noqa: BLE001
                    continue
            if sib_peers:
                median = sorted(sib_peers)[len(sib_peers) // 2]
                baseline = {
                    "median_across_siblings": median,
                    "ratio": round(peers / median, 3) if median and peers else None,
                }

        warnings = list(up_warnings)
        if len({u["asn"] for u in significant}) == 1:
            warnings.append(
                warning(
                    "single_upstream",
                    f"Every collector session that heard it (apart from strays under 1%) did so "
                    f"through AS{significant[0]['asn']}: a single point of failure and a common "
                    "cause of thin visibility.",
                )
            )
        if baseline and baseline.get("ratio") is not None and baseline["ratio"] < 0.6:
            warnings.append(
                warning(
                    "filtered",
                    f"Seen by {peers} peers vs a sibling median of {baseline['median_across_siblings']} "
                    f"({int(baseline['ratio'] * 100)}%). This prefix is being filtered somewhere. "
                    "check RPKI/IRR validity and upstream filters.",
                )
            )

        return {
            "prefix": prefix,
            "peers_seeing": peers,
            "collectors_seeing": ov.get("unique_collectors"),
            "peer_baseline": baseline,
            "upstreams": upstreams,
            "direct_share": direct,
            "concentration": ov.get("concentration"),
            "warnings": warnings,
            "meta": meta("rollup"),
        }


# -- health_check finding builders ---------------------------------------------
# Each lists every affected prefix (up to _LIST_LIMIT) with its persistence and holder,
# counts the groups, and phrases remediation per group, so a reader sees which rows are
# one-day blips or someone else's space instead of having them silently left out.

def _listed(rows: list[dict], detail: str = "full", actionable: Optional[Callable[[dict], bool]] = None) -> dict:
    """The rows to return for a finding. `full` lists up to _LIST_LIMIT rows. `summary`
    (the default) lists the rows that need action in full and summarizes the rest with
    `other_examples`: a Cloudflare-sized network otherwise returns ~200 KB, most of it
    rows like 'covered by a less-specific IRR object' that need no action. Counts and
    breakdowns always cover every row either way."""
    if detail == "full" or actionable is None:
        keep, rest = rows, []
    else:
        keep = [r for r in rows if actionable(r)]
        rest = [r for r in rows if not actionable(r)]
    out: dict[str, Any] = {"affected": [r["prefix"] for r in keep[:_LIST_LIMIT]], "prefixes": keep[:_LIST_LIMIT]}
    notes = []
    if len(keep) > _LIST_LIMIT:
        notes.append(f"first {_LIST_LIMIT} of {len(keep)} listed")
    if rest:
        out["other_examples"] = rest[:_EXAMPLES]
        notes.append(f"{len(rest)} rows needing no action are summarized in breakdown, with "
                     f"{min(len(rest), _EXAMPLES)} in other_examples; pass detail='full' to list them")
    if notes:
        out["note"] = "; ".join(notes) + ". Counts cover all."
    return out


def _top_counts(rows: list[dict], key: str, n: int = 10) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        if r.get(key):
            out[r[key]] = out.get(r[key], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1])[:n])


def _holders(rows: list[dict], want: Optional[bool], n: int = 3) -> list[str]:
    return list(dict.fromkeys(r["holder"] for r in rows if r.get("holder_is_asn") is want and r.get("holder")))[:n]


def _short_lived(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("persistence") in ("transient", "intermittent")]


def _rpki_notfound_finding(asn: int, total: int, rows: list[dict], all_uncovered: bool, detail: str) -> dict:
    blips = _short_lived(rows)
    other = [r for r in rows if r.get("holder_is_asn") is False]
    steps = []
    own = [r for r in rows if r not in blips and r.get("holder_is_asn") is not False]
    if own:
        steps.append(f"Create ROAs authorizing AS{asn} (max_length equal to each announced length) "
                     f"for the {len(own)} steadily announced prefixes in your own or unconfirmed space.")
    if other:
        steps.append(f"{len(other)} prefixes are registered to other organizations "
                     f"(e.g. {', '.join(_holders(rows, False)) or 'see holder'}). Only the holder can "
                     f"publish a ROA, so ask each one to authorize AS{asn}.")
    if blips:
        steps.append(f"{len(blips)} were announced on only part of the window (transient or "
                     "intermittent). Confirm each was intended before publishing a ROA; an "
                     "unintended announcement is its own problem to look into.")
    return {
        "check": "rpki",
        "severity": "high" if all_uncovered else "medium",
        "count": len(rows),
        # Other organizations' space is summarized (by holder): only they can act on it.
        **_listed(rows, detail, lambda r: r.get("holder_is_asn") is not False),
        "breakdown": {"persistence": _shape.count_by(rows, "persistence"),
                      "holder_is_asn": _shape.count_by(rows, "holder_is_asn"),
                      "other_holders": _top_counts([r for r in rows if r.get("holder_is_asn") is False], "holder")},
        "detail": f"{len(rows)} of {total} announced prefixes have no ROA covering them (RPKI "
        "NotFound). Origin validation can neither accept nor reject them.",
        "remediation": " ".join(steps),
    }


def _rpki_invalid_finding(asn: int, rows: list[dict]) -> dict:
    by_reason = _shape.count_by(rows, "reason")
    steps = []
    if by_reason.get("as0"):
        steps.append(f"{by_reason['as0']} are covered only by AS0 ROAs, the holder's 'do not route' "
                     f"marker. Either the holder replaces the AS0 ROA with one authorizing AS{asn}, or "
                     "the announcement should stop.")
    if by_reason.get("max_length"):
        steps.append(f"{by_reason['max_length']} have a ROA for AS{asn} whose max_length is shorter than "
                     "the announced prefix. Raise max_length to the announced length or add a ROA for "
                     "the exact prefix.")
    if by_reason.get("other_origin"):
        steps.append(f"{by_reason['other_origin']} are covered by ROAs for other origins only. The holder "
                     f"must add a ROA for AS{asn} if the announcement is authorized.")
    return {
        "check": "rpki_invalid",
        "severity": "high",
        "count": len(rows),
        **_listed(rows),
        "breakdown": {"reason": by_reason, "persistence": _shape.count_by(rows, "persistence"),
                      "holder_is_asn": _shape.count_by(rows, "holder_is_asn")},
        "detail": f"{len(rows)} announced prefixes are RPKI-invalid: a ROA covers them but none "
        f"authorizes AS{asn} at that length. Networks performing origin validation drop these routes.",
        "remediation": " ".join(steps),
    }


def _maxlength_finding(asn: int, rows: list[dict]) -> dict:
    other = [r for r in rows if r.get("holder_is_asn") is False]
    steps = ["Set each ROA's max_length to the longest prefix actually originated inside it "
             "(`suggested_max_length`), not the host length."]
    if other:
        steps.append(f"{len(other)} of these ROAs cover space registered to other organizations "
                     f"(e.g. {', '.join(_holders(rows, False))}); only they can change them.")
    return {
        "check": "maxlength",
        "severity": "medium",
        "count": len(rows),
        **_listed(rows),
        "breakdown": {"holder_is_asn": _shape.count_by(rows, "holder_is_asn")},
        "detail": "ROAs whose max_length reaches the host length (/32 or /128) authorize any "
        f"more-specific from AS{asn}, a hijack surface rather than protection.",
        "remediation": " ".join(steps),
    }


def _irr_finding(asn: int, total: int, rows: list[dict], detail: str) -> dict:
    by_state = _shape.count_by(rows, "state")
    steps = []
    if by_state.get("missing"):
        steps.append(f"Register route/route6 objects with origin AS{asn} for the {by_state['missing']} "
                     "prefixes that have none, in an IRR your upstreams use.")
    if by_state.get("covered_by_less_specific"):
        steps.append(f"{by_state['covered_by_less_specific']} are inside a less-specific route object "
                     f"for AS{asn}. Filters that accept more-specifics of registered routes pass them; "
                     "exact-match filters do not, so add exact objects if an upstream filters that way.")
    if by_state.get("other_origin_only"):
        steps.append(f"{by_state['other_origin_only']} have route objects only for other origins. Add "
                     f"an object for AS{asn}, and have stale objects removed.")
    if _short_lived(rows):
        steps.append("Transient or intermittent prefixes may not need objects; confirm they were "
                     "intended first.")
    return {
        "check": "irr",
        "severity": "medium" if by_state.get("missing") or by_state.get("other_origin_only") else "low",
        "count": len(rows),
        **_listed(rows, detail, lambda r: r.get("state") != "covered_by_less_specific"),
        "breakdown": {"state": by_state, "persistence": _shape.count_by(rows, "persistence"),
                      "holder_is_asn": _shape.count_by(rows, "holder_is_asn")},
        "detail": f"{len(rows)} of {total} prefixes have no exact route object with origin AS{asn}.",
        "remediation": " ".join(steps),
    }


_TRANSIT_VERIFY = 30


def _verify_transit_rows(client: BGPHorizonClient, asn: int, t: dict, start: str, end: str) -> None:
    """Re-check single-neighbor rows against collector sessions, which count each
    session once through the upstream it actually used. Two cases need it:

    - rows with prepended paths whose neighbor the rollup did not record
      (`neighbors_uncertain`): the prepends may go through a backup provider or the
      same one, and only the sessions can tell;
    - rows that carry a recommendation (single_homed, direct-only, customer-only):
      neighbor shares are weighted by update volume, so a busy primary can push a
      real second neighbor under the 1% cut.

    A row whose sessions show two or more neighbors at 1% or more is dropped and
    counted in `verified_multi`; the rest are marked `verified_by_sessions`. Any
    neighbor the sessions reveal joins the network-wide set, so `single_homed`
    becomes `selective` when the network turns out to have a second neighbor.
    At most _TRANSIT_VERIFY rows are checked; uncertain rows beyond that stay
    marked and are counted in `unverified_uncertain`."""
    uncertain = [r for r in t["rows"] if r.get("neighbors_uncertain")]
    actionable = [r for r in t["rows"] if not r.get("neighbors_uncertain") and (
        r.get("kind") in ("single_homed", "direct_sessions_only") or r.get("relationship") == "customer")]
    targets = (uncertain + actionable)[:_TRANSIT_VERIFY]
    if targets:
        with quiet_api_warnings():
            got = _concurrently({r["prefix"]: (lambda r=r: session_upstreams(
                client, r["prefix"], start, end, origin_as=asn)) for r in targets})
    else:
        got = {}
    network = set(t.get("network") or ())
    drop = set()
    for r in targets:
        res = got.get(r["prefix"])
        if isinstance(res, Exception) or not res:
            continue
        ups, direct, _ = res
        significant = {u["asn"] for u in ups if (u.get("share") or 0) >= 0.01}
        network |= significant
        if len(significant) >= 2:
            drop.add(r["prefix"])
        elif ups or direct:
            r["verified_by_sessions"] = True
            r.pop("neighbors_uncertain", None)
    if drop:
        t["rows"] = [r for r in t["rows"] if r["prefix"] not in drop]
        t["verified_multi"] = len(drop)
    if len(network) > 1:
        for r in t["rows"]:
            if r.get("kind") == "single_homed":
                r["kind"] = "selective"
    t["network_neighbors"] = len(network)
    t["unverified_uncertain"] = sum(1 for r in t["rows"] if r.get("neighbors_uncertain"))


def _transit_finding(asn: int, total: int, t: dict, detail: str) -> dict:
    rows = t["rows"]
    homed = [r for r in rows if r.get("kind") == "single_homed"]
    selective = [r for r in rows if r.get("kind") == "selective"]
    direct = [r for r in rows if r.get("kind") == "direct_sessions_only"]
    via_customer = [r for r in selective if r.get("relationship") == "customer"]
    by_neighbor: dict[str, int] = {}
    for r in selective:
        label = f"AS{r['neighbor']}" + (f" {r['neighbor_name']}" if r.get("neighbor_name") else "")
        by_neighbor[label] = by_neighbor.get(label, 0) + 1
    steps = []
    if homed:
        steps.append(f"AS{asn} reaches the table through a single neighbor for all its prefixes. "
                     "Add a second provider to remove the single point of failure.")
    if selective:
        uses = str(t["network_neighbors"])
        steps.append(f"{len(selective)} prefixes reach the table through one neighbor while the network "
                     f"as a whole uses {uses}. That is usually deliberate (regional or "
                     "traffic-engineered announcements); if any should be reachable everywhere, announce it "
                     "to your other providers too.")
    if via_customer:
        steps.append(f"{len(via_customer)} of them are seen only through a network inferred to be your "
                     "customer, which is unusual for your own space: check they are meant to be announced "
                     "that way.")
    if direct:
        steps.append(f"{len(direct)} were seen only on direct sessions with route collectors, with no "
                     "neighbor in between; they may not be propagated at all.")
    severity = "high" if homed else ("medium" if via_customer or direct else "low")
    return {
        "check": "transit",
        "severity": severity,
        "count": len(rows),
        # Selective announcements are summarized by neighbor (top_lone_neighbors).
        **_listed(rows, detail, lambda r: r.get("kind") != "selective" or r.get("relationship") == "customer"
                  or r.get("neighbors_uncertain")),
        "breakdown": {"kind": _shape.count_by(rows, "kind"),
                      "relationship": _shape.count_by(selective, "relationship"),
                      "persistence": _shape.count_by(rows, "persistence"),
                      "top_lone_neighbors": dict(sorted(by_neighbor.items(), key=lambda kv: -kv[1])[:10])},
        "detail": f"{len(rows)} of {total} prefixes reach the route collectors through at most one "
        f"first-hop neighbor (network-wide: {t['network_neighbors']} neighbors"
        + ")."
        + (f" Not counted: {t['verified_multi']} that collector sessions show reaching the "
           "table through two or more neighbors (update counts or prepending had hidden the second)."
           if t.get("verified_multi") else "")
        + (f" {t['unverified_uncertain']} rows marked neighbors_uncertain have prepended paths "
           "whose neighbor is not recorded and were beyond the verification limit; check them "
           "with `paths` before acting."
           if t.get("unverified_uncertain") else ""),
        "remediation": " ".join(steps),
    }


def _visibility_finding(v: dict, detail: str) -> dict:
    rows = v["rows"]
    unexplained = [r for r in rows if not r["likely_reasons"] and r.get("persistence") == "persistent"]
    invalid = [r for r in rows if "rpki_invalid" in r["likely_reasons"]]
    steps = []
    if invalid:
        steps.append(f"{len(invalid)} are RPKI-invalid, so networks performing origin validation drop "
                     "them; fixing the ROA (see rpki_invalid) should restore reach.")
    if unexplained:
        steps.append(f"{len(unexplained)} steadily announced prefixes have no obvious cause: check "
                     "upstream prefix filters and whether each is announced to all your providers.")
    other = len(rows) - len(invalid) - len(unexplained)
    if other > 0:
        steps.append(f"The other {other} are explained by being short-lived, single-neighbor or "
                     "missing an IRR object (see likely_reasons).")
    return {
        "check": "visibility",
        "severity": "medium" if invalid or unexplained else "low",
        "count": len(rows),
        **_listed(rows, detail, lambda r: not r["likely_reasons"] or "rpki_invalid" in r["likely_reasons"]),
        "breakdown": {"likely_reasons": _shape.count_by(
            [{"r": x} for r in rows for x in (r["likely_reasons"] or ["none"])], "r")},
        "family_median_peers": v["medians"],
        "detail": f"{len(rows)} prefixes are seen by fewer than 60% of the collector peers that see the "
        "network's typical persistent prefix of the same address family.",
        "remediation": " ".join(steps),
    }


# -- small helpers -----------------------------------------------------------

def _concurrently(calls: dict[str, Callable[[], Any]]) -> dict[str, Any]:
    """Run independent API reads at once. Each runs in a copy of the caller's context:
    on the hosted server the caller's API key lives in a contextvar, and a bare thread
    would not see it. A call that raises returns its exception in place of a result."""
    if not calls:
        return {}

    def run(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            return e

    with ThreadPoolExecutor(max_workers=min(_MAX_PARALLEL, len(calls))) as pool:
        futures = {k: pool.submit(contextvars.copy_context().run, run, fn) for k, fn in calls.items()}
        return {k: f.result() for k, f in futures.items()}


def _ok(value: Any, default: Any) -> Any:
    """A result from _concurrently, or `default` if the call failed or was not made."""
    return default if value is None or isinstance(value, Exception) else value


def _unrouted_aggregates(announced: list[str], pres_by_cidr: dict[str, dict]) -> list[str]:
    """Announced aggregates (shorter than /24 or /48) that are not transient."""
    return [
        c for c in announced
        if _plen(c) is not None and _plen(c) < (24 if ":" not in c else 48)
        and (pres_by_cidr.get(c) or {}).get("classification") != "transient"
    ]

def _plen(cidr: str | None) -> Optional[int]:
    if not cidr or "/" not in cidr:
        return None
    try:
        return int(cidr.split("/", 1)[1])
    except ValueError:
        return None


def _within_days(iso_date: str | None, days: int) -> bool:
    if not iso_date:
        return False
    try:
        d = _dt.datetime.fromisoformat(iso_date.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            d = _dt.date.fromisoformat(iso_date[:10])
        except ValueError:
            return False
    return (_dt.datetime.now(_dt.timezone.utc).date() - d).days <= days
