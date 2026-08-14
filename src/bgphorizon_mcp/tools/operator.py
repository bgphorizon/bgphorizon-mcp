"""Operator tools (3) — watching a network you own.

These answer "is my stuff correct and healthy?" and every finding carries
`remediation` in operator terms, so a model can hand an engineer an action list
rather than a data dump.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import BGPHorizonClient
from ..common import (
    default_window,
    meta,
    normalize_asn,
    warning,
    window_from_shorthand,
)
from . import _shape

# Bound the per-prefix probing so an audit stays a handful of calls, not hundreds.
_SAMPLE_LIMIT = 8


def register_operator_tools(mcp: FastMCP, client: BGPHorizonClient) -> None:

    # -- health_check --------------------------------------------------------
    @mcp.tool()
    def health_check(
        asn: int,
        window: str = "30d",
        checks: Optional[list[str]] = None,
    ) -> dict:
        """Full hygiene + exposure audit for an ASN you control — the single most
        valuable operator call. Checks RPKI/IRR coverage, MOAS, ROA max-length
        exposure, transit diversity and visibility, each with remediation. Sampling
        bounds the per-prefix checks to keep it fast."""
        asn = normalize_asn(asn)
        checks = checks or ["rpki", "irr", "moas", "maxlength", "transit", "visibility", "unrouted"]
        start, end = window_from_shorthand(window, default_days=30)

        pres = client.presence(asn=asn, **{"from": start, "to": end})
        prefixes = pres.get("prefixes", []) or []
        announced = [p.get("cidr") for p in prefixes if p.get("cidr")]
        announced_set = set(announced)
        total = len(announced_set)

        # Request the full record set (coverage must count every distinct prefix,
        # not a page). The endpoint returns per-observation rows, so we de-dupe by
        # CIDR below; a high limit ensures every distinct prefix is represented.
        _FULL = 100000
        rpki = (
            client.rpki_asn(asn, start_date=start, end_date=end, limit=_FULL)
            if "rpki" in checks or "maxlength" in checks
            else {}
        )
        irr = client.irr_asn(asn, start_date=start, end_date=end, limit=_FULL) if "irr" in checks else {}

        findings: list[dict] = []
        score: dict[str, Any] = {}

        # RPKI --------------------------------------------------------
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
        if "rpki" in checks:
            # Proper origin validation: a covering ROA (max_length >= announced
            # length) counts, not just an exact-CIDR ROA.
            _, missing = _shape.rpki_coverage(announced, distinct_roas, asn)
            missing = sorted(missing)
            covered = total - len(missing)
            score["rpki_coverage"] = round(covered / total, 3) if total else None
            if missing:
                findings.append(
                    {
                        "check": "rpki",
                        "severity": "high" if total and len(missing) == total else "medium",
                        "affected": missing[:20],
                        "count": len(missing),
                        "detail": f"{len(missing)} of {total} announced prefixes are not covered "
                        "by any ROA authorising this ASN — those announcements cannot be validated "
                        "by origin validation.",
                        "remediation": f"Create ROAs authorising AS{asn} (max_length equal to each "
                        "announced length) for the uncovered prefixes.",
                    }
                )

        # ROA max-length exposure ---------------------------------------
        if "maxlength" in checks:
            loose = []
            for r in distinct_roas:
                plen = r.get("prefix_len")
                ml = r.get("max_length")
                cidr = r.get("cidr") or ""
                host = 32 if ":" not in cidr else 128
                # Only flag max_length opened all the way to the host length on a
                # shorter ROA — that authorises any more-specific and is a genuine
                # hijack surface. Ordinary max_length that covers real more-specifics
                # is normal and not flagged.
                if plen is not None and ml == host and plen < host:
                    loose.append({"cidr": cidr, "prefix_len": plen, "max_length": ml})
            if loose:
                findings.append(
                    {
                        "check": "maxlength",
                        "severity": "medium",
                        "affected": [x["cidr"] for x in loose[:20]],
                        "count": len(loose),
                        "detail": "ROAs whose max_length reaches the host length (/32 or /128) "
                        "authorise any more-specific under this origin — a hijack surface rather "
                        "than protection.",
                        "remediation": "Set max_length to the longest prefix you actually "
                        "originate, not the host length.",
                    }
                )

        # IRR coverage ---------------------------------------------------
        if "irr" in checks:
            irr_cidrs = {r.get("cidr") for r in (irr.get("routes_v4", []) or []) + (irr.get("routes_v6", []) or [])}
            missing_irr = sorted(announced_set - irr_cidrs)
            score["irr_coverage"] = round((total - len(missing_irr)) / total, 3) if total else None
            if missing_irr:
                findings.append(
                    {
                        "check": "irr",
                        "severity": "medium",
                        "affected": missing_irr[:20],
                        "count": len(missing_irr),
                        "detail": f"{len(missing_irr)} of {total} prefixes have no IRR route object. "
                        "Providers that build prefix filters from IRR have nothing to match.",
                        "remediation": "Register route/route6 objects for each prefix in an IRR your "
                        "upstreams use.",
                    }
                )

        # MOAS -----------------------------------------------------------
        if "moas" in checks:
            moas = []
            for p in prefixes:
                origins = {
                    o
                    for day in (p.get("origins_by_day") or {}).values()
                    for o in (day.keys() if isinstance(day, dict) else day)
                }
                if len({int(o) for o in origins}) > 1:
                    moas.append(p.get("cidr"))
            score["prefixes_with_moas"] = len(moas)
            findings.append(
                {
                    "check": "moas",
                    "severity": "high" if moas else "none",
                    "affected": moas[:20],
                    "count": len(moas),
                    "detail": (f"{len(moas)} prefixes seen with a competing origin."
                               if moas else "No competing origins observed."),
                    "remediation": "Investigate each competing origin; if unauthorised, it is a hijack."
                    if moas else "",
                }
            )

        # Transit diversity + visibility (bounded sample) ----------------
        sample = announced[:_SAMPLE_LIMIT]
        if "transit" in checks or "visibility" in checks:
            single_homed = []
            thin_visibility = []
            peer_counts = []
            for cidr in sample:
                try:
                    ov = client.prefix_overview(cidr, start_date=start, end_date=end)
                except Exception:  # noqa: BLE001
                    continue
                upstreams = {p.get("upstream_as") for p in (ov.get("paths") or []) if p.get("upstream_as")}
                if len(upstreams) <= 1:
                    single_homed.append(cidr)
                peers = ov.get("unique_peers")
                if peers is not None:
                    peer_counts.append((cidr, peers))
            if "transit" in checks and single_homed:
                score["single_homed_prefixes"] = len(single_homed)
                findings.append(
                    {
                        "check": "transit",
                        "severity": "medium",
                        "affected": single_homed,
                        "count": len(single_homed),
                        "detail": f"{len(single_homed)} of {len(sample)} sampled prefixes reach the "
                        "table through a single upstream.",
                        "remediation": "Extend a second provider to these prefixes to remove the "
                        "single point of failure.",
                        "note": "sampled" if total > len(sample) else None,
                    }
                )
            if "visibility" in checks and peer_counts:
                median = sorted(p for _, p in peer_counts)[len(peer_counts) // 2]
                weak = [c for c, p in peer_counts if median and p < 0.6 * median]
                if weak:
                    findings.append(
                        {
                            "check": "visibility",
                            "severity": "medium",
                            "affected": weak,
                            "count": len(weak),
                            "detail": f"{len(weak)} prefixes seen by far fewer peers than their "
                            f"siblings (median {median}) — likely being filtered somewhere.",
                            "remediation": "Check RPKI/IRR validity and upstream filters for these "
                            "prefixes; thin visibility usually means a rejected or missing object.",
                        }
                    )

        # Unrouted space (bounded sample of aggregates) ------------------
        if "unrouted" in checks:
            aggregates = [c for c in announced if _plen(c) and _plen(c) < 24][:_SAMPLE_LIMIT]
            unrouted_findings = []
            for cidr in aggregates:
                try:
                    sub = client.prefix_subprefixes(cidr, start_date=start, end_date=end)
                except Exception:  # noqa: BLE001
                    continue
                un = _shape.unrouted_estimate(cidr, sub.get("subprefixes", []) or [])
                if un > 0:
                    unrouted_findings.append({"cidr": cidr, "unrouted_addresses": un})
            if unrouted_findings:
                worst = max(unrouted_findings, key=lambda x: x["unrouted_addresses"])
                findings.append(
                    {
                        "check": "unrouted",
                        "severity": "medium",
                        "affected": [x["cidr"] for x in unrouted_findings],
                        "count": len(unrouted_findings),
                        "detail": f"Allocated space with no visible more-specific — e.g. ~"
                        f"{worst['unrouted_addresses']} addresses under {worst['cidr']}. Unannounced "
                        "space is the easiest to hijack unnoticed.",
                        "remediation": "Publish a covering ROA permitting only the intended "
                        "more-specifics, so the gaps cannot be originated by anyone else.",
                    }
                )

        return {
            "asn": asn,
            "prefixes_checked": total,
            "window": {"from": start, "to": end},
            "findings": findings,
            "score": score,
            "warnings": [
                warning(
                    "sampled_checks",
                    f"Transit, visibility and unrouted checks sampled up to {_SAMPLE_LIMIT} "
                    "prefixes each; re-run scoped to a prefix for exhaustive results.",
                )
            ]
            if total > _SAMPLE_LIMIT
            else [],
            "meta": meta("composed"),
        }

    # -- validate_announcement ----------------------------------------------
    @mcp.tool()
    def validate_announcement(
        prefix: str,
        origin_asn: int,
        check_holder: bool = True,
    ) -> dict:
        """Pre-flight: will announcing `prefix` from `origin_asn` validate? Checks the
        covering ROA (and max-length), IRR route objects, who announces it today, and
        — because freshly transferred space keeps the old holder's ROAs — whether the
        registration changed recently. Returns verdict clear | warn | blocked."""
        origin_asn = normalize_asn(origin_asn)
        plen = _plen(prefix)
        rpki = client.rpki_prefix(prefix)
        irr = client.irr_prefix(prefix)

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
                other = sorted({r.get("origin_asn") for r in records if r.get("origin_asn")})
                ml = next((r.get("max_length") for r in records), None)
                rpki_status = {
                    "status": "invalid",
                    "reason": f"ROA(s) authorise {other}"
                    + (f", max_length {ml}" if ml is not None else "")
                    + f"; announcing from AS{origin_asn} would be RPKI-invalid.",
                    "would_be_rejected_by": "any network performing origin validation",
                }

        irr_records = irr.get("records", []) or []
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

        currently = []
        try:
            ov = client.prefix_overview(prefix)
            currently = [o.get("origin_as") for o in (ov.get("origins") or [])]
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
                "Space changed registered holder within 90 days — the previous holder's ROAs may "
                "still be published; confirm before announcing."
            )
        verdict = "blocked" if blockers else ("warn" if warns else "clear")

        return {
            "prefix": prefix,
            "origin_asn": origin_asn,
            "rpki": rpki_status,
            "irr": irr_status,
            "currently_announced_by": [c for c in currently if c is not None],
            "holder": holder,
            "verdict": verdict,
            "blockers": blockers,
            "warnings": warns,
            "meta": meta("composed"),
        }

    # -- visibility ----------------------------------------------------------
    @mcp.tool()
    def visibility(
        prefix: str,
        compare_to: Optional[list[str]] = None,
        window: str = "7d",
    ) -> dict:
        """Where can the internet see this prefix, and where can it not? Peer and
        collector reach, upstreams, and — the useful part — a ratio against sibling
        prefixes. Absolute peer counts mean little; a prefix seen by 40 peers when its
        siblings are seen by 330 is being filtered."""
        start, end = window_from_shorthand(window, default_days=7)
        ov = client.prefix_overview(prefix, start_date=start, end_date=end)
        peers = ov.get("unique_peers")
        upstreams = _shape.aggregate_upstreams(ov.get("paths", []) or [])

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

        warnings = []
        if len(upstreams) <= 1:
            warnings.append(
                warning(
                    "single_upstream",
                    "Reachable through one upstream only — a single point of failure and a "
                    "common cause of thin visibility.",
                )
            )
        if baseline and baseline.get("ratio") is not None and baseline["ratio"] < 0.6:
            warnings.append(
                warning(
                    "filtered",
                    f"Seen by {peers} peers vs a sibling median of {baseline['median_across_siblings']} "
                    f"({int(baseline['ratio'] * 100)}%). This prefix is being filtered somewhere — "
                    "check RPKI/IRR validity and upstream filters.",
                )
            )

        return {
            "prefix": prefix,
            "peers_seeing": peers,
            "collectors_seeing": ov.get("unique_collectors"),
            "peer_baseline": baseline,
            "upstreams": upstreams,
            "concentration": ov.get("concentration"),
            "warnings": warnings,
            "meta": meta("rollup"),
        }


# -- small helpers -----------------------------------------------------------

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
    import datetime as _dt

    try:
        d = _dt.datetime.fromisoformat(iso_date.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            d = _dt.date.fromisoformat(iso_date[:10])
        except ValueError:
            return False
    return (_dt.datetime.now(_dt.timezone.utc).date() - d).days <= days
