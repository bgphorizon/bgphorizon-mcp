"""Pure reshaping helpers shared across tools.

These turn raw ``/api/v1`` payloads into the task-shaped structures the tool
contracts promise (docs/mcp/TOOLS.md). Kept pure and importable so the logic that
docs say a model tends to get wrong — persistence transitions, detection direction,
upstream/prepend collapsing — is testable in isolation.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..common import prefix_addresses


# -- identify ----------------------------------------------------------------

def abuse_email(rdap: dict | None) -> str | None:
    if not isinstance(rdap, dict):
        return None
    for ent in rdap.get("entities", []) or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "abuse" in roles and ent.get("email"):
            return ent["email"]
    return None


def registrant_name(rdap: dict | None) -> str | None:
    if not isinstance(rdap, dict):
        return None
    for ent in rdap.get("entities", []) or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrant" in roles and ent.get("name"):
            return ent["name"]
    # fall back to the network/autnum name
    return rdap.get("name")


def irr_objects(irr: dict | None, observed_origins: set[int]) -> list[dict]:
    """Flatten IRR records to {origin_as, source, stale}. ``stale`` marks an IRR
    origin never actually observed announcing the space."""
    if not isinstance(irr, dict):
        return []
    records = irr.get("records") or irr.get("routes_v4") or []
    seen: set[tuple[int, str]] = set()
    out: list[dict] = []
    for r in records:
        origin = r.get("origin_as")
        source = r.get("source", "")
        if origin is None:
            continue
        key = (origin, source)
        if key in seen:
            continue
        seen.add(key)
        obj = {"origin_as": origin, "source": source}
        if observed_origins and origin not in observed_origins:
            obj["stale"] = True
        out.append(obj)
    return out


# -- origin_history / transitions --------------------------------------------

def days_from_origins_by_day(origins_by_day: dict[str, Any]) -> list[dict]:
    """{date: [asn,...]} → ordered [{d, origins:[...], moas}]."""
    days = []
    for d in sorted(origins_by_day.keys()):
        origins = origins_by_day[d]
        if isinstance(origins, dict):
            origin_list = [int(k) for k in origins.keys()]
        else:
            origin_list = [int(o) for o in origins]
        days.append(
            {"d": d, "origins": origin_list, "moas": len(set(origin_list)) > 1}
        )
    return days


def transitions_from_days(days: list[dict]) -> list[dict]:
    """Detect origin changes and classify each: handover | episode | intermittent.

    - handover: origin A gives way to origin B and B persists to the end.
    - episode:  origin B appears then reverts back to A.
    - intermittent: origin flips repeatedly.
    """
    # Build the sequence of *primary* origin sets per day.
    seq = [(day["d"], frozenset(day["origins"])) for day in days if day["origins"]]
    transitions: list[dict] = []
    for i in range(1, len(seq)):
        prev_d, prev = seq[i - 1]
        cur_d, cur = seq[i]
        gained = cur - prev
        lost = prev - cur
        if not gained and not lost:
            continue
        for to_asn in sorted(gained):
            for from_asn in sorted(prev) or [None]:
                # does to_asn persist to the end of the window?
                tail = [s for _, s in seq[i:]]
                persists = all(to_asn in s for s in tail)
                # does the old origin come back *after* the transition day? (the
                # transition day itself often still shows both during a clean handover)
                reverts = any(from_asn in s for _, s in seq[i + 1:]) if from_asn else False
                overlap = sum(
                    1 for _, s in seq if from_asn in s and to_asn in s
                ) if from_asn else 0
                if persists and not reverts:
                    ttype = "handover"
                elif reverts:
                    ttype = "episode"
                else:
                    ttype = "intermittent"
                transitions.append(
                    {
                        "from_asn": from_asn,
                        "to_asn": to_asn,
                        "date": cur_d,
                        "overlap_days": overlap,
                        "type": ttype,
                    }
                )
    return transitions


# -- detections --------------------------------------------------------------

def detection_direction(incident: dict, asn: int | None) -> str | None:
    """Explicit direction relative to a queried ASN. Reading actor_as vs
    baseline_asns wrong inverts a report's conclusion, so we compute it."""
    if asn is None:
        return None
    baseline = incident.get("baseline_asns") or []
    actor = incident.get("actor_as")
    if asn in baseline:
        return "queried_entity_is_baseline"
    if actor == asn:
        return "queried_entity_is_invalid_party"
    return "third_party"


def counts_by(incidents: list[dict], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for inc in incidents:
        key = str(inc.get(field, "unknown"))
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# -- paths -------------------------------------------------------------------

def aggregate_upstreams(paths: list[dict]) -> list[dict]:
    """Sum observed counts by immediate upstream AS → share of total."""
    totals: dict[int, int] = {}
    grand = 0
    for p in paths:
        up = p.get("upstream_as")
        c = p.get("count", 0) or 0
        if up is None:
            continue
        totals[up] = totals.get(up, 0) + c
        grand += c
    out = [
        {"asn": up, "share": round(c / grand, 4) if grand else 0.0}
        for up, c in sorted(totals.items(), key=lambda kv: -kv[1])
    ]
    return out


def prepend_observations(paths: list[dict]) -> list[dict]:
    obs: list[dict] = []
    flagged: set[int] = set()
    for p in paths:
        pc = p.get("prepend_count", 0) or 0
        origin = p.get("origin_as")
        if pc > 0 and origin not in flagged:
            flagged.add(origin)
            obs.append(
                {
                    "code": "prepending_detected",
                    "message": f"AS{origin} prepended {pc}× on at least one path, "
                    "indicating a deliberately de-preferred (backup) path.",
                }
            )
    return obs


# -- subprefixes -------------------------------------------------------------

def rpki_coverage(
    announced: list[str], roa_records: list[dict], asn: int
) -> tuple[list[str], list[str]]:
    """Split announced prefixes into (covered, uncovered) by proper RPKI origin
    validation — not exact-CIDR matching.

    An announced prefix is covered when some ROA for `asn` has a prefix that
    *contains* it with ``max_length >= announced_length``. A /20 ROA (max_length
    /24) therefore covers all the announced /24s under it, which exact-CIDR
    matching misses (and badly undercounts coverage for real networks).
    """
    # Index distinct ROAs authorising this ASN: {(version, net_int, plen): max_maxlen}.
    idx: dict[tuple[int, int, int], int] = {}
    min_len = {4: 33, 6: 129}
    for r in roa_records:
        if r.get("origin_asn") != asn:
            continue
        cidr = r.get("cidr")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        ml = r.get("max_length")
        maxlen = ml if isinstance(ml, int) else net.max_prefixlen
        key = (net.version, int(net.network_address), net.prefixlen)
        if key not in idx or maxlen > idx[key]:
            idx[key] = maxlen
        if net.prefixlen < min_len[net.version]:
            min_len[net.version] = net.prefixlen

    covered: list[str] = []
    uncovered: list[str] = []
    for a in announced:
        try:
            an = ipaddress.ip_network(a, strict=False)
        except ValueError:
            uncovered.append(a)
            continue
        v = an.version
        ok = False
        for plen in range(an.prefixlen, min_len[v] - 1, -1):
            sup = an.supernet(new_prefix=plen)
            maxlen = idx.get((v, int(sup.network_address), plen))
            if maxlen is not None and an.prefixlen <= maxlen:
                ok = True
                break
        (covered if ok else uncovered).append(a)
    return covered, uncovered


def unrouted_estimate(parent_cidr: str, subprefixes: list[dict]) -> int:
    """Rough count of addresses in the block never seen as an announced
    more-specific. Approximate: parent size minus the summed sizes of announced
    more-specifics (ignores overlap, so it is a lower bound on unrouted space)."""
    parent = prefix_addresses(parent_cidr)
    covered = 0
    for s in subprefixes:
        cidr = s.get("cidr")
        if cidr:
            covered += prefix_addresses(cidr)
    return max(0, parent - covered)
