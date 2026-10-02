"""Pure reshaping helpers shared across tools.

These turn raw ``/api/v1`` payloads into the task-shaped structures the tool
contracts promise (docs/TOOLS.md). Kept pure and importable so the logic that
docs say a model tends to get wrong (persistence transitions, detection direction,
upstream/prepend collapsing) is testable in isolation.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
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


def irr_is_current(record: dict, max_age_days: int = 3) -> bool:
    """IRR history keeps one row per day while an object exists, so a record's `timestamp`
    is the last day it was present. Older than a few days means the object was deleted;
    an unwindowed lookup still returns it (102.0.0.0/8's AS37358 object, gone since
    2023-07-19, was once cited as a live mismatch)."""
    ts = record.get("timestamp") or record.get("last_seen")
    if not ts:
        return True
    try:
        t = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return True
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return (_dt.datetime.now(_dt.timezone.utc) - t).days <= max_age_days


def irr_objects(irr: dict | None, observed_origins: set[int]) -> list[dict]:
    """Flatten IRR records to {origin_as, source, last_seen, current, stale}. ``current`` is
    false for objects no longer in the registry; ``stale`` marks an IRR origin never observed
    announcing the space."""
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
        obj = {"origin_as": origin, "source": source, "last_seen": r.get("timestamp"), "current": irr_is_current(r)}
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
    if actor == asn and asn in baseline:
        # Announcer and holder are the same network: its own routing change (a new
        # more-specific of its own block, a route longer than its own ROA allows),
        # not someone else taking its space.
        return "queried_entity_announced_own_space"
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
    """Sum observed counts by immediate upstream AS → share of total.

    A path that is only the origin (upstream_as 0) has no upstream: it is the
    origin's own session with a route collector. It counts toward the total, so
    the shares stay honest, but is not listed as an upstream (see direct_share)."""
    totals: dict[int, int] = {}
    grand = 0
    for p in paths:
        up = p.get("upstream_as")
        c = p.get("count", 0) or 0
        if up is None:
            continue
        grand += c
        if up == 0:
            continue
        totals[up] = totals.get(up, 0) + c
    out = [
        {"asn": up, "share": round(c / grand, 4) if grand else 0.0}
        for up, c in sorted(totals.items(), key=lambda kv: -kv[1])
    ]
    return out


def direct_share(paths: list[dict]) -> float:
    """Share of path observations that are the origin alone (its own collector
    session, no upstream)."""
    grand = direct = 0
    for p in paths:
        if p.get("upstream_as") is None:
            continue
        c = p.get("count", 0) or 0
        grand += c
        if p.get("upstream_as") == 0:
            direct += c
    return round(direct / grand, 4) if grand else 0.0


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
    validation, not exact-CIDR matching.

    An announced prefix is covered when some ROA for `asn` has a prefix that
    *contains* it with ``max_length >= announced_length``. A /20 ROA (max_length
    /24) therefore covers all the announced /24s under it, which exact-CIDR
    matching misses (and badly undercounts coverage for real networks).
    """
    # Index distinct ROAs authorizing this ASN: {(version, net_int, plen): max_maxlen}.
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


def unrouted_gaps(block_cidr: str, announced: list[str]) -> list[str]:
    """CIDRs inside `block_cidr` that no announced prefix covers. `announced` may hold
    more-specifics, the block itself or a less-specific; anything containing the
    block means nothing in it is unrouted. Overlapping announcements are handled as
    a real set difference, not by summing sizes."""
    try:
        block = ipaddress.ip_network(block_cidr, strict=False)
    except ValueError:
        return []
    remaining = [block]
    for cidr in announced:
        try:
            a = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if a.version != block.version or not a.overlaps(block):
            continue
        if block.subnet_of(a):
            return []
        nxt = []
        for r in remaining:
            if r.subnet_of(a):
                continue
            if a.subnet_of(r):
                nxt.extend(r.address_exclude(a))
            else:
                nxt.append(r)
        remaining = nxt
        if not remaining:
            break
    return [str(n) for n in ipaddress.collapse_addresses(remaining)]


class CidrIndex:
    """Set of CIDRs answering "which stored prefix contains this one" in one dict
    lookup per prefix length (33 or 129), instead of comparing against every entry.
    health_check did the latter for hundreds of prefixes against thousands of IRR
    objects: ~9.5M ip_network parses and ~36 s for AS13335."""

    def __init__(self, cidrs: list[str] | None = None) -> None:
        self._by: dict[tuple[int, int, int], str] = {}
        self._lens: dict[int, set[int]] = {4: set(), 6: set()}
        for c in cidrs or []:
            self.add(c)

    def add(self, cidr: str) -> None:
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        self._by[(n.version, n.prefixlen, int(n.network_address))] = str(n)
        self._lens[n.version].add(n.prefixlen)

    def containing(self, cidr: str, strict: bool = False) -> str | None:
        """Most specific stored CIDR containing `cidr` (itself too, unless strict)."""
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None
        addr, bits = int(n.network_address), n.max_prefixlen
        for plen in sorted(self._lens[n.version], reverse=True):
            if plen > n.prefixlen or (strict and plen == n.prefixlen):
                continue
            key = (n.version, plen, addr >> (bits - plen) << (bits - plen))
            if key in self._by:
                return self._by[key]
        return None


def nets_inside(block: str, nets: list) -> list:
    """Pre-parsed networks from `nets` that sit inside `block`."""
    try:
        b = ipaddress.ip_network(block, strict=False)
    except ValueError:
        return []
    return [n for n in nets if n.version == b.version and n.subnet_of(b)]


def parse_nets(cidrs: list[str]) -> list:
    out = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return out


def covering_announced(block_cidr: str, hierarchy: dict | None) -> list[str]:
    """From a /prefix/hierarchy response (routed prefixes containing the block's first
    address), the ones equal to or less specific than the block, i.e. announcements
    that already route every address in it."""
    try:
        block = ipaddress.ip_network(block_cidr, strict=False)
    except ValueError:
        return []
    out = []
    for p in (hierarchy or {}).get("prefixes") or []:
        try:
            n = ipaddress.ip_network(p.get("cidr") or "", strict=False)
        except ValueError:
            continue
        if n.version == block.version and block.subnet_of(n):
            out.append(str(n))
    return out


def unrouted_estimate(parent_cidr: str, subprefixes: list[dict], covering: list[str] | None = None) -> int:
    """Addresses in the block that no announcement covers: the block minus the union of
    announced more-specifics, or 0 when the block itself or a less-specific is announced
    (pass those in `covering`)."""
    announced = [s.get("cidr") for s in subprefixes if s.get("cidr")] + list(covering or [])
    return sum(prefix_addresses(g) for g in unrouted_gaps(parent_cidr, announced))


_RIR_HOSTS = {
    "arin": "ARIN",
    "ripe": "RIPE NCC",
    "apnic": "APNIC",
    "lacnic": "LACNIC",
    "afrinic": "AFRINIC",
}


def rir_from_rdap(rdap: dict | None) -> str | None:
    """Which RIR answered the RDAP query, from the server that served it."""
    if not rdap:
        return None
    server = (rdap.get("rdap_server") or rdap.get("RDAPServer") or "").lower()
    for key, name in _RIR_HOSTS.items():
        if key in server:
            return name
    return None


def parse_details(incident: dict) -> None:
    """Detections carry `details` as a JSON string; expose it as an object in place."""
    raw = incident.get("details")
    if isinstance(raw, str) and raw.startswith("{"):
        try:
            incident["details"] = json.loads(raw)
        except ValueError:
            pass


def detections_summary(incidents: list[dict]) -> dict:
    """Aggregates a report needs from a complete incident list: counts by type x direction,
    by opening hour, distinct prefixes and counterpart ASNs, and the peer-count spread."""
    by_type_dir: dict[str, dict[str, int]] = {}
    by_hour: dict[str, int] = {}
    prefixes: set[str] = set()
    counterparts: set[int] = set()
    peers: list[int] = []
    for inc in incidents:
        t = inc.get("detection_type") or "unknown"
        d = inc.get("direction") or "unknown"
        by_type_dir.setdefault(t, {})
        by_type_dir[t][d] = by_type_dir[t].get(d, 0) + 1
        fs = (inc.get("first_seen") or "")[:13]
        if fs:
            by_hour[fs] = by_hour.get(fs, 0) + 1
        if inc.get("prefix") is not None:
            prefixes.add(f"{inc.get('prefix')}/{inc.get('prefix_len')}")
        for a in inc.get("baseline_asns") or []:
            counterparts.add(a)
        if isinstance(inc.get("peer_count"), int):
            peers.append(inc["peer_count"])
    peers.sort()

    def pct(p: float) -> int | None:
        return peers[min(len(peers) - 1, int(p * len(peers)))] if peers else None

    return {
        "by_type_and_direction": by_type_dir,
        "opened_by_hour": dict(sorted(by_hour.items())),
        "distinct_prefixes": len(prefixes),
        "distinct_baseline_asns": len(counterparts),
        "peer_count": {"min": peers[0] if peers else None, "median": pct(0.5), "max": peers[-1] if peers else None},
    }


# Columns of `detections` compact rows, in order.
# -- health_check annotations ---------------------------------------------------
# Findings keep every affected prefix; these add the context a reader needs to act on
# each one (was it a one-day blip, and whose space is it) instead of dropping any.

def rdap_entities(rdap: dict | None) -> list[dict]:
    """Entities from either RDAP shape: the /rdap endpoints' `entities` list, or the
    bulk endpoint's cache row, which carries them as an `EntitiesJSON` string."""
    if not isinstance(rdap, dict):
        return []
    ents = rdap.get("entities") or rdap.get("Entities")
    if isinstance(ents, list):
        return ents
    raw = rdap.get("EntitiesJSON")
    if isinstance(raw, str) and raw.startswith("["):
        try:
            return json.loads(raw)
        except ValueError:
            return []
    return []


def _registrants(rdap: dict | None) -> list[dict]:
    return [e for e in rdap_entities(rdap) if "registrant" in [str(r).lower() for r in (e.get("roles") or [])]]


def _name_key(name: str | None) -> str | None:
    """First word of an organization name, lowercased: "Cloudflare, Inc." -> "cloudflare".
    Too-short or generic first words give None rather than a loose match."""
    if not name:
        return None
    word = "".join(ch for ch in name.split()[0].lower() if ch.isalnum())
    return word if len(word) >= 4 and word not in {"the", "internet", "network", "networks", "global"} else None


def asn_holder_identity(asn_rdap: dict | None) -> dict:
    """Registrant handles and a name key for the audited ASN, to compare against
    each prefix's registration."""
    regs = _registrants(asn_rdap)
    name = next((e.get("name") for e in regs if e.get("name")), None) or (asn_rdap or {}).get("name")
    return {"handles": {e.get("handle") for e in regs if e.get("handle")}, "name_key": _name_key(name)}


def prefix_holder(prefix_rdap: dict | None, asn_ident: dict, fallback: dict | None = None,
                  approximate: bool = False) -> dict:
    """Who is registered for a prefix (or ASN) and whether it is the audited network.

    holder_is_asn is True/False when registrant handles can be compared (same RIR),
    else decided by a first-word name comparison, else None. `basis` says which
    applied. With no cached RDAP record, `fallback` (the API's name_fallback: an IRR
    descr or PeeringDB name) supplies the holder and only a name match can confirm
    it; `holder_source` then names that source. `holder_approximate` marks an RDAP
    record that is the containing registration rather than a lookup of this prefix."""
    has_rdap = isinstance(prefix_rdap, dict) and bool(
        prefix_rdap.get("Name") or prefix_rdap.get("name") or rdap_entities(prefix_rdap))
    if not has_rdap:
        if not (fallback or {}).get("name"):
            return {"holder": None, "holder_is_asn": None, "basis": None}
        name = fallback["name"]
        key = asn_ident.get("name_key")
        match = True if key and key in "".join(ch for ch in name.lower() if ch.isalnum()) else None
        return {"holder": name, "holder_is_asn": match, "basis": "name" if match else None,
                "holder_source": fallback.get("source")}
    regs = _registrants(prefix_rdap)
    net_name = prefix_rdap.get("Name") or prefix_rdap.get("name")
    holder = next((e.get("name") for e in regs if e.get("name")), None) or net_name
    handles = {e.get("handle") for e in regs if e.get("handle")}
    out: dict[str, Any] = {"holder": holder, "holder_is_asn": None, "basis": None, "holder_source": "rdap"}
    if approximate:
        out["holder_approximate"] = True
    key = asn_ident.get("name_key")
    name_text = "".join(ch for ch in " ".join(filter(None, [net_name, holder] + [
        e.get("name") for e in rdap_entities(prefix_rdap)])).lower() if ch.isalnum())
    if handles and asn_ident.get("handles") and handles & asn_ident["handles"]:
        out.update(holder_is_asn=True, basis="registrant_handle")
    elif key and key in name_text:
        out.update(holder_is_asn=True, basis="name")
    elif handles and asn_ident.get("handles"):
        out.update(holder_is_asn=False, basis="registrant_handle")
    return out


def rpki_state(records: list[dict], asn: int, plen: int | None) -> dict:
    """RFC 6811 state of an announcement from `asn` given every covering ROA (the
    /rpki/prefix records). reason: as0 (only AS0 ROAs cover it: the holder marked it
    do-not-route), max_length (a ROA names asn but not this length), other_origin."""
    if not records:
        return {"state": "not_found"}
    def ok(r):
        ml = r.get("max_length")
        return r.get("origin_asn") == asn and (ml is None or plen is None or ml >= plen)
    if any(ok(r) for r in records):
        return {"state": "valid"}
    origins = {r.get("origin_asn") for r in records}
    reason = "as0" if origins == {0} else ("max_length" if asn in origins else "other_origin")
    covering = sorted({(r.get("cidr") or r.get("prefix"), r.get("origin_asn"), r.get("max_length")) for r in records},
                      key=lambda x: (str(x[0]), x[1] or 0))
    return {"state": "invalid", "reason": reason,
            "covering_roas": [{"cidr": c, "origin_asn": o, "max_length": m} for c, o, m in covering[:5]]}


def count_by(rows: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = r.get(key)
        k = "unknown" if k is None else (str(k).lower() if isinstance(k, bool) else str(k))
        out[k] = out.get(k, 0) + 1
    return out


def relationship_map(rel: dict | None) -> dict[int, dict]:
    """ASN -> {"relationship": provider|customer|other, "name"} from /asn/relationships
    (M13 inferred provider-to-customer links; other = observed adjacency, e.g. peering)."""
    out: dict[int, dict] = {}
    for key, label in (("upstreams", "provider"), ("downstreams", "customer"), ("other_connections", "other")):
        for n in (rel or {}).get(key) or []:
            if n.get("asn") is not None and n["asn"] not in out:
                out[n["asn"]] = {"relationship": label, "name": n.get("name")}
    return out


def transit_analysis(transit: list[dict], pres_by_cidr: dict[str, dict], rels: dict[int, dict]) -> dict:
    """Single-neighbor prefixes across the whole ASN, each with its lone first-hop
    neighbor, how the neighbor relates to the ASN, and persistence.

    A prefix seen through one neighbor is only a single point of failure if the
    network itself has one. When the network has many neighbors, a prefix that reaches
    the table through just one of them is usually a deliberate regional or
    traffic-engineered announcement, so it is labelled `selective`, not `single_homed`."""
    network = {n["asn"] for p in transit for n in (p.get("neighbors") or []) if n.get("share", 0) >= 0.01}
    rows = []
    for p in transit:
        sig = p.get("significant_neighbor_count")
        if sig is None or sig > 1:
            continue
        cidr = p.get("cidr")
        pres = pres_by_cidr.get(cidr) or {}
        row: dict[str, Any] = {"prefix": cidr, "unique_peers": p.get("unique_peers")}
        if pres:
            row["persistence"] = pres.get("classification")
            row["days_present"] = pres.get("days_present")
        # Prepended paths whose neighbor the rollup did not keep (API prepended_share).
        # They may go through a second provider (a prepended backup) or the same one,
        # so the row is uncertain until collector sessions settle it.
        if (p.get("prepended_share") or 0) >= 0.01:
            row["prepended_share"] = p["prepended_share"]
            row["neighbors_uncertain"] = True
        if sig == 0:
            row["kind"] = "direct_sessions_only"
        else:
            top = (p.get("neighbors") or [{}])[0]
            rel = rels.get(top.get("asn")) or {}
            row.update(neighbor=top.get("asn"), neighbor_name=rel.get("name"),
                       relationship=rel.get("relationship", "unknown"),
                       kind="single_homed" if len(network) <= 1 else "selective")
        rows.append(row)
    return {"rows": rows, "network_neighbors": len(network), "network": network}


def visibility_analysis(transit: list[dict], pres_by_cidr: dict[str, dict],
                        context: dict[str, dict], ratio: float = 0.6) -> dict:
    """Prefixes seen by far fewer collector peers than the ASN's typical prefix of the
    same address family. The baseline is the median over persistent prefixes, so
    one-day announcements do not drag it down. Each weak prefix gets likely
    explanations from what the audit already knows (`context`: RPKI/IRR state per
    prefix), e.g. an RPKI-invalid route is dropped by validating networks."""
    medians: dict[bool, float] = {}
    for v6 in (False, True):
        peers = sorted(p.get("unique_peers") or 0 for p in transit if bool(p.get("is_v6")) == v6
                       and (pres_by_cidr.get(p.get("cidr")) or {}).get("classification") == "persistent")
        if len(peers) >= 5:
            medians[v6] = peers[len(peers) // 2]
    rows = []
    for p in transit:
        med = medians.get(bool(p.get("is_v6")))
        peers = p.get("unique_peers") or 0
        if not med or peers >= ratio * med:
            continue
        cidr = p.get("cidr")
        pres = pres_by_cidr.get(cidr) or {}
        ctx = context.get(cidr) or {}
        reasons = []
        if ctx.get("rpki") == "invalid":
            reasons.append("rpki_invalid")
        if pres.get("classification") in ("transient", "intermittent"):
            reasons.append("short_lived")
        if (p.get("significant_neighbor_count") or 0) <= 1 and (p.get("prepended_share") or 0) < 0.01:
            reasons.append("single_neighbor")
        if ctx.get("irr") in ("missing", "other_origin_only"):
            reasons.append("no_irr_object")
        rows.append({"prefix": cidr, "unique_peers": peers, "family_median": med,
                     "ratio": round(peers / med, 2), "persistence": pres.get("classification"),
                     "likely_reasons": reasons})
    rows.sort(key=lambda r: r["ratio"])
    return {"rows": rows, "medians": {"v4": medians.get(False), "v6": medians.get(True)}}


def moas_by_prefix(incidents: list[dict], asn: int) -> list[dict]:
    """Group moas_conflict incidents touching `asn` into one row per prefix: who else
    originated it, the prefix's 30-day baseline origins, which origins the detector
    flagged as outside that baseline, how each flagged origin relates to the baseline
    (the detector's `related_to`), and whether the conflict is still active.

    `baseline_origins` comes from each incident's details, not the incident's
    `baseline_asns` column: for MOAS that column also lists every counterparty, so an
    origin can appear there and still be outside the baseline.

    classification: `anomalous` (a flagged origin with no known relation, or only an
    observed adjacency, which is how leaks look), `related` (flagged origins are all a
    baseline origin's provider or customer), `same_organization` (all registered to
    the baseline origin's organization), or `steady` (no flagged origin). Nothing is
    dropped."""
    rank = {"anomalous": 4, "related": 3, "same_organization": 2, "steady": 1}
    rows: dict[str, dict] = {}
    for inc in incidents:
        prefix = inc.get("prefix")
        if prefix and "/" not in str(prefix) and inc.get("prefix_len") is not None:
            prefix = f"{prefix}/{inc['prefix_len']}"
        if not prefix:
            continue
        details = inc.get("details") if isinstance(inc.get("details"), dict) else {}
        origins = {inc.get("actor_as")} | {
            o.get("asn") for o in (details.get("other_origins") or []) if isinstance(o, dict)
        }
        origins.discard(None)
        r = rows.setdefault(prefix, {
            "prefix": prefix, "other_origins": set(), "anomalous_origins": set(), "relations": {},
            "baseline_origins": set(), "active": False, "incidents": 0, "classification": "steady",
            "first_seen": inc.get("first_seen"), "last_seen": inc.get("last_seen"),
        })
        r["other_origins"] |= origins - {asn}
        r["baseline_origins"] |= set(details.get("baseline_origins") or [])
        actor = inc.get("actor_as")
        if inc.get("is_anomalous") and actor is not None:
            r["anomalous_origins"].add(actor)
            rel = (details.get("related_to") or {}).get("relation")
            if rel:
                r["relations"][str(actor)] = {"asn": (details.get("related_to") or {}).get("asn"), "relation": rel}
            cls = {"same_organization": "same_organization", "provider": "related",
                   "customer": "related"}.get(rel, "anomalous")
            if rank[cls] > rank[r["classification"]]:
                r["classification"] = cls
        r["active"] = r["active"] or inc.get("state") == "active"
        r["incidents"] += 1
        fs, ls = inc.get("first_seen"), inc.get("last_seen")
        if fs and (not r["first_seen"] or fs < r["first_seen"]):
            r["first_seen"] = fs
        if ls and (not r["last_seen"] or ls > r["last_seen"]):
            r["last_seen"] = ls
    out = []
    for r in rows.values():
        out.append({
            "prefix": r["prefix"],
            "other_origins": sorted(r["other_origins"]),
            "baseline_origins": sorted(r["baseline_origins"]),
            "anomalous_origins": sorted(r["anomalous_origins"]),
            "relations": r["relations"],
            "classification": r["classification"],
            "active": r["active"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "incidents": r["incidents"],
        })
    out.sort(key=lambda x: (-rank[x["classification"]], not x["active"], str(x["last_seen"] or "")))
    return out


def detector_gap_days(trend_points: list[dict], start: str, end: str) -> list[str]:
    """Days in [start, end] with no anomalous detection anywhere on the platform. The
    platform records thousands a day, so a zero day means the detector was not running
    and a 'none' result for that day proves nothing."""
    seen = {p.get("date") for p in trend_points if (p.get("count") or 0) > 0}
    d0, d1 = _dt.date.fromisoformat(start[:10]), _dt.date.fromisoformat(end[:10])
    gaps = []
    d = d0
    while d <= d1:
        if d.isoformat() not in seen:
            gaps.append(d.isoformat())
        d += _dt.timedelta(days=1)
    return gaps


COMPACT_INCIDENT_COLUMNS = [
    "detection_type", "prefix", "actor_as", "baseline_asns", "direction",
    "severity", "state", "first_seen", "last_seen", "peer_count",
]


def compact_incidents(incidents: list[dict]) -> dict:
    """One row per incident under a shared column list, without details. The repeated
    key names are most of a long incident list's size."""
    rows = []
    for inc in incidents:
        prefix = inc.get("prefix")
        if prefix and "/" not in str(prefix) and inc.get("prefix_len") is not None:
            prefix = f"{prefix}/{inc['prefix_len']}"
        row = {**inc, "prefix": prefix}
        rows.append([row.get(c) for c in COMPACT_INCIDENT_COLUMNS])
    return {"columns": list(COMPACT_INCIDENT_COLUMNS), "rows": rows}


def registry_summary(entries: list[dict]) -> dict:
    """Counts over bulk_registry prefix entries: ROA and IRR coverage, and prefixes by RIR
    and by registry country (the 15 most common)."""
    by_rir: dict[str, int] = {}
    by_country: dict[str, int] = {}
    with_roas = with_irr = irr_match = 0
    for e in entries:
        if e.get("roas"):
            with_roas += 1
        if e.get("irr_origins"):
            with_irr += 1
        if e.get("irr_matches_origin"):
            irr_match += 1
        rd = e.get("rdap") or {}
        rir = rd.get("rir") or "unknown"
        by_rir[rir] = by_rir.get(rir, 0) + 1
        country = (rd.get("country") or "unknown").upper() if rd.get("country") else "unknown"
        by_country[country] = by_country.get(country, 0) + 1
    top = sorted(by_country.items(), key=lambda kv: (-kv[1], kv[0]))[:15]
    return {
        "prefixes": len(entries),
        "with_roas": with_roas,
        "with_irr_objects": with_irr,
        "irr_matches_origin": irr_match,
        "by_rir": dict(sorted(by_rir.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_country": dict(top),
    }
