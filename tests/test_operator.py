"""Operator-tool tests: validate_announcement's RPKI verdict and the health_check
unrouted check, against a fake API client."""

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from bgphorizon_mcp.tools.operator import register_operator_tools


class FakeClient:
    def __init__(self, rpki=None, rdap=None, hierarchy=None, subprefixes=None, presence=None,
                 detections=None, gated=False, trend_days=None):
        self._detections = detections or []
        self._gated = gated
        self._trend_days = trend_days
        self._rpki = rpki or []
        self._rdap = rdap or {}
        self._hierarchy = hierarchy or {}
        self._subprefixes = subprefixes or {}
        self._presence = presence or []

    def rpki_prefix(self, prefix, **p):
        return {"records": self._rpki}

    def irr_prefix(self, prefix, **p):
        return {"records": []}

    def prefix_overview(self, prefix, **p):
        return {"origins": [], "paths": [], "unique_peers": 100}

    def rdap_prefix(self, prefix, live=True):
        return self._rdap.get(prefix, {"has_rdap": False})

    def prefix_hierarchy(self, prefix):
        return self._hierarchy.get(prefix, {"prefixes": []})

    def prefix_subprefixes(self, prefix, **p):
        return self._subprefixes.get(prefix, {"subprefixes": [], "total": 0})

    def presence(self, **p):
        return {"prefixes": [{"cidr": c} for c in self._presence]}

    def rpki_asn(self, asn, **p):
        return {"records": []}

    def irr_asn(self, asn, **p):
        return {"routes_v4": [], "routes_v6": []}

    def detections_asn(self, asn, **p):
        if self._gated:
            return {"incidents": None, "pagination": {"offset": 0, "limit": 0, "total": 0}}
        off, lim = p.get("offset", 0), p.get("limit", 500)
        return {"incidents": self._detections[off:off + lim],
                "pagination": {"offset": off, "limit": lim, "total": len(self._detections)}}

    def detections_trends(self, **p):
        import datetime as dt
        days = self._trend_days
        if days is None:  # detector ran every day
            today = dt.date.today()
            days = [(today - dt.timedelta(days=i)).isoformat() for i in range(120)]
        return {"points": [{"date": d, "series": "all", "count": 1000} for d in days]}


def call(client, name, args):
    mcp = FastMCP(name="test")
    register_operator_tools(mcp, client)
    result = asyncio.run(mcp.call_tool(name, args))
    payload = result[1] if isinstance(result, tuple) else result
    if isinstance(payload, dict) and "result" in payload:
        payload = payload["result"]
    if isinstance(payload, list) and payload and hasattr(payload[0], "text"):
        payload = json.loads(payload[0].text)
    return payload


def test_validate_announcement_as0_covering_roa_is_invalid():
    # 103.21.244.0/24 under an AS0 /23 (max /23): invalid, and the reason says why.
    client = FakeClient(rpki=[{"cidr": "103.21.244.0/23", "origin_asn": 0, "max_length": 23}])
    out = call(client, "validate_announcement",
               {"prefix": "103.21.244.0/24", "origin_asn": 13335, "check_holder": False})
    assert out["rpki"]["status"] == "invalid"
    assert "AS0" in out["rpki"]["reason"]
    assert out["verdict"] == "blocked"


def test_health_check_unrouted_ignores_announced_blocks():
    # The /20 is announced and RDAP registers exactly the /20: nothing is unrouted.
    client = FakeClient(
        presence=["104.27.16.0/20"],
        rdap={"104.27.16.0/20": {"has_rdap": True, "prefix": "104.27.16.0", "prefix_len": 20,
                                  "network_cidrs": ["104.27.16.0/20"]}},
    )
    out = call(client, "health_check", {"asn": 13335, "checks": ["unrouted"]})
    assert not [f for f in out["findings"] if f["check"] == "unrouted"]


def test_health_check_unrouted_reports_gaps_in_allocation():
    # Allocation /22, only one /23 announced anywhere: the other /23 is the gap.
    client = FakeClient(
        presence=["10.0.0.0/23"],
        # prefix/prefix_len echo the query, as the real endpoint does; network_cidrs is the block.
        rdap={"10.0.0.0/23": {"has_rdap": True, "prefix": "10.0.0.0", "prefix_len": 23,
                              "network_cidrs": ["10.0.0.0/22"]}},
        subprefixes={"10.0.0.0/22": {"subprefixes": [{"cidr": "10.0.0.0/23"}], "total": 1}},
    )
    out = call(client, "health_check", {"asn": 64500, "checks": ["unrouted"]})
    (f,) = [f for f in out["findings"] if f["check"] == "unrouted"]
    assert f["affected"] == ["10.0.0.0/22"]
    assert f["gaps"][0]["gaps"] == ["10.0.2.0/23"]


def _moas(prefix, actor, others, anomalous, state="resolved", baseline=(13335,)):
    return {
        "detection_type": "moas_conflict", "prefix": prefix, "prefix_len": 24,
        "actor_as": actor, "baseline_asns": list(baseline), "is_anomalous": anomalous,
        "state": state, "first_seen": "2026-09-22T21:37:30Z", "last_seen": "2026-09-22T21:37:30Z",
        "details": json.dumps({"other_origins": [{"asn": o} for o in others]}),
    }


def test_health_check_moas_from_detections_keeps_steady_and_flags_anomalous():
    client = FakeClient(detections=[
        _moas("103.21.244.0", 199524, [13335], anomalous=True),
        _moas("103.21.244.0", 13335, [199524], anomalous=False),
        _moas("198.51.100.0", 13335, [64500], anomalous=False, baseline=(13335, 64500)),
    ])
    out = call(client, "health_check", {"asn": 13335, "checks": ["moas"]})
    (f,) = [f for f in out["findings"] if f["check"] == "moas"]
    assert f["severity"] == "high" and f["count"] == 2
    by = {m["prefix"]: m for m in f["prefixes"]}
    assert by["103.21.244.0/24"]["classification"] == "anomalous"
    assert by["103.21.244.0/24"]["other_origins"] == [199524]
    # Steady rows need no action: summarized in summary mode (the default), never
    # dropped, and listed with detail='full'.
    assert "198.51.100.0/24" not in by
    assert f["breakdown"]["classification"]["steady"] == 1
    assert [m["prefix"] for m in f["other_examples"]] == ["198.51.100.0/24"]
    full = call(client, "health_check", {"asn": 13335, "checks": ["moas"], "detail": "full"})
    (ff,) = [x for x in full["findings"] if x["check"] == "moas"]
    assert {m["prefix"]: m for m in ff["prefixes"]}["198.51.100.0/24"]["classification"] == "steady"


def test_health_check_moas_warns_on_detector_gap():
    client = FakeClient(trend_days=[])  # no detections recorded on any day
    out = call(client, "health_check", {"asn": 13335, "checks": ["moas"]})
    assert any(w["code"] == "detector_gap" for w in out["warnings"])


def test_health_check_moas_omitted_when_type_unavailable():
    out = call(FakeClient(gated=True), "health_check", {"asn": 13335, "checks": ["moas"]})
    assert not [f for f in out["findings"] if f["check"] == "moas"]


class AuditClient(FakeClient):
    """AS13335-shaped data from the 2026-09-29 audit, as the real endpoints return it."""

    PRESENCE = [
        ("103.21.244.0/24", "persistent", 31), ("104.16.0.0/12", "transient", 1),
        ("103.186.74.0/24", "persistent", 31), ("104.28.10.0/24", "persistent", 31),
        ("5.183.206.0/24", "persistent", 31), ("185.54.80.0/24", "persistent", 31),
    ]
    CF = {"Name": "CLOUDFLARENET", "EntitiesJSON": json.dumps(
        [{"handle": "CLOUD14", "roles": ["registrant"], "name": "Cloudflare, Inc."}])}
    BULK = {
        "103.21.244.0/24": {"rpki": {"records": [{"cidr": "103.21.244.0/23", "origin_asn": 0, "max_length": 23}]},
                            "rdap": {"Name": "CLOUDFLARE_103_21_244_0", "EntitiesJSON": json.dumps(
                                [{"handle": "IRT-CLOUDFLAREHK-AP", "roles": ["abuse"]}])}},
        "104.16.0.0/12": {"rpki": {"records": []}, "rdap": CF},
        "103.186.74.0/24": {"rpki": {"records": []}, "rdap": {"Name": "DBSVO-AS-AP", "EntitiesJSON": json.dumps(
            [{"handle": "ORG-DVSP1-AP", "roles": ["registrant"], "name": "DBS Vickers Securities (Singapore) PTE LTD"}])}},
        "104.28.10.0/24": {"irr": {"records": []}, "rdap": CF},
        "5.183.206.0/24": {"irr": {"records": [{"origin_as": 20473}]}, "rdap": {"Name": "Damiete-King-Harry"}},
        "185.54.80.0/22": {"rdap": {"Name": "CH-GOLINE-20140417", "EntitiesJSON": json.dumps(
            [{"handle": "ORG-GS131-RIPE", "roles": ["registrant"], "name": "GOLINE SA"}])}},
    }

    def presence(self, **p):
        return {"prefixes": [{"cidr": c, "classification": k, "days_present": d} for c, k, d in self.PRESENCE]}

    def rpki_asn(self, asn, **p):
        return {"records": [
            {"cidr": "104.28.0.0/16", "prefix_len": 16, "max_length": 24, "origin_asn": 13335},
            {"cidr": "5.183.206.0/24", "prefix_len": 24, "max_length": 32, "origin_asn": 13335},
            {"cidr": "185.54.80.0/22", "prefix_len": 22, "max_length": 32, "origin_asn": 13335},
        ]}

    def irr_asn(self, asn, **p):
        return {"routes_v4": [{"cidr": c} for c in
                              ("103.21.244.0/22", "104.16.0.0/13", "103.186.74.0/24", "185.54.80.0/24")]}

    def registry_bulk(self, body):
        return {"prefixes": {c: self.BULK[c] for c in body["prefixes"] if c in self.BULK}}

    def rdap_asn(self, asn):
        return {"name": "CLOUDFLARENET", "entities": [{"handle": "CLOUD14", "roles": ["registrant"], "name": "Cloudflare, Inc."}]}


def test_health_check_annotates_instead_of_dropping():
    out = call(AuditClient(), "health_check", {"asn": 13335, "checks": ["rpki", "irr", "maxlength"]})
    f = {x["check"]: x for x in out["findings"]}

    # AS0-covered /24 is its own high-severity invalid finding, not "no ROA".
    (inv,) = f["rpki_invalid"]["prefixes"]
    assert inv["prefix"] == "103.21.244.0/24" and inv["reason"] == "as0"
    assert inv["holder_is_asn"] is True and inv["basis"] == "name"

    # The one-day /12 and the customer /24 stay listed, each labelled.
    nf = {r["prefix"]: r for r in f["rpki"]["prefixes"]}
    assert nf["104.16.0.0/12"]["persistence"] == "transient" and nf["104.16.0.0/12"]["holder_is_asn"] is True
    # Summary mode: someone else's space moves to other_examples (only they can act), still counted.
    others = {r["prefix"]: r for r in f["rpki"]["other_examples"]}
    assert others["103.186.74.0/24"]["holder_is_asn"] is False
    assert f["rpki"]["breakdown"]["other_holders"] == {"DBS Vickers Securities (Singapore) PTE LTD": 1}
    full = call(AuditClient(), "health_check", {"asn": 13335, "checks": ["rpki"], "detail": "full"})
    listed = [p for x in full["findings"] for p in x["affected"]]
    assert "103.186.74.0/24" in listed
    assert "only part of the window" in f["rpki"]["remediation"]
    assert "DBS Vickers" in f["rpki"]["remediation"]

    # IRR: exact object missing vs covered by a /22 vs other origin only.
    irr = {r["prefix"]: r for r in f["irr"]["prefixes"] + f["irr"].get("other_examples", [])}
    assert irr["103.21.244.0/24"]["state"] == "covered_by_less_specific"
    assert irr["103.21.244.0/24"]["covering_object"] == "103.21.244.0/22"
    assert irr["104.28.10.0/24"]["state"] == "missing"
    assert irr["5.183.206.0/24"]["state"] == "other_origin_only" and irr["5.183.206.0/24"]["object_origins"] == [20473]

    # Max-length: GoLine's ROA, with the concrete target length.
    ml = {r["prefix"]: r for r in f["maxlength"]["prefixes"]}
    assert ml["185.54.80.0/22"]["holder_is_asn"] is False
    assert ml["185.54.80.0/22"]["suggested_max_length"] == 24


class SiblingClient(FakeClient):
    def registry_bulk(self, body):
        return {"asns": {
            "14789": {"rdap": {"Name": "CLOUDFLARENET-SFO", "EntitiesJSON": json.dumps(
                [{"handle": "CLOUD14", "roles": ["registrant"], "name": "Cloudflare, Inc."}])}},
            "199524": {"rdap": {"Name": "GCORE", "EntitiesJSON": json.dumps(
                [{"handle": "ORG-GL1-RIPE", "roles": ["registrant"], "name": "G-Core Labs S.A."}])}},
        }}

    def rdap_asn(self, asn):
        return {"entities": [{"handle": "CLOUD14", "roles": ["registrant"], "name": "Cloudflare, Inc."}]}


def test_health_check_moas_marks_same_organization_siblings():
    client = SiblingClient(detections=[
        _moas("2400:cb00:681::", 14789, [13335], anomalous=True),
        _moas("103.21.244.0", 199524, [13335], anomalous=True),
    ])
    out = call(client, "health_check", {"asn": 13335, "checks": ["moas"]})
    (f,) = [f for f in out["findings"] if f["check"] == "moas"]
    by = {m["prefix"].split("/")[0]: m for m in f["prefixes"]}
    assert by["2400:cb00:681::"]["classification"] == "same_organization"
    assert by["2400:cb00:681::"]["anomalous_origins"] == [14789]  # detector's flag kept
    assert by["103.21.244.0"]["classification"] == "anomalous"
    assert by["103.21.244.0"]["other_origin_names"] == {"199524": "G-Core Labs S.A."}
    assert f["severity"] == "high"


def test_concurrent_reads_keep_the_callers_context():
    # The hosted server reads each caller's API key from a contextvar; the parallel
    # reads in health_check must see it, or they would run as the wrong user.
    import contextvars
    from bgphorizon_mcp.tools import operator
    key = contextvars.ContextVar("key", default=None)
    key.set("caller-A")
    out = operator._concurrently({str(i): key.get for i in range(12)} | {"boom": lambda: 1 / 0})
    assert all(out[str(i)] == "caller-A" for i in range(12))
    assert isinstance(out["boom"], ZeroDivisionError)


def test_health_check_moas_related_tier_and_real_baseline():
    inc = _moas("198.51.100.0", 174, [209242], anomalous=True, baseline=(209242, 174))
    inc["details"] = json.dumps({"baseline_origins": [209242], "other_origins": [{"asn": 209242}],
                                 "related_to": {"asn": 209242, "relation": "provider"}})
    out = call(FakeClient(detections=[inc]), "health_check", {"asn": 209242, "checks": ["moas"]})
    (f,) = [f for f in out["findings"] if f["check"] == "moas"]
    (row,) = f["prefixes"]
    assert row["classification"] == "related" and f["severity"] == "medium"
    # The baseline is details.baseline_origins, not the incident's baseline_asns (which adds counterparties).
    assert row["baseline_origins"] == [209242]
    assert row["relations"] == {"174": {"asn": 209242, "relation": "provider"}}


class DownClient(AuditClient):
    """The API could not read RPKI or IRR for these prefixes."""
    def registry_bulk(self, body):
        return {"prefixes": {c: {"error": "unavailable: rpki, irr (query failed or timed out; retry)"}
                             for c in body.get("prefixes", [])}}


def test_health_check_unavailable_sections_are_not_checked_not_notfound():
    out = call(DownClient(), "health_check", {"asn": 13335, "checks": ["rpki", "irr"], "detail": "full"})
    f = {x["check"]: x for x in out["findings"]}
    assert "rpki_invalid" not in f
    assert {r["state"] for r in f["rpki"]["prefixes"]} == {"not_checked"}
    irr = {r["prefix"]: r["state"] for r in f["irr"]["prefixes"]}
    assert irr["104.28.10.0/24"] == "not_checked"  # would have read "missing"


def test_verify_transit_rows_drops_hidden_second_neighbor_quietly():
    from bgphorizon_mcp import common
    from bgphorizon_mcp.tools.operator import _verify_transit_rows

    class C:
        def prefix_upstreams(self, prefix, **p):
            common.record_api_warnings(["direct_session_only: about this prefix only"])
            if prefix == "10.0.0.0/24":
                return {"upstreams": [{"asn": 6939, "share": 0.73}, {"asn": 1299, "share": 0.06}]}
            return {"upstreams": [{"asn": 3356, "share": 1.0}]}

    t = {"rows": [
        {"prefix": "10.0.0.0/24", "kind": "single_homed"},
        {"prefix": "10.0.1.0/24", "kind": "single_homed"},
        {"prefix": "10.0.2.0/24", "kind": "selective", "relationship": "provider"},
    ]}
    bucket: list = []
    token = common._api_warnings.set(bucket)
    try:
        _verify_transit_rows(C(), 64500, t, "2026-09-01", "2026-09-29")
    finally:
        common._api_warnings.reset(token)
    assert [r["prefix"] for r in t["rows"]] == ["10.0.1.0/24", "10.0.2.0/24"]
    assert t["verified_multi"] == 1 and t["rows"][0]["verified_by_sessions"] is True
    assert "verified_by_sessions" not in t["rows"][1]  # selective rows are not re-checked
    assert bucket == []


def test_verify_transit_prepended_rows_resolve_both_ways():
    from bgphorizon_mcp.tools.operator import _verify_transit_rows

    class C:
        def prefix_upstreams(self, prefix, **p):
            if prefix == "10.0.0.0/24":  # prepends go through a backup: two neighbors
                return {"upstreams": [{"asn": 3356, "share": 0.75}, {"asn": 6461, "share": 0.25}]}
            return {"upstreams": [{"asn": 3356, "share": 1.0}]}  # prepends toward the same provider

    t = {"network": {3356}, "network_neighbors": 1, "rows": [
        {"prefix": "10.0.0.0/24", "kind": "single_homed", "neighbors_uncertain": True},
        {"prefix": "10.0.1.0/24", "kind": "single_homed", "neighbors_uncertain": True},
    ]}
    _verify_transit_rows(C(), 64500, t, "2026-09-01", "2026-09-29")
    assert [r["prefix"] for r in t["rows"]] == ["10.0.1.0/24"]
    assert t["rows"][0]["verified_by_sessions"] is True and "neighbors_uncertain" not in t["rows"][0]
    # The backup found on the first prefix proves the network has two neighbors.
    assert t["network_neighbors"] == 2 and t["rows"][0]["kind"] == "selective"
    assert t["unverified_uncertain"] == 0


def test_verify_transit_prepended_only_toward_one_provider_stays_single_homed():
    from bgphorizon_mcp.tools.operator import _verify_transit_rows

    class C:
        def prefix_upstreams(self, prefix, **p):
            return {"upstreams": [{"asn": 3356, "share": 1.0}]}

    t = {"network": {3356}, "network_neighbors": 1, "rows": [
        {"prefix": "10.0.1.0/24", "kind": "single_homed", "neighbors_uncertain": True}]}
    _verify_transit_rows(C(), 64500, t, "2026-09-01", "2026-09-29")
    assert t["rows"][0]["kind"] == "single_homed" and t["network_neighbors"] == 1


class RecordingAuditClient(AuditClient):
    def __init__(self):
        super().__init__()
        self.bulk_bodies = []

    def registry_bulk(self, body):
        self.bulk_bodies.append(body)
        return super().registry_bulk(body)


def test_health_check_enrichment_uses_cached_rdap_only():
    # Live registry lookups count against the account's daily allowance; one
    # health check's background enrichment must not use it up.
    c = RecordingAuditClient()
    call(c, "health_check", {"asn": 13335, "checks": ["rpki", "irr"]})
    assert c.bulk_bodies and all(b.get("rdap_live") is False for b in c.bulk_bodies)
