"""Unit tests for the deterministic reshaping logic — the pieces the MCP design
says a model tends to get wrong: persistence transitions, detection direction,
and upstream/prepend collapsing."""

from bgphorizon_mcp.tools import _shape
from bgphorizon_mcp import common


def _days(seq):
    """seq: list of (date, [origins])"""
    return _shape.days_from_origins_by_day({d: o for d, o in seq})


def test_handover_is_detected_and_persists():
    days = _days([
        ("2026-07-08", [33015]),
        ("2026-07-09", [33015, 54994]),  # overlap / MOAS
        ("2026-07-10", [54994]),
        ("2026-07-11", [54994]),
    ])
    trans = _shape.transitions_from_days(days)
    handover = [t for t in trans if t["to_asn"] == 54994]
    assert handover and handover[0]["type"] == "handover"
    assert handover[0]["from_asn"] == 33015


def test_transient_reversion_is_episode_not_handover():
    days = _days([
        ("2026-07-08", [100]),
        ("2026-07-09", [200]),  # brief appearance
        ("2026-07-10", [100]),
        ("2026-07-11", [100]),
    ])
    trans = _shape.transitions_from_days(days)
    to200 = [t for t in trans if t["to_asn"] == 200]
    assert to200 and to200[0]["type"] == "episode"


def test_moas_flag_per_day():
    days = _days([("2026-07-09", [1, 2]), ("2026-07-10", [1])])
    assert days[0]["moas"] is True
    assert days[1]["moas"] is False


def test_detection_direction_offender_vs_victim():
    inc_hijack = {"actor_as": 33015, "baseline_asns": [54994]}
    # querying the offender
    assert _shape.detection_direction(inc_hijack, 33015) == "queried_entity_is_invalid_party"
    # querying the rightful holder
    assert _shape.detection_direction(inc_hijack, 54994) == "queried_entity_is_baseline"
    # querying an unrelated party
    assert _shape.detection_direction(inc_hijack, 999) == "third_party"
    # a network announcing inside its own space is neither victim nor offender
    inc_self = {"actor_as": 197207, "baseline_asns": [197207]}
    assert _shape.detection_direction(inc_self, 197207) == "queried_entity_announced_own_space"
    assert _shape.detection_direction(inc_self, 999) == "third_party"
    # no asn context → no direction
    assert _shape.detection_direction(inc_hijack, None) is None


def test_upstream_aggregation_shares_sum_to_one():
    paths = [
        {"upstream_as": 3356, "count": 60},
        {"upstream_as": 3356, "count": 40},
        {"upstream_as": 174, "count": 100},
    ]
    ups = _shape.aggregate_upstreams(paths)
    shares = {u["asn"]: u["share"] for u in ups}
    assert shares[3356] == 0.5
    assert shares[174] == 0.5
    # sorted by observed count, ties preserved
    assert abs(sum(u["share"] for u in ups) - 1.0) < 1e-9


def test_direct_only_paths_are_not_an_upstream():
    paths = [
        {"upstream_as": 0, "count": 25},
        {"upstream_as": 174, "count": 75},
    ]
    ups = _shape.aggregate_upstreams(paths)
    assert ups == [{"asn": 174, "share": 0.75}]
    assert _shape.direct_share(paths) == 0.25
    assert _shape.aggregate_upstreams([{"upstream_as": 0, "count": 1}]) == []
    assert _shape.direct_share([{"upstream_as": 0, "count": 1}]) == 1.0


def test_prepend_observation_emitted_once_per_origin():
    paths = [
        {"origin_as": 1600, "prepend_count": 3},
        {"origin_as": 1600, "prepend_count": 2},
        {"origin_as": 700, "prepend_count": 0},
    ]
    obs = _shape.prepend_observations(paths)
    assert len(obs) == 1
    assert obs[0]["code"] == "prepending_detected"
    assert "AS1600" in obs[0]["message"]


def test_rpki_coverage_counts_covering_roas_not_just_exact():
    # A /20 ROA (max_length /24) should cover all announced /24s under it.
    roas = [{"cidr": "192.0.0.0/20", "max_length": 24, "origin_asn": 64500}]
    announced = ["192.0.1.0/24", "192.0.2.0/24", "203.0.113.0/24"]
    covered, uncovered = _shape.rpki_coverage(announced, roas, 64500)
    assert set(covered) == {"192.0.1.0/24", "192.0.2.0/24"}
    assert uncovered == ["203.0.113.0/24"]  # outside the ROA


def test_rpki_coverage_respects_maxlength_and_origin():
    roas = [{"cidr": "10.0.0.0/16", "max_length": 20, "origin_asn": 100}]
    # /24 is more specific than max_length /20 -> not covered
    _, uncovered = _shape.rpki_coverage(["10.0.0.0/24"], roas, 100)
    assert uncovered == ["10.0.0.0/24"]
    # right prefix length but wrong origin -> not covered
    _, uncovered2 = _shape.rpki_coverage(["10.0.0.0/20"], roas, 999)
    assert uncovered2 == ["10.0.0.0/20"]
    # exact fit -> covered
    covered, _ = _shape.rpki_coverage(["10.0.0.0/20"], roas, 100)
    assert covered == ["10.0.0.0/20"]


def test_unrouted_estimate_lower_bounds_gap():
    # /24 parent, one /25 announced -> ~128 unrouted
    un = _shape.unrouted_estimate("10.0.0.0/24", [{"cidr": "10.0.0.0/25"}])
    assert un == 128


def test_unrouted_estimate_zero_when_block_itself_announced():
    # An announced /20 with no more-specifics is routed, not unrouted.
    assert _shape.unrouted_estimate("104.27.16.0/20", [], covering=["104.27.16.0/20"]) == 0
    # ...and likewise when a less-specific covers it.
    assert _shape.unrouted_estimate("104.27.16.0/20", [], covering=["104.16.0.0/12"]) == 0


def test_unrouted_gaps_handles_nested_overlap():
    # A /23 plus both of its /24s must not count the space twice (old sum-of-sizes bug).
    subs = ["10.0.0.0/23", "10.0.0.0/24", "10.0.1.0/24"]
    assert _shape.unrouted_gaps("10.0.0.0/22", subs) == ["10.0.2.0/23"]
    assert _shape.unrouted_estimate("10.0.0.0/22", [{"cidr": c} for c in subs]) == 512


def test_concentration_warning_fires_above_half():
    w = common.concentration_warning({"top_collector": "rrc00", "top_collector_share": 0.87})
    assert w and w[0]["code"] == "single_vantage_point"
    assert common.concentration_warning({"top_collector_share": 0.2}) == []


def test_parse_target_and_asn_normalisation():
    assert common.parse_target("asn:13335") == ("asn", "13335")
    assert common.parse_target("prefix:1.1.1.0/24") == ("prefix", "1.1.1.0/24")
    assert common.normalize_asn("AS13335") == 13335
    assert common.normalize_asn(13335) == 13335


def test_irr_objects_flags_stale_origin():
    irr = {"records": [
        {"origin_as": 13335, "source": "ARIN"},
        {"origin_as": 5693, "source": "RADB"},
    ]}
    objs = _shape.irr_objects(irr, observed_origins={13335})
    by_asn = {o["origin_as"]: o for o in objs}
    assert "stale" not in by_asn[13335]
    assert by_asn[5693].get("stale") is True


# -- M21 helpers ---------------------------------------------------------------

def test_string_warnings_become_dicts():
    ws = common.normalize_warnings([
        "window_start_censored: first_seen is censored",
        {"code": "x", "message": "y"},
        "free text with spaces: no code",
    ])
    assert ws[0] == {"code": "window_start_censored", "message": "first_seen is censored"}
    assert ws[1]["code"] == "x"
    assert ws[2]["code"] == "api_warning"


def test_parse_when_dates_and_timestamps():
    assert common.rfc3339(common.parse_when("2026-09-20")) == "2026-09-20T00:00:00Z"
    assert common.rfc3339(common.parse_when("2026-09-20", end_of_day=True)) == "2026-09-20T23:59:59Z"
    assert common.rfc3339(common.parse_when("2026-09-20T10:03:12Z")) == "2026-09-20T10:03:12Z"


def test_rir_from_rdap_server():
    assert _shape.rir_from_rdap({"rdap_server": "https://rdap.db.ripe.net/"}) == "RIPE NCC"
    assert _shape.rir_from_rdap({"RDAPServer": "https://rdap.afrinic.net/rdap/"}) == "AFRINIC"
    assert _shape.rir_from_rdap({}) is None


def test_details_parsed_and_summary_counts():
    incs = [
        {"detection_type": "moas_conflict", "direction": "queried_entity_is_invalid_party",
         "first_seen": "2026-09-20T10:03:12Z", "prefix": "81.28.32.0", "prefix_len": 23,
         "baseline_asns": [25306], "peer_count": 206, "details": '{"origin":197207}'},
        {"detection_type": "moas_conflict", "direction": "queried_entity_is_invalid_party",
         "first_seen": "2026-09-20T09:56:25Z", "prefix": "152.89.12.0", "prefix_len": 24,
         "baseline_asns": [12660], "peer_count": 48, "details": "{}"},
    ]
    for i in incs:
        _shape.parse_details(i)
    assert incs[0]["details"] == {"origin": 197207}
    s = _shape.detections_summary(incs)
    assert s["by_type_and_direction"]["moas_conflict"]["queried_entity_is_invalid_party"] == 2
    assert s["opened_by_hour"] == {"2026-09-20T09": 1, "2026-09-20T10": 1}
    assert s["distinct_prefixes"] == 2 and s["distinct_baseline_asns"] == 2
    assert s["peer_count"]["max"] == 206


def test_deleted_irr_objects_are_not_current():
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    live = {"origin_as": 42990, "source": "RIPE", "timestamp": now.isoformat()}
    gone = {"origin_as": 37358, "source": "RADB", "timestamp": "2023-07-19T00:00:00Z"}
    objs = _shape.irr_objects({"records": [live, gone]}, set())
    assert [o["current"] for o in objs] == [True, False]


def test_prefix_holder_uses_stored_name_when_rdap_not_cached():
    ident = _shape.asn_holder_identity({"entities": [{"handle": "CLOUD14", "roles": ["registrant"], "name": "Cloudflare, Inc."}]})
    h = _shape.prefix_holder(None, ident, {"name": "Cloudflare Hong Kong, LLC 101 Townsend Street", "source": "irr"})
    assert h == {"holder": "Cloudflare Hong Kong, LLC 101 Townsend Street", "holder_is_asn": True,
                 "basis": "name", "holder_source": "irr"}
    # A non-matching stored name is "unknown", never "someone else": an IRR descr cannot prove it.
    h = _shape.prefix_holder(None, ident, {"name": "DBS Vickers", "source": "irr"})
    assert h["holder_is_asn"] is None and h["holder"] == "DBS Vickers"
    # Containing registration only: flagged.
    h = _shape.prefix_holder({"Name": "CLOUDFLARENET", "EntitiesJSON": '[{"handle":"CLOUD14","roles":["registrant"]}]'},
                             ident, approximate=True)
    assert h["holder_is_asn"] is True and h["holder_approximate"] is True


def _tp(cidr, neighbors, peers, v6=False):
    ns = [{"asn": a, "share": s} for a, s in neighbors]
    return {"cidr": cidr, "is_v6": v6, "unique_peers": peers, "neighbors": ns,
            "significant_neighbor_count": sum(1 for _, s in neighbors if s >= 0.01)}


def test_transit_selective_vs_single_homed():
    pres = {c: {"classification": "persistent", "days_present": 30} for c in ("a/24", "b/24", "c/24")}
    rels = _shape.relationship_map({"upstreams": [{"asn": 28573, "name": "Claro"}],
                                    "downstreams": [{"asn": 4775, "name": "Globe"}]})
    many = [_tp("a/24", [(28573, 1.0)], 289), _tp("b/24", [(4775, 1.0)], 384),
            _tp("c/24", [(1299, 0.5), (3257, 0.5)], 315)]
    t = _shape.transit_analysis(many, pres, rels)
    kinds = {r["prefix"]: (r["kind"], r["relationship"]) for r in t["rows"]}
    assert kinds == {"a/24": ("selective", "provider"), "b/24": ("selective", "customer")}
    # A network with one neighbor overall: that is real single-homing.
    one = [_tp("a/24", [(3356, 1.0)], 100), _tp("c/24", [(3356, 0.995), (174, 0.005)], 100)]
    t = _shape.transit_analysis(one, pres, {})
    assert {r["kind"] for r in t["rows"]} == {"single_homed"} and len(t["rows"]) == 2


def test_visibility_uses_family_median_and_explains():
    pres = {f"p{i}": {"classification": "persistent"} for i in range(6)}
    pres["x"] = {"classification": "persistent"}
    transit = [_tp(f"p{i}", [(1, 0.5), (2, 0.5)], 300) for i in range(6)]
    transit += [_tp("x", [(1, 0.5), (2, 0.5)], 90),
                _tp("v6a", [(1, 1.0)], 20, v6=True)]  # too few v6 prefixes for a median: skipped
    v = _shape.visibility_analysis(transit, pres, {"x": {"rpki": "invalid"}})
    assert [r["prefix"] for r in v["rows"]] == ["x"]
    assert v["rows"][0]["likely_reasons"] == ["rpki_invalid"] and v["medians"]["v6"] is None


def test_cidr_index_most_specific_and_strict():
    idx = _shape.CidrIndex(["104.16.0.0/12", "104.28.0.0/19", "104.28.10.0/24", "2606:4700::/32"])
    assert idx.containing("104.28.10.0/24") == "104.28.10.0/24"
    assert idx.containing("104.28.10.0/24", strict=True) == "104.28.0.0/19"
    assert idx.containing("104.23.174.0/24") == "104.16.0.0/12"
    assert idx.containing("8.8.8.0/24") is None
    assert idx.containing("2606:4700:7000::/48") == "2606:4700::/32"


def test_transit_prepended_rows_are_uncertain_not_assumed_backups():
    transit = [
        {"cidr": "144.166.174.0/24", "significant_neighbor_count": 1, "prepended_share": 0.09,
         "neighbors": [{"asn": 3356, "share": 1.0}]},
        {"cidr": "144.166.175.0/24", "significant_neighbor_count": 1,
         "neighbors": [{"asn": 3356, "share": 1.0}]},
    ]
    t = _shape.transit_analysis(transit, {}, {})
    # Prepends could go through the same provider, so nothing is dropped or relabelled
    # until collector sessions are checked.
    assert [r["prefix"] for r in t["rows"]] == ["144.166.174.0/24", "144.166.175.0/24"]
    assert t["rows"][0]["neighbors_uncertain"] is True and "neighbors_uncertain" not in t["rows"][1]
    assert all(r["kind"] == "single_homed" for r in t["rows"])
