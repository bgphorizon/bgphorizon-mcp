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
