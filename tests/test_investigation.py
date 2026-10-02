"""Investigation-tool tests: the size controls on detections, origin_episode and
bulk_registry, which keep large results readable without changing what they say."""

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from bgphorizon_mcp.tools.investigation import register_investigation_tools


class FakeClient:
    def __init__(self, detections=None, episode=None, registry=None):
        self._detections = detections or []
        self._episode = episode or {}
        self._registry = registry or {}
        self.calls = {}

    def detections_asn(self, asn, **p):
        self.calls["detections_asn"] = p
        off, lim = p.get("offset", 0), p.get("limit", 500)
        return {"incidents": self._detections[off:off + lim], "pagination": {"total": len(self._detections)}}

    def asn_episode(self, asn, **p):
        self.calls["asn_episode"] = p
        return self._episode

    def registry_bulk(self, body):
        self.calls.setdefault("registry_bulk", []).append(body)
        return self._registry


def call(client, name, args):
    mcp = FastMCP(name="test")
    register_investigation_tools(mcp, client)
    result = asyncio.run(mcp.call_tool(name, args))
    payload = result[1] if isinstance(result, tuple) else result
    if isinstance(payload, dict) and "result" in payload:
        payload = payload["result"]
    if isinstance(payload, list) and payload and hasattr(payload[0], "text"):
        payload = json.loads(payload[0].text)
    return payload


def _incident(i):
    return {
        "incident_id": f"id-{i}", "detection_type": "origin_mismatch_new",
        "prefix": f"10.{i // 256}.{i % 256}.0", "prefix_len": 24,
        "actor_as": 197207, "baseline_asns": [25306], "severity": "high", "state": "resolved",
        "first_seen": "2026-09-20T10:03:12Z", "last_seen": "2026-09-20T10:20:02Z",
        "peer_count": 9, "details": json.dumps({"kind": "new", "origin": 197207}),
    }


def test_detections_small_result_stays_full():
    c = FakeClient(detections=[_incident(i) for i in range(5)])
    out = call(c, "detections", {"asn": 197207, "start": "2026-09-10", "end": "2026-09-23"})
    assert len(out["incidents"]) == 5
    assert isinstance(out["incidents"][0]["details"], dict)
    assert "incidents_compact" not in out


def test_detections_large_result_goes_compact_with_same_counts():
    c = FakeClient(detections=[_incident(i) for i in range(450)])
    out = call(c, "detections", {"asn": 197207, "start": "2026-09-10", "end": "2026-09-23"})
    assert "incidents" not in out
    comp = out["incidents_compact"]
    assert len(comp["rows"]) == 450
    row = dict(zip(comp["columns"], comp["rows"][0]))
    assert row["prefix"] == "10.0.0.0/24" and row["actor_as"] == 197207
    assert row["direction"] == "queried_entity_is_invalid_party"
    assert out["total_matching"] == 450 and out["complete"] is True
    assert out["counts_by_type"] == {"origin_mismatch_new": 450}
    assert any(w["code"] == "compact_incidents" for w in out["warnings"])
    assert len(json.dumps(comp)) < len(json.dumps(c._detections)) / 2


def test_detections_full_format_overrides_auto():
    c = FakeClient(detections=[_incident(i) for i in range(450)])
    out = call(c, "detections", {"asn": 197207, "start": "2026-09-10", "end": "2026-09-23", "format": "full"})
    assert len(out["incidents"]) == 450
    assert not any(w["code"] == "compact_incidents" for w in out["warnings"])


def _episode(n):
    return {
        "asn": 197207, "from": "2026-09-20", "to": "2026-09-20",
        "summary": {"new_other_space": n, "peer_buckets": [{"peers": "1-9", "prefixes": n}]},
        "prefixes": [{"prefix": f"10.{i}.0.0/16", "space": "other", "peers": 9} for i in range(n)],
    }


def test_origin_episode_caps_listing_and_passes_min_peers():
    c = FakeClient(episode=_episode(150))
    out = call(c, "origin_episode", {"asn": 197207, "start": "2026-09-20", "min_peers": 10})
    assert c.calls["asn_episode"]["min_peers"] == 10
    assert len(out["prefixes"]) == 100 and out["prefixes_available"] == 150
    assert out["summary"]["peer_buckets"][0]["prefixes"] == 150
    assert any(w["code"] == "prefixes_truncated" for w in out["warnings"])


def test_origin_episode_no_min_peers_param_by_default():
    c = FakeClient(episode=_episode(3))
    out = call(c, "origin_episode", {"asn": 197207, "start": "2026-09-20"})
    assert "min_peers" not in c.calls["asn_episode"]
    assert len(out["prefixes"]) == 3
    assert not any(w["code"] == "prefixes_truncated" for w in out["warnings"])


def _registry(prefixes):
    out = {}
    for i, p in enumerate(prefixes):
        country = ("IR" if i % 4 == 1 else "ir") if i % 2 else "CN"  # registries mix case
        e = {"rdap": {"name": f"NET-{i}", "country": country, "port43": "whois.ripe.net"}}
        if i == 0:
            e["rpki"] = {"records": [{"cidr": p, "origin_asn": 25306, "max_length": 24}]}
        if i == 1:
            e["irr"] = {"records": [{"origin_as": 197207}]}
        out[p] = e
    return {"prefixes": out}


def test_bulk_registry_summary_only_keeps_counts_and_notables():
    pfx = [f"10.{i}.0.0/24" for i in range(10)]
    c = FakeClient(registry=_registry(pfx))
    out = call(c, "bulk_registry", {"prefixes": pfx, "origin_asn": 197207, "as_of": "2026-09-20", "summary_only": True})
    assert "prefixes" not in out
    assert out["summary"]["prefixes"] == 10
    assert out["summary"]["with_roas"] == 1
    assert out["summary"]["irr_matches_origin"] == 1
    assert out["summary"]["by_country"] == {"CN": 5, "IR": 5}
    assert out["rpki_summary"]["invalid"] == 1 and out["rpki_summary"]["not_found"] == 9
    assert [e["prefix"] for e in out["notable_prefixes"]] == ["10.0.0.0/24", "10.1.0.0/24"]


def test_bulk_registry_default_still_lists_every_prefix():
    pfx = [f"10.{i}.0.0/24" for i in range(4)]
    c = FakeClient(registry=_registry(pfx))
    out = call(c, "bulk_registry", {"prefixes": pfx, "as_of": "2026-09-20"})
    assert len(out["prefixes"]) == 4 and out["summary"]["prefixes"] == 4


class FilteringClient(FakeClient):
    """Like the gateway: pages by offset/limit, then drops incidents the caller's plan
    cannot see, so pages come back short."""

    def detections_asn(self, asn, **p):
        off, lim = p.get("offset", 0), p.get("limit", 500)
        page = [i for i in self._detections[off:off + lim] if not i["incident_id"].endswith("7")]
        return {"incidents": page, "pagination": {"offset": off, "limit": lim, "total": len(self._detections)}}


def test_detections_offset_resumes_without_skipping_or_rereading():
    inc = [_incident(i) for i in range(1200)]
    c = FilteringClient(detections=inc)
    first = call(c, "detections", {"asn": 197207, "anomalous_only": False, "max_incidents": 1000, "format": "compact"})
    # 1000 visible incidents take more than 1000 positions when some are filtered out.
    assert first["returned"] == 1000 and first["next_offset"] > 1000 and first["complete"] is False
    second = call(c, "detections", {"asn": 197207, "anomalous_only": False, "max_incidents": 1000,
                                     "offset": first["next_offset"], "format": "compact"})
    assert second["next_offset"] is None
    seen = first["returned"] + second["returned"]
    assert seen == len([i for i in inc if not i["incident_id"].endswith("7")])


class GeoClient(FakeClient):
    def __init__(self, points, facilities=None):
        super().__init__()
        self._points = points
        self._fac = facilities or []

    def asn_geo_ingress(self, asn):
        return {"points": self._points}

    def peeringdb_asn(self, asn):
        return {"facilities": self._fac}


def _pt(city, obs, lat=1.0):
    return {"city": city, "country": None, "lat": lat, "lon": 1.0, "total_obs": obs, "communities": []}


def test_locate_uses_ingress_evidence_not_sort_order():
    # AS21799's real shape: LA and San Jose carry the evidence; nothing is picked by alphabet.
    out = call(GeoClient([_pt("San Jose", 28423), _pt("Los Angeles", 39838), _pt("Cape Town", 5)]),
               "locate", {"asn": 21799})
    assert out["assessment"]["most_probable"] == "Los Angeles"
    assert "Cape Town" not in (out["assessment"].get("alternatives") or [])


def test_locate_anycast_is_distributed_and_empty_is_insufficient():
    many = [_pt(f"City{i}", 100) for i in range(8)]
    out = call(GeoClient(many), "locate", {"asn": 13335})
    assert out["assessment"]["classification"] == "distributed" and out["assessment"]["most_probable"] is None
    out = call(GeoClient([]), "locate", {"asn": 64500})
    assert out["assessment"]["classification"] == "insufficient_evidence"


class NotableClient(FakeClient):
    def notable_events(self, **p):
        base = {"victim_as": 199524, "prefix_count": 1, "sample_prefix": "141.11.161.0",
                "sample_prefix_len": 24, "detection_types": ["origin_mismatch_new"],
                "severity": "high", "score": 3.0, "is_v4": True}
        return {"window_hours": 24, "events": [
            {**base, "actor_as": 12098794, "actor_allocated": False},
            {**base, "actor_as": 197207, "actor_allocated": True},
            {**base, "actor_as": 64512},
        ]}


def test_notable_events_flags_unallocated_announcer():
    out = call(NotableClient(), "notable_events", {})
    assert [e["announcing_as_allocated"] for e in out["events"]] == [False, True, None]
    codes = {w["code"]: w["message"] for w in out["warnings"]}
    assert "AS12098794" in codes["unallocated_announcer"]
    assert "AS197207" not in codes["unallocated_announcer"]


class UpstreamsClient(FakeClient):
    def __init__(self, fail=False):
        super().__init__()
        self.fail = fail

    def prefix_overview(self, prefix, **p):
        # One churning peer's path dominates the update counts.
        return {"paths": [
            {"path_string": "53046 61626 268581 13335", "count": 270, "origin_as": 13335, "upstream_as": 268581},
            {"path_string": "3356 13335", "count": 10, "origin_as": 13335, "upstream_as": 3356},
        ]}

    def prefix_upstreams(self, prefix, **p):
        self.calls["prefix_upstreams"] = p
        if self.fail:
            raise RuntimeError("down")
        return {"sessions": 100, "direct_share": 0.02, "upstreams": [
            {"asn": 3356, "origin_as": 13335, "sessions": 60, "share": 0.6},
            {"asn": 268581, "origin_as": 13335, "sessions": 1, "share": 0.01},
        ]}


def test_paths_upstreams_are_session_weighted_and_window_is_cut():
    c = UpstreamsClient()
    out = call(c, "paths", {"prefix": "1.1.1.0/24", "start": "2026-06-01", "end": "2026-09-29"})
    assert out["upstreams"][0]["asn"] == 3356 and out["upstreams"][0]["sessions"] == 60
    assert out["direct_share"] == 0.02
    assert c.calls["prefix_upstreams"]["from"].startswith("2026-08-30")
    assert "upstreams_window_cut" in {w["code"] for w in out["warnings"]}


def test_paths_falls_back_to_update_mix_with_warning():
    out = call(UpstreamsClient(fail=True), "paths", {"prefix": "1.1.1.0/24", "start": "2026-09-20", "end": "2026-09-29"})
    assert out["upstreams"][0]["asn"] == 268581
    assert "upstreams_by_updates" in {w["code"] for w in out["warnings"]}


class EmptyPresenceClient(FakeClient):
    """The API sends null, not [], for an empty list (an ASN that announced nothing)."""
    def presence(self, **p):
        return {"target": "asn:64500", "prefixes": None}


def test_inventory_survives_null_prefix_list():
    out = call(EmptyPresenceClient(), "inventory", {"asn": 64500, "only": None, "start": None})
    assert out["totals"]["listed"] == 0 and out["prefixes"] == []
