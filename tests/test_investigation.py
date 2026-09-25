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
