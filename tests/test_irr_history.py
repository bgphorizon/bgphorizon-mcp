"""irr_history: paging, the attention list and the bulk entries."""

import asyncio
import json

import pytest
from mcp.server.fastmcp import FastMCP

from bgphorizon_mcp.tools.investigation import register_investigation_tools


def _change(i, **kw):
    c = {"date": f"2026-10-{(i % 28) + 1:02d}", "prev_date": "2026-09-30", "source": "RADB", "kind": "third_party",
         "object_type": "route", "change": "added", "object_key": f"10.0.{i}.0/24", "asn": 64500,
         "mnt_by": ["MAINT-OTHER"], "own_maintainer": False, "descr": ""}
    c.update(kw)
    return c


class FakeClient:
    def __init__(self, changes, extra=None):
        self.changes = changes
        self.extra = extra or {}
        self.calls = []

    def irr_changes(self, **p):
        self.calls.append(p)
        off, lim = p.get("offset", 0), p.get("limit", 50)
        return {"target": "AS64500", "start_date": p["start_date"], "end_date": p["end_date"],
                "history_since": {"RADB": "2022-01-01"}, "total": len(self.changes),
                "counts": {"added": len(self.changes), "removed": 0, "modified": 0},
                "maintainers": [{"mntner": "MAINT-OTHER", "added": len(self.changes), "own": False}],
                "own_maintainers": ["MAINT-AS64500"], "changes": self.changes[off:off + lim], **self.extra}


def call(client, args):
    mcp = FastMCP(name="test")
    register_investigation_tools(mcp, client)
    result = asyncio.run(mcp.call_tool("irr_history", args))
    payload = result[1] if isinstance(result, tuple) else result
    if isinstance(payload, dict) and "result" in payload:
        payload = payload["result"]
    if isinstance(payload, list) and payload and hasattr(payload[0], "text"):
        payload = json.loads(payload[0].text)
    return payload


def test_pages_until_limit_and_flags_truncation():
    c = FakeClient([_change(i) for i in range(1200)])
    out = call(c, {"asn": 64500, "limit": 700})
    assert len(out["changes"]) == 700
    assert [p["offset"] for p in c.calls] == [0, 500]
    assert c.calls[0]["asn"] == 64500 and c.calls[1]["limit"] == 200
    assert any(w["code"] == "truncated" for w in out["warnings"])
    assert out["total_entries"] == 1200 and out["counts"]["added"] == 1200


def test_default_window_and_filters_pass_through():
    c = FakeClient([_change(1)])
    out = call(c, {"prefix": " 10.0.1.0/24 ", "registry": "radb", "object_type": "route", "change": "added"})
    p = c.calls[0]
    assert p["prefix"] == "10.0.1.0/24" and p["source"] == "RADB" and p["type"] == "route" and p["change"] == "added"
    assert "asn" not in p
    assert out["window"]["start"] < out["window"]["end"]
    assert not out["warnings"]


def test_attention_lists_third_party_additions_by_other_maintainers():
    changes = [
        _change(1),                                                         # third-party, other: attention
        _change(2, own_maintainer=True, mnt_by=["MAINT-AS64500"]),          # own maintainer
        _change(3, source="ARIN", kind="authoritative"),                    # RIR registry
        _change(4, change="removed"),                                       # removal
        _change(5, object_type="as-set-member", object_key="AS-X", member="AS64500"),
    ]
    out = call(FakeClient(changes), {"asn": 64500})
    assert [a["object_key"] for a in out["attention"]] == ["10.0.1.0/24"]
    assert out["attention"][0]["own_maintainer"] is False
    assert "existed_since" not in out["attention"][0]  # empty fields dropped
    assert out["by_registry_listed"]["RADB"]["added"] == 3


def test_bulk_entries_counted_by_their_size():
    bulk = _change(1, change="removed", bulk={"id": "RADB|2026-10-02|route|removed|mnt:MAINT-HGC", "count": 3, "total": 123259, "examples": ["a", "b"]})
    out = call(FakeClient([bulk, _change(2)]), {"asn": 64500})
    assert out["bulk_changes"][0]["bulk"]["total"] == 123259
    assert out["by_registry_listed"]["RADB"] == {"added": 1, "removed": 3, "modified": 0}


def test_needs_exactly_one_target():
    for args in ({}, {"asn": 1, "prefix": "10.0.0.0/8"}):
        with pytest.raises(Exception):
            call(FakeClient([]), args)


def test_without_own_maintainers_every_third_party_addition_is_listed():
    changes = [_change(1, own_maintainer=None), _change(2, own_maintainer=None, kind="authoritative", source="RIPE")]
    out = call(FakeClient(changes, extra={"own_maintainers": []}), {"asn": 64500})
    assert [a["object_key"] for a in out["attention"]] == ["10.0.1.0/24"]

