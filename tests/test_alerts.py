"""Alert-tool tests: the report-shaping logic and the warnings that stop a model
misreading a quiet window as an incident."""

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from bgphorizon_mcp.tools.alerts import register_alert_tools


class FakeClient:
    """Records the params each tool sends and returns a canned API payload."""

    def __init__(self, notifications=None, monitors=None):
        self._notifications = notifications or {}
        self._monitors = monitors or {}
        self.calls = {}

    def notifications(self, **p):
        self.calls["notifications"] = p
        return self._notifications

    def monitors(self, **p):
        self.calls["monitors"] = p
        return self._monitors


def call(client, name, args):
    mcp = FastMCP(name="test")
    register_alert_tools(mcp, client)
    result = asyncio.run(mcp.call_tool(name, args))
    # FastMCP returns (content, structured) on newer versions, content on older.
    payload = result[1] if isinstance(result, tuple) else result
    if isinstance(payload, dict) and "result" in payload:
        payload = payload["result"]
    if isinstance(payload, list) and payload and hasattr(payload[0], "text"):
        payload = json.loads(payload[0].text)
    return payload


def _alerts_payload(alerts, by_type=None, by_monitor=None, total=None, truncated=False):
    return {
        "window": {"from": "2026-09-03T00:00:00Z", "to": "2026-09-03T18:00:00Z"},
        "total": total if total is not None else len(alerts),
        "returned": len(alerts),
        "truncated": truncated,
        "summary": {
            "by_detection_type": by_type or [],
            "by_severity": [],
            "by_monitor": by_monitor or [],
        },
        "alerts": alerts,
    }


def test_window_shorthand_is_passed_through_to_the_api():
    """'today' is resolved server-side by one parser, not re-implemented here."""
    c = FakeClient(notifications=_alerts_payload([]))
    call(c, "my_alerts", {"window": "today"})
    assert c.calls["notifications"]["from"] == "today"


def test_explicit_dates_win_over_the_shorthand():
    c = FakeClient(notifications=_alerts_payload([]))
    call(c, "my_alerts", {"window": "7d", "start": "2026-09-01", "end": "2026-09-02"})
    sent = c.calls["notifications"]
    assert sent["from"] == "2026-09-01" and sent["to"] == "2026-09-02"


def test_window_params_avoid_the_from_keyword_trap():
    """`from` is a Python keyword: published in the schema it can never bind, so
    the tools take start/end and map them to the API's from/to."""
    c = FakeClient(notifications=_alerts_payload([]))
    call(c, "my_alerts", {"start": "2026-09-01"})
    assert c.calls["notifications"]["from"] == "2026-09-01"


def test_empty_window_warns_rather_than_reading_as_nothing_watched():
    c = FakeClient(notifications=_alerts_payload([]))
    out = call(c, "my_alerts", {"window": "today"})
    assert [w["code"] for w in out["warnings"]] == ["no_alerts_in_window"]
    assert out["totals"]["alerts"] == 0


def test_truncation_is_flagged_so_a_report_does_not_understate():
    alerts = [{"id": str(i)} for i in range(200)]
    c = FakeClient(notifications=_alerts_payload(alerts, total=900, truncated=True))
    out = call(c, "my_alerts", {"window": "7d"})
    codes = [w["code"] for w in out["warnings"]]
    assert "truncated" in codes


def test_informational_flood_is_not_an_incident():
    by_type = [{"key": "unregistered_route", "count": 90}, {"key": "moas_conflict", "count": 10}]
    c = FakeClient(notifications=_alerts_payload([{"id": "a"}], by_type=by_type, total=100))
    out = call(c, "my_alerts", {"window": "today"})
    codes = [w["code"] for w in out["warnings"]]
    assert "mostly_informational" in codes


def test_one_noisy_monitor_is_attributed_not_generalised():
    by_monitor = [{"name": "NASA 128.102.0.0/16", "count": 80}, {"name": "other", "count": 20}]
    c = FakeClient(notifications=_alerts_payload([{"id": "a"}], by_monitor=by_monitor, total=100))
    out = call(c, "my_alerts", {"window": "today"})
    w = [x for x in out["warnings"] if x["code"] == "single_monitor_dominates"]
    assert w and "NASA" in w[0]["message"]


def test_monitors_summarise_coverage_and_flag_paused():
    monitors = {
        "window": {"from": "2026-08-27T00:00:00Z", "to": "2026-09-03T00:00:00Z"},
        "total": 3,
        "scope": "mine",
        "monitors": [
            {"id": "1", "resource_type": "prefix", "enabled": True, "alerts_in_window": 12, "detection_types": ["moas_conflict"]},
            {"id": "2", "resource_type": "asn", "enabled": False, "alerts_in_window": 0, "detection_types": ["moas_conflict"]},
            {"id": "3", "resource_type": "prefix", "enabled": True, "alerts_in_window": 0, "detection_types": ["moas_conflict"]},
        ],
    }
    out = call(FakeClient(monitors=monitors), "my_monitors", {"window": "7d"})
    t = out["totals"]
    assert t["monitors"] == 3 and t["enabled"] == 2 and t["paused"] == 1
    assert t["prefix_monitors"] == 2 and t["asn_monitors"] == 1
    assert t["quiet_in_window"] == 2
    assert out["most_active"][0]["id"] == "1"
    assert "paused_monitors" in [w["code"] for w in out["warnings"]]


def test_all_types_subscribed_points_at_the_bulk_fix():
    every_type = [f"t{i}" for i in range(15)]
    monitors = {
        "total": 2, "scope": "mine",
        "window": {"from": "a", "to": "b"},
        "monitors": [
            {"id": "1", "resource_type": "prefix", "enabled": True, "alerts_in_window": 5, "detection_types": every_type},
            {"id": "2", "resource_type": "prefix", "enabled": True, "alerts_in_window": 5, "detection_types": every_type},
        ],
    }
    out = call(FakeClient(monitors=monitors), "my_monitors", {"window": "7d"})
    w = [x for x in out["warnings"] if x["code"] == "all_types_subscribed"]
    assert w and "Monitors page" in w[0]["message"]
