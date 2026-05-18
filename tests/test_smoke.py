"""Smoke tests — verify the small, pure utilities don't regress."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── wol ─────────────────────────────────────────────────────────────────────

def test_wol_magic_packet():
    import wol
    captured = {}

    class FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def setsockopt(self, *a): pass
        def sendto(self, payload, addr):
            captured["payload"] = payload
            captured["addr"] = addr

    with patch("wol.socket.socket", return_value=FakeSock()):
        wol.wake("AA:BB:CC:DD:EE:FF")

    payload = captured["payload"]
    assert payload[:6] == b"\xff" * 6
    assert payload[6:] == bytes.fromhex("AABBCCDDEEFF") * 16
    assert captured["addr"] == ("<broadcast>", 9)


def test_wol_rejects_bad_mac():
    import wol
    import pytest
    with pytest.raises(ValueError):
        wol.wake("not-a-mac")


# ── scanner ─────────────────────────────────────────────────────────────────

def test_normalize_mac():
    from scanner import _normalize_mac
    assert _normalize_mac("a:b:c:d:e:f") == "0A:0B:0C:0D:0E:0F"
    assert _normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"


def test_is_unicast():
    from scanner import _is_unicast
    assert _is_unicast("192.168.1.10", "AA:BB:CC:DD:EE:FF")
    assert not _is_unicast("192.168.1.10", "FF:FF:FF:FF:FF:FF")
    assert not _is_unicast("224.0.0.1", "AA:BB:CC:DD:EE:FF")
    assert not _is_unicast("239.255.0.1", "AA:BB:CC:DD:EE:FF")


def test_probe_ports_excludes_udp():
    from scanner import PROBE_PORTS
    assert 1900 not in PROBE_PORTS
    assert 5353 not in PROBE_PORTS


# ── store (SQLite) ──────────────────────────────────────────────────────────

def _fresh_store(tmp_path):
    import store
    return store.DeviceStore(data_dir=tmp_path)


def test_store_touch_persists_and_marks_new(tmp_path):
    s = _fresh_store(tmp_path)
    d1 = s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
                  "hostname": "host.local", "vendor": "Acme"})
    assert d1["_is_new"] is True

    d2 = s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
                  "hostname": "host.local", "vendor": "Acme"})
    assert d2["_is_new"] is False


def test_store_detects_vendor_change(tmp_path):
    s = _fresh_store(tmp_path)
    s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
             "hostname": "h", "vendor": "Acme Corp"})
    spoofed = s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
                       "hostname": "h", "vendor": "Evil Industries"})
    assert spoofed["_vendor_changed"] == "Acme Corp"


def test_store_update_ports_returns_newly_opened(tmp_path):
    s = _fresh_store(tmp_path)
    mac = "AA:BB:CC:DD:EE:FF"
    s.touch({"ip": "10.0.0.5", "mac": mac, "hostname": "h", "vendor": "v"})
    assert s.update_ports(mac, [22, 80]) == [22, 80]
    assert s.update_ports(mac, [22, 80, 443]) == [443]
    assert s.update_ports(mac, [22, 80, 443]) == []        # no diff


def test_store_known_roundtrip(tmp_path):
    s = _fresh_store(tmp_path)
    s.add_known("AA:BB:CC:DD:EE:FF", "my-laptop")
    assert s.is_known("AA:BB:CC:DD:EE:FF")
    assert s.known_name("AA:BB:CC:DD:EE:FF") == "my-laptop"
    s.remove_known("AA:BB:CC:DD:EE:FF")
    assert not s.is_known("AA:BB:CC:DD:EE:FF")


def test_store_alerts_and_ack(tmp_path):
    s = _fresh_store(tmp_path)
    aid = s.add_alert("new_device", "info", "x joined", "msg here", mac="AA:BB:CC:DD:EE:FF")
    assert s.unack_alert_count() == 1
    assert s.alerts()[0]["id"] == aid
    s.acknowledge_alert(aid)
    assert s.unack_alert_count() == 0


def test_store_webhooks_filter_by_severity(tmp_path):
    s = _fresh_store(tmp_path)
    s.add_webhook("https://example.com/info",     "info",     min_severity="info")
    s.add_webhook("https://example.com/warn",     "warn",     min_severity="warning")
    s.add_webhook("https://example.com/critical", "critical", min_severity="critical")

    assert {h["min_severity"] for h in s.active_webhooks_for("info")}     == {"info"}
    assert {h["min_severity"] for h in s.active_webhooks_for("warning")}  == {"info", "warning"}
    assert {h["min_severity"] for h in s.active_webhooks_for("critical")} == {"info", "warning", "critical"}


def test_store_migrates_v1_json(tmp_path):
    import store
    (tmp_path / "known.json").write_text(json.dumps({
        "AA:BB:CC:DD:EE:FF": {"name": "router", "added": 1000.0},
    }))
    (tmp_path / "seen.json").write_text(json.dumps({
        "AA:BB:CC:DD:EE:FF": {"ip": "10.0.0.1", "vendor": "Asus", "first_seen": 999.0,
                              "last_seen": 1000.0, "hostname": "router.local",
                              "fingerprint": {"mdns": "router.local"}, "ports": [80, 443]},
    }))
    (tmp_path / "history.json").write_text(json.dumps([{"ts": 1000.0, "count": 5, "ssid": "HomeWiFi"}]))
    (tmp_path / "hook.json").write_text(json.dumps({"on_join": "echo joined"}))

    s = store.DeviceStore(data_dir=tmp_path)
    assert s.is_known("AA:BB:CC:DD:EE:FF")
    assert s.known_name("AA:BB:CC:DD:EE:FF") == "router"
    dev = s.get_device("AA:BB:CC:DD:EE:FF")
    assert dev["vendor"] == "Asus"
    assert dev["ports"] == [80, 443]
    assert dev["fingerprint"] == {"mdns": "router.local"}
    assert s.history[0]["ssid"] == "HomeWiFi"
    assert s.hook_script == "echo joined"
    # JSON files should be moved aside.
    assert not (tmp_path / "known.json").exists()
    assert (tmp_path / "known.json.v1.bak").exists()

    # Reinitializing must not re-import.
    s2 = store.DeviceStore(data_dir=tmp_path)
    assert s2.is_known("AA:BB:CC:DD:EE:FF")  # still there
    assert s2.history[0]["ssid"] == "HomeWiFi"
    # History row count didn't double.
    assert len(s2.history) == 1


# ── classify ────────────────────────────────────────────────────────────────

def test_classify_by_fingerprint_keyword():
    import classify
    dtype, conf = classify.classify(fingerprint="iPhone-of-Sam")
    assert dtype == "phone"
    assert conf >= 0.8

    dtype, _ = classify.classify(fingerprint="MyMacBook-Pro.local")
    assert dtype == "laptop"


def test_classify_by_vendor():
    import classify
    dtype, conf = classify.classify(vendor="Brother Industries, Ltd.")
    assert dtype == "printer"
    assert 0.5 <= conf <= 0.95


def test_classify_ports_only():
    import classify
    dtype, _ = classify.classify(vendor="", fingerprint="", ports=[9100])
    assert dtype == "printer"
    dtype, _ = classify.classify(vendor="", fingerprint="", ports=[554])
    assert dtype == "camera"


def test_classify_unknown_when_no_signals():
    import classify
    dtype, conf = classify.classify(vendor="", fingerprint="", ports=[])
    assert dtype == "unknown"
    assert conf == 0.0


# ── security rules ──────────────────────────────────────────────────────────

def test_security_new_device_alert():
    import security
    a = security.check_new_device({
        "_is_new": True, "is_known": False, "me": False,
        "mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.7",
        "hostname": "?", "vendor": "Espressif", "device_type": "iot",
    })
    assert a is not None
    assert a.severity == "info"
    assert "joined" in a.title.lower() or "new" in a.title.lower()


def test_security_no_alert_for_self_or_known():
    import security
    assert security.check_new_device({"_is_new": True, "is_known": True}) is None
    assert security.check_new_device({"_is_new": True, "is_known": False, "me": True}) is None


def test_security_vendor_change_is_critical():
    import security
    a = security.check_vendor_change({
        "_vendor_changed": "Apple Inc",
        "vendor": "Random Vendor", "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "10.0.0.1",
    })
    assert a is not None
    assert a.severity == "critical"


def test_security_risky_ports_flag_telnet_as_critical():
    import security
    alerts = security.check_risky_ports(
        {"mac": "X", "ip": "1.2.3.4"}, new_ports=[23, 80]
    )
    assert any(a.severity == "critical" and "Telnet" in a.title for a in alerts)


# ── notify (throttling) ─────────────────────────────────────────────────────

def test_notify_throttles_and_dedupes(monkeypatch):
    import notify
    notify._last_emit_ts = 0
    notify._recent.clear()
    notify._burst_queue.clear()
    notify._burst_timer = None

    sent = []
    monkeypatch.setattr(notify, "_osascript_notify",
                        lambda title, msg, subtitle="": sent.append((title, msg)))

    # Use a critical alert (skips burst-coalescing) so we get an immediate emit
    # we can assert on. Same dedup key fires once, second call is suppressed.
    a = {"kind": "vendor_changed", "severity": "critical",
         "title": "spoof", "message": "...", "mac": "AA:BB:CC:DD:EE:FF"}
    assert notify.notify_alert(a) is True
    assert notify.notify_alert(a) is False
    assert len(sent) == 1


# ── webhooks (payload shape) ────────────────────────────────────────────────

def test_webhook_payload_discord_format():
    import webhooks
    p = webhooks._payload_for(
        "https://discord.com/api/webhooks/123/abc",
        {"title": "T", "message": "M", "severity": "warning"},
    )
    assert "embeds" in p
    assert p["embeds"][0]["title"] == "T"


def test_webhook_payload_slack_format():
    import webhooks
    p = webhooks._payload_for(
        "https://hooks.slack.com/services/T/B/X",
        {"title": "T", "message": "M", "severity": "critical"},
    )
    assert "attachments" in p
    assert p["attachments"][0]["title"] == "T"


def test_webhook_payload_generic_default():
    import webhooks
    p = webhooks._payload_for(
        "https://example.com/whatever",
        {"title": "T", "message": "M", "severity": "info"},
    )
    assert p["alert"]["title"] == "T"


# ── events ──────────────────────────────────────────────────────────────────

def test_events_subscribe_and_publish():
    import events
    got = []
    events.subscribe("test.x", lambda p: got.append(p))
    events.publish("test.x", {"v": 1})
    events.publish("test.x", {"v": 2})
    assert got == [{"v": 1}, {"v": 2}]


def test_events_one_bad_subscriber_doesnt_stop_others():
    import events
    got = []
    events.subscribe("test.y", lambda p: (_ for _ in ()).throw(RuntimeError("bad")))
    events.subscribe("test.y", lambda p: got.append(p))
    events.publish("test.y", {"ok": True})
    assert got == [{"ok": True}]


# ── dashboard origin check ──────────────────────────────────────────────────

def test_origin_check_accepts_local():
    import dashboard
    dashboard._Handler.allowed_origins = {
        "http://127.0.0.1:8765",
        "http://localhost:8765",
    }
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.headers = {"Origin": "http://127.0.0.1:8765"}
    assert h._origin_ok()
    h.headers = {"Referer": "http://localhost:8765/"}
    assert h._origin_ok()


def test_origin_check_rejects_foreign():
    import dashboard
    dashboard._Handler.allowed_origins = {
        "http://127.0.0.1:8765",
        "http://localhost:8765",
    }
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.headers = {"Origin": "https://evil.com"}
    assert not h._origin_ok()
    h.headers = {"Origin": "http://localhost:8765.evil.com"}
    assert not h._origin_ok()
    h.headers = {}
    assert not h._origin_ok()


def test_static_path_traversal_blocked(tmp_path, monkeypatch):
    import dashboard
    # Try to escape with ../.
    assert dashboard._read_static("../store.py") is None
    assert dashboard._read_static("..") is None


# ── updater ─────────────────────────────────────────────────────────────────

def test_version_tuple_parses_v_prefix():
    from updater import _version_tuple
    assert _version_tuple("1.2.3") == (1, 2, 3)
    assert _version_tuple("v1.2.3") == (1, 2, 3)
    assert _version_tuple("garbage") == ()
    assert _version_tuple("") == ()


def test_check_for_update_returns_newer():
    import updater
    fake = MagicMock()
    fake.read.return_value = json.dumps({
        "tag_name": "v3.0.0",
        "html_url": "https://example.com/releases/v3.0.0",
        "body":     "Big release",
    }).encode()
    fake.__enter__ = lambda self: self
    fake.__exit__ = lambda *a: None
    with patch("updater.urllib.request.urlopen", return_value=fake):
        result = updater.check_for_update(current="2.0.0")
    assert result == {"tag": "3.0.0", "url": "https://example.com/releases/v3.0.0", "body": "Big release"}


def test_check_for_update_returns_none_when_current():
    import updater
    fake = MagicMock()
    fake.read.return_value = json.dumps({"tag_name": "v2.0.0", "html_url": "x"}).encode()
    fake.__enter__ = lambda self: self
    fake.__exit__ = lambda *a: None
    with patch("updater.urllib.request.urlopen", return_value=fake):
        assert updater.check_for_update(current="2.0.0") is None


def test_check_for_update_returns_none_on_network_error():
    import updater
    with patch("updater.urllib.request.urlopen", side_effect=OSError("no network")):
        assert updater.check_for_update(current="2.0.0") is None


# ── health (Network Health Score) ───────────────────────────────────────────

def test_health_baseline_is_100():
    import health
    h = health.compute(devices=[], unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    assert h["score"] == 100
    assert h["band"] == "excellent"


def test_health_drops_for_unknown_devices():
    import health
    devices = [
        {"mac": "AA:BB:CC:DD:EE:0" + str(i), "ip": f"10.0.0.{i}",
         "is_known": False, "me": False, "device_type": "unknown",
         "vendor": "", "ports": []}
        for i in range(3)
    ]
    h = health.compute(devices, [], [], [])
    assert h["score"] < 100
    assert any("unknown" in r["label"].lower() for r in h["reasons"])


def test_health_critical_for_rogue_dhcp():
    import health
    from detect import DhcpServer
    servers = [
        DhcpServer("192.168.1.1", "AA:BB:CC:DD:EE:FF", 0, 0),
        DhcpServer("192.168.1.50", "11:22:33:44:55:66", 0, 0),
    ]
    h = health.compute([], [], [], servers)
    assert h["score"] <= 75   # rogue dhcp is a 35-point hit
    assert any("dhcp" in r["label"].lower() for r in h["reasons"])


def test_health_wan_exposed_camera_is_heavily_penalized():
    import health
    devices = [{"mac": "X", "ip": "10.0.0.5", "device_type": "camera",
                "is_known": True, "me": False, "vendor": "Hikvision",
                "ports": [80]}]
    mappings = [{"internal_ip": "10.0.0.5", "internal_port": 80,
                 "external_port": 8080, "protocol": "TCP"}]
    h = health.compute(devices, [], mappings, [])
    assert h["score"] < 75
    assert any("camera" in r["label"].lower() and "internet" in r["label"].lower()
               for r in h["reasons"])


def test_health_bands_cover_full_range():
    import health
    # Hit it with one of everything to drive into "at_risk"
    devices = [{"mac": f"X{i}", "ip": f"10.0.0.{i}", "device_type": "unknown",
                "is_known": False, "me": False, "vendor": "", "ports": [23, 3389]}
               for i in range(10)]
    from detect import DhcpServer
    servers = [DhcpServer(f"10.0.0.{i}", f"XX:XX:XX:XX:XX:{i:02x}", 0, 0)
               for i in range(3)]
    h = health.compute(devices, [], [], servers)
    assert h["band"] in ("poor", "at_risk")


# ── detect (passive network watchers) ──────────────────────────────────────

def test_detect_rogue_dhcp_returns_one_per_pair(tmp_path):
    import store, detect
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_dhcp_server("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    s.record_dhcp_server("192.168.1.1", "AA:BB:CC:DD:EE:FF")   # same → dedup
    s.record_dhcp_server("192.168.1.50", "11:22:33:44:55:66")
    servers = detect.rogue_dhcp_servers(s)
    assert len(servers) == 2


def test_detect_arp_anomalies_flags_ip_with_multiple_macs(tmp_path):
    import store, detect
    s = store.DeviceStore(data_dir=tmp_path)
    # Two MACs claim the same IP inside the 1h window
    s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
             "hostname": "h", "vendor": "v"})
    s.touch({"ip": "10.0.0.5", "mac": "11:22:33:44:55:66",
             "hostname": "h", "vendor": "v"})
    anomalies = detect.arp_anomalies(s)
    assert any(a.ip == "10.0.0.5" and len(a.macs) >= 2 for a in anomalies)


def test_detect_fingerprint_groups_collapses_to_canonical(tmp_path):
    import store, detect, json
    s = store.DeviceStore(data_dir=tmp_path)
    s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
             "hostname": "iphone.local", "vendor": "Apple"})
    s.update_fingerprint("AA:BB:CC:DD:EE:FF", {"mdns": "iphone.local"})
    s.add_known("AA:BB:CC:DD:EE:FF", "Sam's iPhone")

    # Same fingerprint shows up on a different randomized MAC
    s.touch({"ip": "10.0.0.6", "mac": "11:22:33:44:55:66",
             "hostname": "iphone.local", "vendor": "Apple"})
    s.update_fingerprint("11:22:33:44:55:66", {"mdns": "iphone.local"})

    groups = detect.fingerprint_groups(s)
    assert len(groups) == 1
    g = groups[0]
    assert g.canonical_mac == "AA:BB:CC:DD:EE:FF"
    assert "11:22:33:44:55:66" in g.member_macs


# ── new security rules ─────────────────────────────────────────────────────

def test_security_wan_exposed_camera_is_critical():
    import security
    alerts = security.check_wan_exposed_ports(
        {"mac": "X", "ip": "10.0.0.5", "device_type": "camera"},
        [{"internal_ip": "10.0.0.5", "internal_port": 80,
          "external_port": 8080, "protocol": "TCP"}],
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"


def test_security_wan_exposed_random_port_is_warning():
    import security
    alerts = security.check_wan_exposed_ports(
        {"mac": "X", "ip": "10.0.0.5", "device_type": "computer"},
        [{"internal_ip": "10.0.0.5", "internal_port": 9000,
          "external_port": 9000, "protocol": "TCP"}],
    )
    assert alerts[0].severity == "warning"


def test_security_rogue_dhcp_silent_with_one_server():
    import security
    from detect import DhcpServer
    assert security.check_rogue_dhcp([
        DhcpServer("192.168.1.1", "AA:BB:CC:DD:EE:FF", 0, 0),
    ]) == []


def test_security_rogue_dhcp_critical_with_two():
    import security
    from detect import DhcpServer
    alerts = security.check_rogue_dhcp([
        DhcpServer("192.168.1.1",  "AA:BB:CC:DD:EE:FF", 0, 0),
        DhcpServer("192.168.1.50", "11:22:33:44:55:66", 0, 0),
    ])
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"


def test_security_arp_anomalies_emits_one_per_ip():
    import security
    from detect import ArpAnomaly
    alerts = security.check_arp_anomalies([
        ArpAnomaly(ip="10.0.0.5", macs=("AA:BB", "11:22")),
        ArpAnomaly(ip="10.0.0.6", macs=("AA:BB", "11:22")),
    ])
    assert len(alerts) == 2
    assert all(a.severity == "critical" for a in alerts)


def test_security_dns_threat_matches_exact_and_suffix():
    import security
    threats = {"malware.example", "phish.test"}
    alerts = security.check_dns_threat(
        {"mac": "X", "ip": "10.0.0.5"},
        ["safe.com", "subdomain.malware.example", "phish.test"],
        threats,
    )
    assert len(alerts) == 1
    assert "subdomain.malware.example" in alerts[0].message
    assert "phish.test" in alerts[0].message


def test_security_dns_threat_silent_when_no_hits():
    import security
    assert security.check_dns_threat(
        {"mac": "X", "ip": "10.0.0.5"},
        ["safe.com", "also-safe.example"],
        {"malware.example"},
    ) == []


def test_security_randomized_mac_group_includes_label_and_members():
    import security
    from detect import FingerprintGroup
    a = security.check_randomized_mac_group(FingerprintGroup(
        canonical_mac="AA:BB:CC:DD:EE:FF",
        canonical_label="Sam's iPhone",
        member_macs=("11:22:33:44:55:66", "77:88:99:AA:BB:CC"),
    ))
    assert a is not None
    assert "Sam's iPhone" in a.title
    assert "11:22:33:44:55:66" in a.message


def test_security_evaluate_passes_wan_mappings_through():
    import security
    alerts = security.evaluate(
        {"mac": "X", "ip": "10.0.0.5", "device_type": "camera"},
        wan_mappings=[{"internal_ip": "10.0.0.5", "internal_port": 80,
                       "external_port": 8080, "protocol": "TCP"}],
    )
    assert any(a.kind.startswith("wan_exposed_") for a in alerts)


# ── store extensions ───────────────────────────────────────────────────────

def test_store_no_probe_roundtrip(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
             "hostname": "h", "vendor": "v"})
    assert s.is_probe_blocked("AA:BB:CC:DD:EE:FF") is False
    s.set_no_probe("AA:BB:CC:DD:EE:FF", True)
    assert s.is_probe_blocked("AA:BB:CC:DD:EE:FF") is True
    s.set_no_probe("AA:BB:CC:DD:EE:FF", False)
    assert s.is_probe_blocked("AA:BB:CC:DD:EE:FF") is False


def test_store_dhcp_servers_recorded(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_dhcp_server("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    rows = s._q("SELECT ip, mac FROM dhcp_servers")
    assert len(rows) == 1
    assert rows[0]["mac"] == "AA:BB:CC:DD:EE:FF"   # normalized to upper


def test_store_wan_mappings_replace(tmp_path):
    import store
    from igd import Mapping
    s = store.DeviceStore(data_dir=tmp_path)
    m1 = Mapping(8080, "10.0.0.5", 80, "TCP", "test", 0, True)
    m2 = Mapping(22, "10.0.0.6", 22, "TCP", "ssh", 0, True)
    s.record_wan_mappings([m1, m2])
    assert len(s.wan_mappings()) == 2
    s.record_wan_mappings([m1])
    assert len(s.wan_mappings()) == 1
    assert s.wan_mappings_for("10.0.0.5")[0]["external_port"] == 8080
    assert s.wan_mappings_for("10.0.0.99") == []


def test_store_health_snapshot_roundtrip(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    assert s.latest_health() is None
    s.record_health(82, [{"weight": 10, "label": "two unknown devices", "key": "unknown_device"}])
    snap = s.latest_health()
    assert snap["score"] == 82
    assert snap["reasons"][0]["weight"] == 10


# ── new webhook formats ────────────────────────────────────────────────────

def test_webhook_ntfy_format():
    import webhooks
    p = webhooks._payload_for(
        "https://ntfy.sh/my-topic",
        {"title": "T", "message": "M", "severity": "warning"},
    )
    assert p["title"] == "T"
    assert p["priority"] == 4


def test_webhook_pushover_extracts_token_and_user():
    import webhooks
    p = webhooks._payload_for(
        "https://api.pushover.net/1/messages.json?token=APP123&user=USR456",
        {"title": "T", "message": "M", "severity": "critical"},
    )
    assert p["token"] == "APP123"
    assert p["user"]  == "USR456"
    assert p["priority"] == 2


# ── notify (burst coalescing) ──────────────────────────────────────────────

def test_notify_coalesces_new_device_burst(monkeypatch):
    import notify
    notify._last_emit_ts = 0
    notify._recent.clear()
    notify._burst_queue.clear()
    notify._burst_timer = None

    sent = []
    monkeypatch.setattr(notify, "_osascript_notify",
                        lambda title, msg, subtitle="": sent.append((title, msg)))

    for i in range(4):
        notify.notify_alert({
            "kind": "new_device", "severity": "info",
            "title": f"New device {i}", "message": "...",
            "mac": f"AA:BB:CC:DD:EE:0{i}",
        })

    # Force-flush instead of waiting on the timer.
    notify._flush_burst()
    assert len(sent) == 1
    assert "4 new devices" in sent[0][0]


def test_notify_critical_alerts_fire_individually(monkeypatch):
    import notify
    notify._last_emit_ts = 0
    notify._recent.clear()
    notify._burst_queue.clear()
    notify._burst_timer = None

    sent = []
    monkeypatch.setattr(notify, "_osascript_notify",
                        lambda title, msg, subtitle="": sent.append(title))

    notify.notify_alert({
        "kind": "rogue_dhcp", "severity": "critical",
        "title": "Rogue DHCP", "message": "...", "mac": None,
    })
    assert sent == ["Rogue DHCP"]


# ── igd (mapping XML parsing) ──────────────────────────────────────────────

def test_igd_parse_mapping_returns_mapping_dataclass():
    import igd
    xml = b"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
 <s:Body>
  <u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
   <NewRemoteHost></NewRemoteHost>
   <NewExternalPort>8080</NewExternalPort>
   <NewProtocol>TCP</NewProtocol>
   <NewInternalPort>80</NewInternalPort>
   <NewInternalClient>192.168.1.42</NewInternalClient>
   <NewEnabled>1</NewEnabled>
   <NewPortMappingDescription>camera</NewPortMappingDescription>
   <NewLeaseDuration>0</NewLeaseDuration>
  </u:GetGenericPortMappingEntryResponse>
 </s:Body>
</s:Envelope>"""
    m = igd._parse_mapping(xml)
    assert m is not None
    assert m.external_port == 8080
    assert m.internal_client == "192.168.1.42"
    assert m.internal_port == 80
    assert m.protocol == "TCP"
    assert m.enabled is True
    assert m.is_public() is True


def test_igd_parse_mapping_handles_missing_fields():
    import igd
    xml = b"<bogus/>"
    assert igd._parse_mapping(xml) is None


# ── scanner: mDNS + ARP augmentation ───────────────────────────────────────

def test_ip_in_network_inside_and_outside():
    from scanner import _ip_in_network
    assert _ip_in_network("10.0.0.5",  "10.0.0.0/24")
    assert not _ip_in_network("10.0.1.5", "10.0.0.0/24")
    assert not _ip_in_network("not-an-ip", "10.0.0.0/24")


def test_arp_resolve_extracts_macs_for_requested_ips(monkeypatch):
    import scanner
    monkeypatch.setattr(scanner.subprocess, "run", _fake_arp_run)
    out = scanner._arp_resolve(["10.0.0.5", "10.0.0.6", "10.0.0.99"])
    by_ip = {r["ip"]: r["mac"] for r in out}
    assert by_ip == {
        "10.0.0.5": "AA:BB:CC:DD:EE:FF",
        "10.0.0.6": "11:22:33:44:55:66",
    }


def test_arp_resolve_skips_incomplete_entries(monkeypatch):
    import scanner

    def fake_run(cmd, *a, **kw):
        if cmd[:1] == ["ping"]:
            class R: stdout = ""
            return R()
        if cmd[:2] == ["arp", "-an"]:
            class R: pass
            R.stdout = (
                "? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
                "? (10.0.0.6) at (incomplete) on en0 ifscope [ethernet]\n"
            )
            return R()
        class R: stdout = ""
        return R()

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    out = scanner._arp_resolve(["10.0.0.5", "10.0.0.6"])
    assert out == [{"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF"}]


def test_arp_resolve_empty_input_returns_empty():
    import scanner
    assert scanner._arp_resolve([]) == []


# ── actions (voice + Shortcuts) ────────────────────────────────────────────

def test_actions_wire_is_idempotent(tmp_path):
    import store, actions, events
    s = store.DeviceStore(data_dir=tmp_path)
    actions._wired = False  # reset for isolated test
    actions.wire(s)
    actions.wire(s)
    actions.wire(s)
    assert actions._wired is True


def test_actions_speak_uses_say(monkeypatch):
    import actions
    captured = []
    class P:
        def __init__(self, cmd, **kw):
            captured.append(cmd)
        def communicate(self, *a, **kw): return (b"", b"")
    monkeypatch.setattr(actions.subprocess, "Popen", P)
    actions._speak("Network alert")
    assert captured and captured[0][0] == "say"
    assert "Network alert" in captured[0]


def test_actions_run_shortcut_no_op_on_empty_name(monkeypatch):
    import actions
    called = []
    monkeypatch.setattr(actions.subprocess, "Popen",
                        lambda *a, **kw: called.append(a) or None)
    actions._run_shortcut("", {"title": "x"})
    actions._run_shortcut("   ", {"title": "x"})
    assert called == []


def test_actions_alert_speaks_only_warning_and_critical(tmp_path, monkeypatch):
    import store, actions
    s = store.DeviceStore(data_dir=tmp_path)
    s.set_setting("voice_enabled", "1")
    spoken = []
    monkeypatch.setattr(actions, "_speak", lambda t: spoken.append(t))
    actions._on_alert_raised({"severity": "info", "title": "info one"}, store=s)
    actions._on_alert_raised({"severity": "warning", "title": "warn one"}, store=s)
    actions._on_alert_raised({"severity": "critical", "title": "crit one"}, store=s)
    assert spoken == ["warn one", "crit one"]


def test_actions_alert_silent_when_voice_disabled(tmp_path, monkeypatch):
    import store, actions
    s = store.DeviceStore(data_dir=tmp_path)
    s.set_setting("voice_enabled", "0")
    spoken = []
    monkeypatch.setattr(actions, "_speak", lambda t: spoken.append(t))
    actions._on_alert_raised({"severity": "critical", "title": "crit"}, store=s)
    assert spoken == []


# ── routerctl (router quarantine adapters) ─────────────────────────────────

def test_routerctl_noop_raises_helpful_error():
    import routerctl
    b = routerctl.NoopBackend()
    import pytest
    with pytest.raises(routerctl.RouterError) as ei:
        b.block("AA:BB:CC:DD:EE:FF")
    assert "Settings" in str(ei.value)
    assert b.test()["ok"] is False


def test_routerctl_get_backend_returns_noop_when_unconfigured(tmp_path):
    import store, routerctl
    s = store.DeviceStore(data_dir=tmp_path)
    assert isinstance(routerctl.get_backend(s), routerctl.NoopBackend)


def test_routerctl_get_backend_returns_unifi_when_configured(tmp_path):
    import store, routerctl
    s = store.DeviceStore(data_dir=tmp_path)
    s.set_setting("router_kind", "unifi")
    s.set_setting("router_host", "https://10.0.0.1:8443")
    s.set_setting("router_user", "admin")
    s.set_setting("router_pass", "x")
    assert isinstance(routerctl.get_backend(s), routerctl.UnifiBackend)


def test_routerctl_get_backend_returns_openwrt_when_configured(tmp_path):
    import store, routerctl
    s = store.DeviceStore(data_dir=tmp_path)
    s.set_setting("router_kind", "openwrt")
    s.set_setting("router_host", "10.0.0.1")
    s.set_setting("router_user", "root")
    assert isinstance(routerctl.get_backend(s), routerctl.OpenWrtBackend)


def test_routerctl_unifi_login_failure_surfaces_clean_error(monkeypatch):
    import routerctl, urllib.error
    b = routerctl.UnifiBackend("https://10.0.0.1:8443", "admin", "x")
    monkeypatch.setattr(routerctl.urllib.request, "urlopen",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            urllib.error.URLError("connection refused")))
    import pytest
    with pytest.raises(routerctl.RouterError) as ei:
        b._login()
    assert "Couldn't reach Unifi" in str(ei.value) or "Unifi login failed" in str(ei.value)


def test_routerctl_openwrt_ssh_failure_surfaces_clean_error(monkeypatch):
    import routerctl
    b = routerctl.OpenWrtBackend("10.0.0.1", "root", None)
    monkeypatch.setattr(routerctl.subprocess, "run",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            FileNotFoundError("ssh missing")))
    import pytest
    with pytest.raises(routerctl.RouterError) as ei:
        b._ssh("echo hi")
    assert "SSH to OpenWrt failed" in str(ei.value)


def test_routerctl_openwrt_block_is_idempotent(monkeypatch):
    import routerctl
    b = routerctl.OpenWrtBackend("10.0.0.1", "root", None)
    calls = []
    monkeypatch.setattr(b, "_read_maclist", lambda: ["aa:bb:cc:dd:ee:ff"])
    monkeypatch.setattr(b, "_write_maclist", lambda macs: calls.append(macs))
    b.block("AA:BB:CC:DD:EE:FF")
    assert calls == []   # already present, no write


# ── threats (threat-intel list) ────────────────────────────────────────────

def test_threats_seed_file_created_if_missing(tmp_path):
    import threats
    p = tmp_path / "threats.txt"
    tl = threats.ThreatList(p)
    assert p.exists()
    assert "torproject.org" in tl.domains()


def test_threats_exact_and_suffix_match(tmp_path):
    import threats
    p = tmp_path / "threats.txt"
    p.write_text("# header\nbad.example\nphish.test\n")
    tl = threats.ThreatList(p)
    assert tl.matches("bad.example") == "bad.example"
    assert tl.matches("sub.bad.example") == "bad.example"
    assert tl.matches("phish.test") == "phish.test"
    assert tl.matches("bad-example.com") is None  # NOT a suffix match
    assert tl.matches("safe.com") is None
    assert tl.matches("") is None


def test_threats_comments_and_blanks_ignored(tmp_path):
    import threats
    p = tmp_path / "threats.txt"
    p.write_text("\n# a comment\n\nfoo.example\n  bar.example  \n")
    tl = threats.ThreatList(p)
    domains = tl.domains()
    assert "foo.example" in domains
    assert "bar.example" in domains
    assert "# a comment" not in domains


def test_threats_reload_on_mtime_change(tmp_path):
    import threats, time as _t
    p = tmp_path / "threats.txt"
    p.write_text("one.example\n")
    tl = threats.ThreatList(p)
    assert tl.matches("one.example") is not None

    _t.sleep(0.01)
    p.write_text("two.example\n")
    import os as _os
    _os.utime(p, None)   # force mtime tick
    tl.reload_if_stale()
    assert tl.matches("one.example") is None
    assert tl.matches("two.example") is not None


# ── sniffer (no real packets — just status / parsers) ──────────────────────

def test_sniffer_status_default_disabled():
    import sniffer
    s = sniffer.status()
    assert s["enabled"] is False
    assert s["running"] is False
    assert "packets" in s


def test_sniffer_can_capture_returns_helpful_reason_when_no_bpf(monkeypatch):
    import sniffer
    monkeypatch.setattr(sniffer.os, "open",
                        lambda *a, **kw: (_ for _ in ()).throw(PermissionError("nope")))
    ok, reason = sniffer._can_capture()
    assert ok is False
    assert "enable_sniffer" in reason


def test_sniffer_bump_credits_in_and_out():
    import sniffer
    sniffer._counters.clear()
    sniffer._bump("aa:bb:cc:dd:ee:ff", "in", 100)
    sniffer._bump("AA:BB:CC:DD:EE:FF", "out", 250)
    sniffer._bump("11:22:33:44:55:66", "out", 50)
    snap = sniffer._snapshot_and_reset()
    assert snap["AA:BB:CC:DD:EE:FF"].bytes_in == 100
    assert snap["AA:BB:CC:DD:EE:FF"].bytes_out == 250
    assert snap["11:22:33:44:55:66"].bytes_out == 50
    # Snapshot resets in-memory counters.
    assert sniffer._counters == {}


# ── store bandwidth/DNS roundtrips ─────────────────────────────────────────

def test_store_bandwidth_roundtrip(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_bandwidth_samples([
        ("AA:BB:CC:DD:EE:FF", 1024, 2048),
        ("11:22:33:44:55:66", 500, 0),
    ])
    rows = s.bandwidth_for("AA:BB:CC:DD:EE:FF")
    assert len(rows) == 1
    assert rows[0]["bytes_in"] == 1024
    assert rows[0]["bytes_out"] == 2048
    # Cross-mac isolation
    assert len(s.bandwidth_for("FF:FF:FF:FF:FF:FF")) == 0


def test_store_bandwidth_empty_input_is_noop(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_bandwidth_samples([])
    assert s.bandwidth_for("AA:BB:CC:DD:EE:FF") == []


def test_store_dns_query_roundtrip(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_dns_query("AA:BB:CC:DD:EE:FF", "example.com", 1)
    s.record_dns_query("AA:BB:CC:DD:EE:FF", "tracker.example", 1)
    rows = s.dns_queries_for("AA:BB:CC:DD:EE:FF", limit=10)
    qnames = [r["qname"] for r in rows]
    assert "example.com" in qnames
    assert "tracker.example" in qnames


def test_store_dns_query_skips_empty_inputs(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_dns_query("", "example.com", 1)
    s.record_dns_query("AA:BB:CC:DD:EE:FF", "", 1)
    assert s.dns_queries_for("AA:BB:CC:DD:EE:FF") == []


def _fake_arp_run(cmd, *a, **kw):
    """Shared subprocess.run mock for scanner ARP tests."""
    class R:
        stdout = ""
    if cmd[:1] == ["ping"]:
        return R()
    if cmd[:2] == ["arp", "-an"]:
        R.stdout = (
            "? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (10.0.0.6) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
        )
        return R()
    return R()
