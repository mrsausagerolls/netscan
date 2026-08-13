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
    # Each server needs >= 2 recent sightings to count (a single stray OFFER is
    # ignored so a transient hotspot/VM doesn't pin a week-long critical alert).
    s.record_dhcp_server("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    s.record_dhcp_server("192.168.1.1", "AA:BB:CC:DD:EE:FF")   # same → one pair
    s.record_dhcp_server("192.168.1.50", "11:22:33:44:55:66")
    s.record_dhcp_server("192.168.1.50", "11:22:33:44:55:66")
    servers = detect.rogue_dhcp_servers(s)
    assert len(servers) == 2


def test_detect_rogue_dhcp_ignores_single_stray_offer(tmp_path):
    import store, detect
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_dhcp_server("192.168.1.1",  "AA:BB:CC:DD:EE:FF")  # router, seen twice
    s.record_dhcp_server("192.168.1.1",  "AA:BB:CC:DD:EE:FF")
    s.record_dhcp_server("192.168.1.99", "DE:AD:BE:EF:00:01")  # one-off blip
    servers = detect.rogue_dhcp_servers(s)
    assert [srv.ip for srv in servers] == ["192.168.1.1"]


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


# ── launchd_agent (Keep in menubar / KeepAlive plist rewrite) ──────────────

def test_launchd_agent_get_returns_false_when_plist_missing(monkeypatch, tmp_path):
    import launchd_agent
    monkeypatch.setattr(launchd_agent, "PLIST_PATH", tmp_path / "missing.plist")
    assert launchd_agent.plist_exists() is False
    assert launchd_agent.get_keep_alive() is False


def test_launchd_agent_set_errors_helpfully_when_plist_missing(monkeypatch, tmp_path):
    import launchd_agent
    monkeypatch.setattr(launchd_agent, "PLIST_PATH", tmp_path / "missing.plist")
    r = launchd_agent.set_keep_alive(True)
    assert r["ok"] is False
    assert "Install INS" in r["message"]


def test_launchd_agent_roundtrips_keep_alive(monkeypatch, tmp_path):
    import launchd_agent, plistlib
    plist = tmp_path / "ka.plist"
    plistlib.dump({
        "Label": launchd_agent.LABEL,
        "ProgramArguments": ["/usr/bin/true"],
        "KeepAlive": False,
    }, plist.open("wb"))
    monkeypatch.setattr(launchd_agent, "PLIST_PATH", plist)
    # Stub launchctl so the test doesn't actually load anything.
    class Done:
        returncode = 0; stdout = ""; stderr = ""
    monkeypatch.setattr(launchd_agent.subprocess, "run", lambda *a, **kw: Done())
    assert launchd_agent.get_keep_alive() is False
    r = launchd_agent.set_keep_alive(True)
    assert r["ok"] is True
    assert launchd_agent.get_keep_alive() is True
    r = launchd_agent.set_keep_alive(False)
    assert r["ok"] is True
    assert launchd_agent.get_keep_alive() is False


def test_launchd_agent_set_preserves_program_arguments(monkeypatch, tmp_path):
    """The user's plist has paths to their venv python + app.py. The
    KeepAlive flip must not touch ProgramArguments."""
    import launchd_agent, plistlib
    plist = tmp_path / "preserve.plist"
    original_args = ["/Users/me/.netscan/.venv/bin/python3",
                     "/Users/me/.netscan/app.py"]
    plistlib.dump({
        "Label": launchd_agent.LABEL,
        "ProgramArguments": original_args,
        "KeepAlive": False,
        "RunAtLoad": True,
        "StandardOutPath": "/tmp/ins.log",
    }, plist.open("wb"))
    monkeypatch.setattr(launchd_agent, "PLIST_PATH", plist)
    class Done:
        returncode = 0; stdout = ""; stderr = ""
    monkeypatch.setattr(launchd_agent.subprocess, "run", lambda *a, **kw: Done())
    launchd_agent.set_keep_alive(True)
    with plist.open("rb") as fp:
        data = plistlib.load(fp)
    assert data["ProgramArguments"] == original_args
    assert data["RunAtLoad"] is True
    assert data["StandardOutPath"] == "/tmp/ins.log"
    assert data["KeepAlive"] is True


def test_launchd_agent_get_handles_dict_keep_alive(monkeypatch, tmp_path):
    """Hand-edited plists sometimes use the <dict> form of KeepAlive."""
    import launchd_agent, plistlib
    plist = tmp_path / "dict.plist"
    plistlib.dump({
        "Label": launchd_agent.LABEL,
        "ProgramArguments": ["/usr/bin/true"],
        "KeepAlive": {"SuccessfulExit": False},
    }, plist.open("wb"))
    monkeypatch.setattr(launchd_agent, "PLIST_PATH", plist)
    # Any truthy sub-value counts as "on".
    assert launchd_agent.get_keep_alive() is False  # SuccessfulExit=False is the only entry
    plistlib.dump({
        "Label": launchd_agent.LABEL,
        "ProgramArguments": ["/usr/bin/true"],
        "KeepAlive": {"NetworkState": True},
    }, plist.open("wb"))
    assert launchd_agent.get_keep_alive() is True


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


# ── dashboard Host gate (anti-DNS-rebinding) ────────────────────────────────

def test_host_check_accepts_local():
    import dashboard
    dashboard._Handler.allowed_hosts = {"127.0.0.1:8765", "localhost:8765"}
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.headers = {"Host": "localhost:8765"}
    assert h._host_ok()
    h.headers = {"Host": "127.0.0.1:8765"}
    assert h._host_ok()


def test_host_check_rejects_foreign():
    import dashboard
    dashboard._Handler.allowed_hosts = {"127.0.0.1:8765", "localhost:8765"}
    h = dashboard._Handler.__new__(dashboard._Handler)
    for bad in ("evil.com", "evil.com:8765", "localhost:8765.evil.com", "127.0.0.1", ""):
        h.headers = {"Host": bad}
        assert not h._host_ok(), bad
    h.headers = {}
    assert not h._host_ok()


# ── updater hardening ───────────────────────────────────────────────────────

def test_check_for_update_honors_optout(monkeypatch):
    import updater
    monkeypatch.setenv("INS_NO_UPDATE_CHECK", "1")
    with patch("updater.urllib.request.urlopen",
               side_effect=AssertionError("network must not be touched when opted out")):
        assert updater.check_for_update(current="2.0.0") is None


def test_check_for_update_skips_prerelease():
    import updater
    fake = MagicMock()
    fake.read.return_value = json.dumps({"tag_name": "v3.0.0-beta", "html_url": "x"}).encode()
    fake.__enter__ = lambda self: self
    fake.__exit__ = lambda *a: None
    with patch("updater.urllib.request.urlopen", return_value=fake):
        assert updater.check_for_update(current="2.0.0") is None


def test_version_tuple_strips_prerelease_suffix():
    from updater import _version_tuple
    assert _version_tuple("v2.6.0-beta") == (2, 6, 0)
    assert _version_tuple("2.6.0rc1") == (2, 6, 0)
    assert _version_tuple("2.5.0+build7") == (2, 5, 0)


def test_newer_is_length_insensitive():
    from updater import _newer
    assert _newer((2, 5, 1), (2, 5, 0)) is True
    assert _newer((2, 5), (2, 5, 0)) is False       # "2.5" is NOT older than "2.5.0"
    assert _newer((2, 6), (2, 5, 9)) is True


# ── store migrations & schema parity ────────────────────────────────────────

_PRE_MIGRATION_DEVICES_DDL = (
    "CREATE TABLE devices ("
    " mac TEXT PRIMARY KEY, first_seen REAL NOT NULL, last_seen REAL NOT NULL,"
    " seen_count INTEGER NOT NULL DEFAULT 1, last_ip TEXT, hostname TEXT,"
    " vendor TEXT, device_type TEXT, type_confidence REAL DEFAULT 0,"
    " fingerprint TEXT, ports TEXT)"
)


def test_store_applies_table_migration_on_old_db(tmp_path):
    import sqlite3, store
    con = sqlite3.connect(str(tmp_path / "ins.db"))
    con.execute(_PRE_MIGRATION_DEVICES_DDL)
    con.commit(); con.close()
    s = store.DeviceStore(data_dir=tmp_path)
    cols = {r["name"] for r in s._q("PRAGMA table_info(devices)")}
    assert "no_probe" in cols
    # Idempotent: re-opening doesn't raise and the column is still present.
    s2 = store.DeviceStore(data_dir=tmp_path)
    cols2 = {r["name"] for r in s2._q("PRAGMA table_info(devices)")}
    assert "no_probe" in cols2


def test_store_schema_matches_migrations(tmp_path):
    """A fresh _SCHEMA install and an old-schema + migrations upgrade must end
    with identical devices columns, or upgrading users miss new columns."""
    import sqlite3, store
    fresh = store.DeviceStore(data_dir=tmp_path / "fresh")
    fresh_cols = {r["name"] for r in fresh._q("PRAGMA table_info(devices)")}
    old_dir = tmp_path / "old"; old_dir.mkdir()
    con = sqlite3.connect(str(old_dir / "ins.db"))
    con.execute(_PRE_MIGRATION_DEVICES_DDL)
    con.commit(); con.close()
    migrated = store.DeviceStore(data_dir=old_dir)
    migrated_cols = {r["name"] for r in migrated._q("PRAGMA table_info(devices)")}
    assert fresh_cols == migrated_cols


def test_store_sightings_capped(tmp_path, monkeypatch):
    import store
    monkeypatch.setitem(store._MAX_ROWS, "sightings", 3)
    s = store.DeviceStore(data_dir=tmp_path)
    for i in range(6):
        s.touch({"mac": "AA:BB:CC:DD:EE:FF", "ip": f"10.0.0.{i}", "latency": 1.0})
    n = s._q("SELECT COUNT(*) AS n FROM sightings")[0]["n"]
    assert n == 3


def test_store_recent_scans_bounded(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    for i in range(10):
        s.record_scan(i, "Net")
    recent = s.recent_scans(limit=3)
    assert len(recent) == 3
    assert [r["count"] for r in recent] == [7, 8, 9]   # oldest-first within the window


def test_store_latest_health_includes_band(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.record_health(58, [{"weight": 35, "label": "rogue dhcp"}])
    snap = s.latest_health()
    assert snap["score"] == 58
    assert snap["band"] == "fair"
    assert snap["headline"]


# ── security rules: default creds & camera-HTTPS ────────────────────────────

def test_security_default_creds_flags_hikvision_with_web_panel():
    import security
    dev = {"vendor": "Hikvision Digital", "device_type": "camera",
           "ports": [80], "ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:01"}
    a = security.check_default_creds(dev)
    assert a is not None and a.severity == "warning" and "12345" in a.message
    assert security.check_default_creds({**dev, "ports": []}) is None


def test_security_camera_http_only_warns():
    import security
    dev = {"device_type": "camera", "ports": [80], "ip": "192.168.1.6",
           "mac": "AA:BB:CC:00:00:02"}
    a = security.check_admin_panel_for_camera(dev)
    assert a is not None and a.kind == "camera_no_https"
    assert security.check_admin_panel_for_camera({**dev, "ports": [80, 443]}) is None


# ── igd protocol whitelist ──────────────────────────────────────────────────

def test_igd_parse_mapping_whitelists_protocol():
    import igd
    def xml(proto):
        return ("<root><NewExternalPort>8443</NewExternalPort>"
                "<NewInternalClient>192.168.1.40</NewInternalClient>"
                "<NewInternalPort>443</NewInternalPort>"
                f"<NewProtocol>{proto}</NewProtocol>"
                "<NewEnabled>1</NewEnabled></root>").encode()
    assert igd._parse_mapping(xml("udp")).protocol == "UDP"
    assert igd._parse_mapping(xml("TCP")).protocol == "TCP"
    # Untrusted / markup-laden value is neutralized to TCP, never rendered raw.
    assert igd._parse_mapping(xml('x&quot;&gt;y')).protocol == "TCP"


# ── health unknown-device penalty scales with count ─────────────────────────

def test_health_unknown_penalty_scales_with_count():
    import health
    def devs(n):
        return [{"is_known": False, "me": False, "ports": [], "vendor": "",
                 "device_type": "unknown", "ip": f"10.0.0.{i}"} for i in range(n)]
    one  = health.compute(devices=devs(1),  unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    five = health.compute(devices=devs(5),  unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    fifty = health.compute(devices=devs(50), unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    assert five["score"] < one["score"]        # scales with count
    assert fifty["score"] == five["score"]     # capped at the soft cap (20)


# ── scanner: vendor memoization + randomized-MAC handling + enrich caching ──

def test_is_locally_administered():
    from scanner import _is_locally_administered
    assert _is_locally_administered("F2:18:98:AA:BB:CC")     # x2 -> LA bit set
    assert _is_locally_administered("DE:AD:BE:EF:00:01")     # DE -> LA bit set
    assert not _is_locally_administered("3C:5A:B4:00:00:00") # universally administered
    assert not _is_locally_administered("AC:DE:48:00:11:22")


def test_get_vendor_skips_randomized_and_private(monkeypatch):
    import scanner
    scanner.clear_caches()
    calls = {"n": 0}
    monkeypatch.setattr(scanner._mac_lookup, "lookup",
                        lambda m: (calls.__setitem__("n", calls["n"] + 1) or "ShouldNotBeUsed"))
    # Randomized (locally-administered) MAC: no OUI lookup at all.
    assert scanner.get_vendor("F2:18:98:AA:BB:CC") == "—"
    assert calls["n"] == 0
    # IEEE "Private" placeholder maps to the em-dash, not a fake vendor name.
    scanner.clear_caches()
    monkeypatch.setattr(scanner._mac_lookup, "lookup", lambda m: "Private")
    assert scanner.get_vendor("3C:5A:B4:00:00:00") == "—"


def test_get_vendor_memoizes(monkeypatch):
    import scanner
    scanner.clear_caches()
    calls = {"n": 0}
    monkeypatch.setattr(scanner._mac_lookup, "lookup",
                        lambda m: (calls.__setitem__("n", calls["n"] + 1) or "Acme"))
    assert scanner.get_vendor("3C:5A:B4:00:00:00") == "Acme"
    assert scanner.get_vendor("3C:5A:B4:00:00:00") == "Acme"
    assert calls["n"] == 1   # second lookup served from the memo


def test_enrich_caches_hostname_and_latency(monkeypatch):
    import scanner
    scanner.clear_caches()
    hcalls = {"n": 0}; pcalls = {"n": 0}
    monkeypatch.setattr(scanner, "get_hostname",
                        lambda ip: (hcalls.__setitem__("n", hcalls["n"] + 1) or f"h-{ip}"))
    monkeypatch.setattr(scanner, "ping_latency",
                        lambda ip, iface=None: (pcalls.__setitem__("n", pcalls["n"] + 1) or 1.0))
    monkeypatch.setattr(scanner, "get_vendor", lambda mac: "V")
    devs = [{"ip": "10.0.0.5", "mac": "AA:BB:CC:00:00:01"}]
    r1 = scanner.enrich([dict(d) for d in devs], "10.0.0.9")
    r2 = scanner.enrich([dict(d) for d in devs], "10.0.0.9")   # within TTL -> cached
    assert hcalls["n"] == 1 and pcalls["n"] == 1               # resolved once, reused
    assert r1[0]["hostname"] == "h-10.0.0.5" == r2[0]["hostname"]
    assert r1[0]["latency"] == 1.0
    assert r1[0]["me"] is False
    scanner.clear_caches()


def test_touch_uses_known_map_without_querying(tmp_path):
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.add_known("AA:BB:CC:00:00:01", "My Phone")
    known = s.known
    out = s.touch({"mac": "AA:BB:CC:00:00:01", "ip": "10.0.0.5",
                   "vendor": "Acme", "hostname": "x"}, known=known)
    assert out["is_known"] is True and out["known_name"] == "My Phone"
    out2 = s.touch({"mac": "FF:EE:DD:00:00:09", "ip": "10.0.0.6",
                    "vendor": "—", "hostname": "—"}, known=known)
    assert out2["is_known"] is False and out2["known_name"] == ""


def test_clear_caches_forces_fresh_resolution_after_roaming(monkeypatch):
    """A roamed network can reuse the same subnet; clearing the IP-keyed caches
    must let a colliding IP re-resolve to the new network's device."""
    import scanner
    scanner.clear_caches()
    names = iter(["old-network-device", "new-network-device"])
    monkeypatch.setattr(scanner, "get_hostname", lambda ip: next(names))
    monkeypatch.setattr(scanner, "ping_latency", lambda ip, iface=None: 1.0)
    monkeypatch.setattr(scanner, "get_vendor", lambda mac: "V")
    dev = [{"ip": "192.168.1.10", "mac": "AA:BB:CC:00:00:01"}]
    r1 = scanner.enrich([dict(d) for d in dev], "192.168.1.1")
    assert r1[0]["hostname"] == "old-network-device"
    r2 = scanner.enrich([dict(d) for d in dev], "192.168.1.1")   # within TTL -> cached
    assert r2[0]["hostname"] == "old-network-device"
    scanner.clear_caches()                                       # simulate network change
    r3 = scanner.enrich([dict(d) for d in dev], "192.168.1.1")
    assert r3[0]["hostname"] == "new-network-device"
    scanner.clear_caches()


# ── scanner: graceful no-network + broadcast-name priority ──────────────────

def test_get_wifi_info_raises_no_network_instead_of_exiting(monkeypatch):
    import pytest
    import scanner
    monkeypatch.setattr(scanner, "_iface_inet", lambda iface: None)
    monkeypatch.setattr(scanner, "_detect_wifi_iface", lambda: "en9")
    scanner._wifi_iface_cache = None
    with pytest.raises(scanner.NoNetworkError):
        scanner.get_wifi_info()


def test_best_fingerprint_prefers_dhcp_hostname():
    from scanner import best_fingerprint
    # DHCP option 12 (the device's broadcast name) wins over everything else.
    assert best_fingerprint({"dhcp_hostname": "Johns-iPhone",
                             "mdns": "x.local", "http_title": "Login"}) == "Johns-iPhone"
    assert best_fingerprint({"mdns": "living-room.local"}) == "living-room.local"
    assert best_fingerprint({}) == ""


def test_sniffer_captures_dhcp_hostname():
    import pytest
    try:
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dhcp import BOOTP, DHCP
    except ImportError:
        pytest.skip("scapy not installed")
    import sniffer
    pkt = (Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") /
           IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=bytes.fromhex("aabbccddeeff")) /
           DHCP(options=[("message-type", "request"),
                         ("hostname", b"Johns-iPhone"),
                         ("param_req_list", [1, 3, 6]), "end"]))
    pkt = Ether(bytes(pkt))   # re-parse from the wire so options decode as ints

    class FakeStore:
        def __init__(self): self.merged = {}
        def merge_fingerprint(self, mac, hints): self.merged.setdefault(mac, {}).update(hints)
        def record_dns_query(self, *a): pass
        def add_alert(self, **k): return 1

    fs = FakeStore()
    sniffer._handle_packet(pkt, local_mac="11:22:33:44:55:66", threat_list=None, store=fs)
    assert fs.merged.get("AA:BB:CC:DD:EE:FF", {}).get("dhcp_hostname") == "Johns-iPhone"


# ── scanner: interface-bound scan + robust fallback (VPN fix) ───────────────

def test_ping_argv_binds_to_iface():
    from scanner import _ping_argv
    assert _ping_argv("10.0.0.5", "en0") == ["ping", "-c", "1", "-W", "500", "-b", "en0", "10.0.0.5"]
    # No iface => byte-identical to the original argv (keeps existing tests green).
    assert _ping_argv("10.0.0.5", None) == ["ping", "-c", "1", "-W", "500", "10.0.0.5"]


def test_arp_scan_binds_to_iface(monkeypatch):
    import scanner
    captured = {}
    monkeypatch.setattr(scanner, "srp", lambda pkt, **kw: (captured.update(kw), ([], []))[1])
    scanner.arp_scan("192.168.50.0/24", timeout=3, iface="en0")
    assert captured.get("iface") == "en0"   # ARP sweep is bound to the Wi-Fi iface


def test_do_scan_falls_back_on_arp_error_and_still_merges_mdns(monkeypatch):
    import scanner
    def boom(*a, **k):
        raise RuntimeError("BIOCSETIF failed on utun4")
    monkeypatch.setattr(scanner, "arp_scan", boom)
    monkeypatch.setattr(scanner, "fallback_scan",
                        lambda network, quiet=False, iface=None: [{"ip": "192.168.50.2", "mac": "AA:BB:CC:00:00:02"}])
    monkeypatch.setattr(scanner, "_mdns_browse", lambda iface_ip=None, timeout=2.0: ["192.168.50.9"])
    monkeypatch.setattr(scanner, "_arp_resolve",
                        lambda ips, iface=None: [{"ip": "192.168.50.9", "mac": "AA:BB:CC:00:00:09"}])
    devices, used_fb = scanner.do_scan("192.168.50.0/24", 3, False, iface="en0")
    macs = {d["mac"] for d in devices}
    assert used_fb is True
    assert "AA:BB:CC:00:00:02" in macs            # ping-sweep fallback ran (no re-raise)
    assert "AA:BB:CC:00:00:09" in macs            # mDNS merge still ran after fallback


def test_do_scan_falls_back_on_empty_arp(monkeypatch):
    import scanner
    monkeypatch.setattr(scanner, "arp_scan", lambda *a, **k: [])
    calls = {"fb": 0}
    def fake_fb(network, quiet=False, iface=None):
        calls["fb"] += 1
        return [{"ip": "192.168.50.3", "mac": "AA:BB:CC:00:00:03"}]
    monkeypatch.setattr(scanner, "fallback_scan", fake_fb)
    monkeypatch.setattr(scanner, "_mdns_browse", lambda **k: [])
    devices, used_fb = scanner.do_scan("192.168.50.0/24", 3, False, iface="en0")
    assert used_fb is True and calls["fb"] == 1
    assert devices and devices[0]["mac"] == "AA:BB:CC:00:00:03"


def test_log_scan_error_rate_limited(capsys):
    import scanner
    scanner._last_scan_log.clear()
    scanner._log_scan_error_once("ARP scan failed (BIOCSETIF failed on utun4); using ping sweep")
    scanner._log_scan_error_once("ARP scan failed (a different detail); using ping sweep")
    assert capsys.readouterr().err.count("[scan]") == 1   # same error class logged once
    scanner._last_scan_log.clear()


# ── audit-round regressions (v2.4.16) ───────────────────────────────────────

def test_touch_after_sniffer_stub_is_still_new(tmp_path):
    """A sniffer-created stub row (seen_count=0) must NOT suppress the
    new-device alert: the first real touch should report _is_new=True."""
    import store
    s = store.DeviceStore(data_dir=tmp_path)
    s.merge_fingerprint("AA:BB:CC:00:00:01", {"dhcp_hostname": "Johns-iPhone"})  # stub, seen_count=0
    out = s.touch({"mac": "AA:BB:CC:00:00:01", "ip": "10.0.0.5",
                   "vendor": "Apple", "hostname": "—"})
    assert out["_is_new"] is True
    # The very next touch is no longer new.
    out2 = s.touch({"mac": "AA:BB:CC:00:00:01", "ip": "10.0.0.5",
                    "vendor": "Apple", "hostname": "—"})
    assert out2["_is_new"] is False


def test_arp_anomalies_ignores_sequential_dhcp_handoff(tmp_path):
    """A normal lease handoff (old MAC stopped being seen long ago, new MAC
    active now) must NOT raise a critical ARP-spoof anomaly; only concurrent
    MACs should."""
    import store, detect, time
    s = store.DeviceStore(data_dir=tmp_path)
    now = time.time()
    # Old lease holder last seen 20 min ago; new holder seen now.
    s._db.execute("INSERT INTO sightings(mac,ip,ts,latency_ms) VALUES(?,?,?,?)",
                  ("AA:AA:AA:AA:AA:AA", "10.0.0.5", now - 1200, None))
    s._db.execute("INSERT INTO sightings(mac,ip,ts,latency_ms) VALUES(?,?,?,?)",
                  ("BB:BB:BB:BB:BB:BB", "10.0.0.5", now, None))
    assert not any(a.ip == "10.0.0.5" for a in detect.arp_anomalies(s))
    # But two MACs seen concurrently (both now) IS flagged.
    s._db.execute("INSERT INTO sightings(mac,ip,ts,latency_ms) VALUES(?,?,?,?)",
                  ("CC:CC:CC:CC:CC:CC", "10.0.0.9", now, None))
    s._db.execute("INSERT INTO sightings(mac,ip,ts,latency_ms) VALUES(?,?,?,?)",
                  ("DD:DD:DD:DD:DD:DD", "10.0.0.9", now, None))
    assert any(a.ip == "10.0.0.9" for a in detect.arp_anomalies(s))


def test_do_scan_does_not_latch_into_fallback(monkeypatch):
    """use_fallback is a soft hint: do_scan must still attempt ARP even when
    told to fall back, so it auto-recovers after a transient miss."""
    import scanner
    monkeypatch.setattr(scanner, "arp_scan",
                        lambda *a, **k: [{"ip": "10.0.0.5", "mac": "AA:BB:CC:00:00:05"}])
    monkeypatch.setattr(scanner, "_mdns_browse", lambda **k: [])
    devices, used_fb = scanner.do_scan("10.0.0.0/24", 2, True, iface="en0")  # hint=True
    assert used_fb is False and len(devices) == 1   # ARP was tried despite the hint


def test_get_backend_tolerates_bad_router_ints(tmp_path):
    import store, routerctl
    s = store.DeviceStore(data_dir=tmp_path)
    for k, v in {"router_kind": "openwrt", "router_host": "10.0.0.1",
                 "router_user": "root", "router_ssh_port": "22a",
                 "router_iface": "x"}.items():
        s.set_setting(k, v)
    b = routerctl.get_backend(s)            # must not raise ValueError
    assert b.ssh_port == 22 and b.iface_idx == 0


# ── regression: risky-port detection is actually wired to the scanner ────────

def test_probe_ports_superset_of_risky_ports():
    """The scanner must probe every port the security rules care about, or the
    'risky protocol reachable' alert and its health penalties can never fire."""
    import scanner, security
    missing = set(security._RISKY_PORTS) - set(scanner.PROBE_PORTS)
    assert not missing, f"risky ports never scanned: {sorted(missing)}"


# ── classifier keyword fixes ─────────────────────────────────────────────────

def test_classify_switch_hostname_is_not_a_console():
    import classify
    # A network switch / "light switch" hostname must not classify as a console.
    dtype, _ = classify.classify(hostname="core-switch")
    assert dtype != "console"
    # A real Nintendo Switch still classifies via the "nintendo" token.
    dtype, _ = classify.classify(fingerprint="Nintendo Switch")
    assert dtype == "console"


def test_classify_name_ending_in_nas_is_not_a_nas():
    import classify
    assert classify.classify(hostname="Jonas-PC")[0] != "nas"
    assert classify.classify(hostname="office-nas")[0] == "nas"
    assert classify.classify(hostname="mynas")[0] == "nas"      # concatenated prefix still matches


# ── classifier: DHCP option-55 fingerprinting ────────────────────────────────

def test_classify_dhcp55_exact_ios():
    import classify
    hints = {"dhcp_55": "1,121,3,6,15,119,252"}
    dtype, conf = classify.classify(hints=hints)
    assert dtype == "phone" and conf >= 0.85
    assert classify.dhcp_vendor(hints) == "Apple"
    assert classify.dhcp_label(hints) == "iPhone / iPad"


def test_classify_dhcp55_feature_fallback_windows():
    import classify
    # A PRL that isn't an exact signature but carries the Windows feature set.
    hints = {"dhcp_55": "1,2,3,6,15,44,46,47,121,249,252,99"}
    dtype, conf = classify.classify(hints=hints)
    assert dtype == "computer" and 0.6 <= conf < 0.85


def test_classify_fingerprint_beats_dhcp55():
    import classify
    # An explicit fingerprint keyword wins over a conflicting DHCP signature.
    dtype, _ = classify.classify(fingerprint="Apple TV",
                                 hints={"dhcp_55": "1,3,6,15,26,28,51,58,59,43"})
    assert dtype == "tv"


def test_classify_dhcp55_unknown_returns_none():
    import classify
    assert classify._match_dhcp({"dhcp_55": "255,254,253"}) is None


# ── security: full risky-port severity table is honored ──────────────────────

def test_security_risky_ports_match_table_severity():
    import security
    for port, (sev, _proto, _why) in security._RISKY_PORTS.items():
        alerts = security.check_risky_ports({"mac": "AA:BB:CC:DD:EE:FF",
                                             "ip": "10.0.0.9"}, [port])
        assert len(alerts) == 1
        assert alerts[0].severity == sev, f"port {port} severity drifted"


def test_security_camera_http_only_is_info_severity():
    import security
    a = security.check_admin_panel_for_camera(
        {"device_type": "camera", "ports": [80], "mac": "AA:BB:CC:DD:EE:FF",
         "ip": "10.0.0.9"})
    assert a is not None and a.kind == "camera_no_https" and a.severity == "info"


# ── health: spoofing penalties are reachable + port penalties derived ────────

def test_health_penalizes_vendor_change_alert():
    import health
    base = health.compute(devices=[], unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    with_spoof = health.compute(
        devices=[], wan_mappings=[], dhcp_servers=[],
        unack_alerts=[{"kind": "vendor_changed", "severity": "critical"}])
    # The dedicated vendor_changed penalty (25) must exceed the generic
    # unack_critical hit (8) that the alert would otherwise contribute.
    assert base["score"] - with_spoof["score"] >= 25


def test_health_penalizes_arp_flap_alert():
    import health
    r = health.compute(
        devices=[], wan_mappings=[], dhcp_servers=[],
        unack_alerts=[{"kind": "arp_flap_10.0.0.5", "severity": "critical"}])
    assert r["score"] <= 100 - 25


def test_health_port_penalties_follow_risky_port_severity():
    import health
    telnet = health.compute(
        devices=[{"ip": "10.0.0.9", "ports": [23], "is_known": False}],
        unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    rdp = health.compute(
        devices=[{"ip": "10.0.0.9", "ports": [3389], "is_known": False}],
        unack_alerts=[], wan_mappings=[], dhcp_servers=[])
    # Telnet is critical, RDP is warning — telnet must cost at least as much.
    telnet_hit = sum(x["weight"] for x in telnet["reasons"] if "risky_port" in x.get("key", ""))
    rdp_hit    = sum(x["weight"] for x in rdp["reasons"] if "risky_port" in x.get("key", ""))
    assert telnet_hit >= rdp_hit > 0


def test_health_every_penalty_key_is_reachable():
    """Guard against a re-introduced dead _PENALTIES entry: every non-zero key
    must be produced by some compute() input."""
    import health
    reachable = set()
    # Drive each condition and collect the keys compute() emits.
    scenarios = [
        dict(devices=[], wan_mappings=[], dhcp_servers=[object(), object()],
             unack_alerts=[]),
        dict(devices=[{"ip": "1", "device_type": "camera", "ports": [80]}],
             wan_mappings=[{"internal_ip": "1", "external_port": 8080}],
             dhcp_servers=[], unack_alerts=[]),
        dict(devices=[{"ip": "1", "ports": [23]}], wan_mappings=[], dhcp_servers=[],
             unack_alerts=[{"kind": "vendor_changed", "severity": "critical"},
                           {"kind": "arp_flap_x", "severity": "critical"},
                           {"kind": "other", "severity": "critical"},
                           {"kind": "w", "severity": "warning"}]),
        dict(devices=[{"ip": "1", "vendor": "Hikvision", "ports": [80]},
                      {"ip": "2", "is_known": False}],
             wan_mappings=[], dhcp_servers=[], unack_alerts=[]),
        dict(devices=[{"ip": "1", "device_type": "camera", "ports": [80]}],
             wan_mappings=[], dhcp_servers=[], unack_alerts=[]),
        # A warning-severity risky port + a non-camera WAN exposure.
        dict(devices=[{"ip": "9", "ports": [3389]}],
             wan_mappings=[{"internal_ip": "9", "external_port": 3389}],
             dhcp_servers=[], unack_alerts=[]),
    ]
    for sc in scenarios:
        for r in health.compute(**sc)["reasons"]:
            reachable.add(r.get("key"))
    nonzero = {k for k, (per, _cap) in health._PENALTIES.items() if per > 0}
    assert nonzero <= reachable, f"unreachable penalty keys: {nonzero - reachable}"


# ── routerctl: MAC validation + OpenWrt add_list-per-MAC ─────────────────────

def test_routerctl_validate_mac():
    import routerctl, pytest
    assert routerctl.validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    for bad in ("", "not-a-mac", "AA:BB:CC:DD:EE", "aa:bb:cc:dd:ee:ff; reboot"):
        with pytest.raises(routerctl.RouterError):
            routerctl.validate_mac(bad)


def test_routerctl_openwrt_block_emits_one_add_list_per_mac():
    import routerctl
    b = routerctl.OpenWrtBackend("10.0.0.1", "root", None)
    scripts = []
    b._ssh = lambda cmd: scripts.append(cmd) or ""
    b._read_maclist = lambda: ["11:22:33:44:55:66"]     # one already blocked
    b.block("AA:BB:CC:DD:EE:FF")                          # add a second
    script = scripts[-1]
    assert script.count("add_list") == 2                 # one per MAC, not one joined
    # No single add_list token may contain two MACs.
    import re
    for m in re.findall(r"add_list \S+\.maclist=(\S+)", script):
        assert m.count(":") == 5


def test_routerctl_openwrt_block_rejects_bad_mac():
    import routerctl, pytest
    b = routerctl.OpenWrtBackend("10.0.0.1", "root", None)
    b._ssh = lambda cmd: ""
    with pytest.raises(routerctl.RouterError):
        b.block("evil'; reboot; '")


# ── igd: SSRF guard on LOCATION / control URLs ───────────────────────────────

def test_igd_is_lan_url_accepts_private_http():
    import igd
    assert igd._is_lan_url("http://192.168.1.1:5000/desc.xml")
    assert igd._is_lan_url("http://10.0.0.1/ctrl")


def test_igd_is_lan_url_rejects_public_and_nonhttp():
    import igd
    assert not igd._is_lan_url("http://8.8.8.8/desc.xml")            # public IP
    assert not igd._is_lan_url("http://evil.example/desc.xml")      # name, not IP
    assert not igd._is_lan_url("file:///etc/passwd")               # non-http scheme
    assert not igd._is_lan_url("ftp://192.168.1.1/")               # non-http scheme
    assert not igd._is_lan_url("http://169.254.169.254/latest/")   # link-local metadata


# ── store: atomic same-day alert dedup + device pruning ──────────────────────

def test_store_add_alert_if_new_today_dedups(tmp_path):
    s = _fresh_store(tmp_path)
    first = s.add_alert_if_new_today("new_device", "info", "t", "m", mac="AA:BB")
    dup   = s.add_alert_if_new_today("new_device", "info", "t", "m", mac="AA:BB")
    other = s.add_alert_if_new_today("new_device", "info", "t", "m", mac="CC:DD")
    assert first is not None and dup is None and other is not None
    assert len(s.alerts()) == 2


def test_store_prune_old_devices_keeps_known(tmp_path):
    import time
    s = _fresh_store(tmp_path)
    s.touch({"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.5", "hostname": "h", "vendor": "v"})
    s.touch({"mac": "11:22:33:44:55:66", "ip": "10.0.0.6", "hostname": "h", "vendor": "v"})
    s.add_known("11:22:33:44:55:66", "My Laptop")
    # Age both rows well past the retention window.
    old = time.time() - 200 * 86400
    s._db.execute("UPDATE devices SET last_seen=?", (old,))
    removed = s.prune_old_devices(max_age_days=90)
    assert removed == 1
    macs = set(s.all_seen)
    assert "11:22:33:44:55:66" in macs        # Known device kept
    assert "AA:BB:CC:DD:EE:FF" not in macs     # stale non-Known pruned


def test_store_cap_table_keeps_newest(tmp_path):
    import store
    s = _fresh_store(tmp_path)
    s._db.execute("BEGIN")
    for i in range(10):
        s._db.execute("INSERT INTO scans(ts,count,ssid) VALUES(?,?,?)", (i, i, "x"))
    s._db.execute("COMMIT")
    with patch.dict(store._MAX_ROWS, {"scans": 3}):
        with s._tx() as db:
            s._cap_table(db, "scans")
    counts = sorted(r["count"] for r in s._q("SELECT count FROM scans"))
    assert counts == [7, 8, 9]      # newest 3 kept


# ── threats: hot-path reload throttle ────────────────────────────────────────

def test_threats_matches_is_throttled(tmp_path, monkeypatch):
    import threats
    p = tmp_path / "threats.txt"
    p.write_text("bad.example\n")
    tl = threats.ThreatList(p)
    calls = {"n": 0}
    real_load = tl._load_locked
    monkeypatch.setattr(tl, "_load_locked", lambda: (calls.__setitem__("n", calls["n"] + 1), real_load())[1])
    for _ in range(50):
        tl.matches("foo.example")
    assert calls["n"] <= 1          # stat()/reload throttled, not once per call


# ── store.run_hook shell-injection sanitizer ─────────────────────────────────

def test_store_run_hook_strips_shell_metacharacters(tmp_path, monkeypatch):
    import store
    s = _fresh_store(tmp_path)
    s.set_hook_script("true")
    captured = {}

    class FakePopen:
        def __init__(self, *a, **k):
            captured["env"] = k.get("env", {})

    monkeypatch.setattr(store.subprocess, "Popen", FakePopen)
    s.run_hook({
        "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": "ACME; rm -rf ~", "hostname": "$(reboot)`id`",
        "device_type": "camera",
    }, ssid="net|evil & echo")
    env = captured["env"]
    for key in ("DEVICE_VENDOR", "DEVICE_HOSTNAME", "SSID"):
        v = env[key]
        assert not any(c in v for c in "$`;|&()'\"\\<>"), f"{key} leaked metachar: {v!r}"
        assert len(v) <= 128


# ── dashboard: webhook URL scheme validation ─────────────────────────────────

def test_webhook_add_rejects_non_http_scheme():
    import dashboard, io
    import json as _json
    calls = []

    class FakeStore:
        def add_webhook(self, **k):
            calls.append(k)

    dashboard._Handler.allowed_hosts   = {"127.0.0.1:8765"}
    dashboard._Handler.allowed_origins = {"http://127.0.0.1:8765"}
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.store = FakeStore()
    h.on_known_change = None
    h.client_address = ("127.0.0.1", 9999)   # loopback → normal Host/Origin flow
    h.command = "POST"
    responses = []
    h._send = lambda code, ctype, b: responses.append((code, b))
    h._ok   = lambda: responses.append((200, b'{"ok":true}'))

    def run(body):
        raw = _json.dumps(body).encode()
        h.headers = {"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765",
                     "Content-Length": str(len(raw))}
        h.rfile = io.BytesIO(raw)
        h.path = "/api/webhooks/add"
        responses.clear()
        h.do_POST()

    run({"url": "file:///etc/passwd"})
    assert responses[-1][0] == 400          # rejected
    assert not calls                        # store never touched

    run({"url": "https://example.com/hook", "label": "x", "min_severity": "info"})
    assert calls and calls[-1]["url"] == "https://example.com/hook"


def test_igd_redirect_handler_blocks_off_lan_hop():
    """The IGD opener must re-validate redirect targets, not just the first URL —
    otherwise a LAN responder can 302 INS to a metadata/off-LAN host (SSRF)."""
    import igd, pytest
    h = igd._LANRedirectHandler()
    # A redirect to a public / metadata host is refused.
    with pytest.raises(igd.urllib.error.HTTPError):
        h.redirect_request(None, None, 302, "Found", {},
                           "http://169.254.169.254/latest/")
    with pytest.raises(igd.urllib.error.HTTPError):
        h.redirect_request(None, None, 302, "Found", {}, "http://8.8.8.8/x")


# ── remote access: LAN auth gate (dashboard) ─────────────────────────────────

def test_dashboard_is_loopback():
    import dashboard
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.client_address = ("127.0.0.1", 5)
    assert h._is_loopback()
    h.client_address = ("::1", 5)
    assert h._is_loopback()
    h.client_address = ("192.168.1.50", 5)
    assert not h._is_loopback()


def test_dashboard_lan_token_constant_time_auth():
    import dashboard
    h = dashboard._Handler.__new__(dashboard._Handler)
    dashboard._Handler.lan_token = "s3cr3t-token"
    h.headers = {"Authorization": "Bearer s3cr3t-token"}
    assert h._lan_authorized()
    h.headers = {"Authorization": "Bearer nope"}
    assert not h._lan_authorized()
    h.headers = {}
    assert not h._lan_authorized()
    dashboard._Handler.lan_token = None            # no token configured → deny all
    h.headers = {"Authorization": "Bearer s3cr3t-token"}
    assert not h._lan_authorized()


def _lan_handler(method, path, headers, *, enabled=True, token="tok"):
    import dashboard
    dashboard._Handler.lan_enabled = enabled
    dashboard._Handler.lan_token   = token
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.command = method
    h.path = path
    h.headers = headers
    h.client_address = ("192.168.1.50", 9999)      # a LAN client
    sent = []
    h._send        = lambda code, ctype, b: sent.append(code)
    h.send_response = lambda code: sent.append(code)
    h.send_header   = lambda *a, **k: None
    h.end_headers   = lambda: None
    return h, sent


def test_dashboard_lan_gate_allows_authed_read():
    h, sent = _lan_handler("GET", "/api/state", {"Authorization": "Bearer tok"})
    assert h._lan_gate() is True and sent == []


def test_dashboard_lan_gate_blocks_post_even_with_token():
    h, sent = _lan_handler("POST", "/api/known/add", {"Authorization": "Bearer tok"})
    assert h._lan_gate() is False and 403 in sent      # read-only over LAN


def test_dashboard_lan_gate_blocks_non_allowlisted_get():
    # /api/remote carries the token — must never be reachable from the LAN.
    h, sent = _lan_handler("GET", "/api/remote", {"Authorization": "Bearer tok"})
    assert h._lan_gate() is False and 403 in sent
    h, sent = _lan_handler("GET", "/api/webhooks", {"Authorization": "Bearer tok"})
    assert h._lan_gate() is False and 403 in sent


def test_dashboard_lan_gate_requires_token():
    h, sent = _lan_handler("GET", "/api/state", {})
    assert h._lan_gate() is False and 401 in sent


def test_dashboard_lan_gate_blocked_when_disabled():
    h, sent = _lan_handler("GET", "/api/state", {"Authorization": "Bearer tok"}, enabled=False)
    assert h._lan_gate() is False and 403 in sent
    # Reset so we don't leave LAN access globally enabled for other tests.
    import dashboard
    dashboard._Handler.lan_enabled = False
    dashboard._Handler.lan_token = None


# ── bonjour TXT encoding ─────────────────────────────────────────────────────

def test_bonjour_encode_txt_no_op_without_foundation():
    import bonjour
    if bonjour._HAVE_FOUNDATION:
        blob = bonjour._encode_txt({"path": "/", "v": "1"})
        assert blob is not None            # produced an NSData TXT blob
    else:
        assert bonjour._encode_txt({"path": "/"}) is None


def test_bonjour_publish_no_op_without_name():
    import bonjour
    assert bonjour.publish("", port=8765) is False    # empty name never publishes
