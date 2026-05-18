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
    assert not _is_unicast("192.168.1.10", "FF:FF:FF:FF:FF:FF")  # broadcast MAC
    assert not _is_unicast("224.0.0.1", "AA:BB:CC:DD:EE:FF")    # multicast IP
    assert not _is_unicast("239.255.0.1", "AA:BB:CC:DD:EE:FF")  # multicast IP


def test_probe_ports_excludes_udp():
    """SSDP (1900) and mDNS (5353) are UDP — not valid for TCP connect probes."""
    from scanner import PROBE_PORTS
    assert 1900 not in PROBE_PORTS
    assert 5353 not in PROBE_PORTS


# ── store ───────────────────────────────────────────────────────────────────

def test_store_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr("store._DATA", tmp_path)
    import store as store_mod
    s = store_mod.DeviceStore()

    s.touch({"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
             "hostname": "host.local", "vendor": "Acme"})
    s.update_ports("AA:BB:CC:DD:EE:FF", [22, 80])
    s.update_fingerprint("AA:BB:CC:DD:EE:FF", {"mdns": "host.local"})
    s._flush_now()

    seen = json.loads((tmp_path / "seen.json").read_text())
    assert seen["AA:BB:CC:DD:EE:FF"]["ip"] == "10.0.0.5"
    assert seen["AA:BB:CC:DD:EE:FF"]["ports"] == [22, 80]
    assert seen["AA:BB:CC:DD:EE:FF"]["fingerprint"] == {"mdns": "host.local"}

    s.add_known("AA:BB:CC:DD:EE:FF", "my-laptop")
    assert s.is_known("AA:BB:CC:DD:EE:FF")
    assert s.known_name("AA:BB:CC:DD:EE:FF") == "my-laptop"
    assert json.loads((tmp_path / "known.json").read_text())["AA:BB:CC:DD:EE:FF"]["name"] == "my-laptop"

    s.remove_known("AA:BB:CC:DD:EE:FF")
    assert not s.is_known("AA:BB:CC:DD:EE:FF")


# ── dashboard origin check ─────────────────────────────────────────────────

def test_origin_check_accepts_local():
    import dashboard
    dashboard._Handler.allowed_origins = {
        "http://127.0.0.1:8765",
        "http://localhost:8765",
    }

    # Build a faux handler instance without invoking BaseHTTPRequestHandler.__init__
    h = dashboard._Handler.__new__(dashboard._Handler)
    h.headers = {"Origin": "http://127.0.0.1:8765"}
    assert h._origin_ok()

    h.headers = {"Origin": "http://localhost:8765"}
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

    h.headers = {}  # missing Origin/Referer
    assert not h._origin_ok()
