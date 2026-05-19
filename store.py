"""Device registry — SQLite persistence for allowlist, sightings, scans, hooks, alerts."""

import json
import os
import subprocess
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

# When running as a py2app bundle __file__ is inside the read-only .app;
# use Application Support so data survives updates.
if getattr(sys, "frozen", False):
    _DATA = Path.home() / "Library" / "Application Support" / "InglNetScan"
else:
    _DATA = Path(__file__).parent / "data"

_DB_NAME = "ins.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac          TEXT PRIMARY KEY,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    seen_count   INTEGER NOT NULL DEFAULT 1,
    last_ip      TEXT,
    hostname     TEXT,
    vendor       TEXT,
    device_type  TEXT,
    type_confidence REAL DEFAULT 0,
    fingerprint  TEXT,    -- JSON blob of probe hints
    ports        TEXT,    -- JSON array of open port ints
    no_probe     INTEGER NOT NULL DEFAULT 0  -- user marked: don't actively probe
);

CREATE TABLE IF NOT EXISTS known (
    mac    TEXT PRIMARY KEY,
    name   TEXT NOT NULL DEFAULT '',
    added  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sightings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac         TEXT NOT NULL,
    ip          TEXT,
    ts          REAL NOT NULL,
    latency_ms  REAL
);
CREATE INDEX IF NOT EXISTS idx_sightings_mac_ts ON sightings(mac, ts);

CREATE TABLE IF NOT EXISTS scans (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL NOT NULL,
    count  INTEGER NOT NULL,
    ssid   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    mac           TEXT,
    kind          TEXT NOT NULL,        -- new_device, vendor_changed, insecure_port, etc.
    severity      TEXT NOT NULL,        -- info / warning / critical
    title         TEXT NOT NULL,
    message       TEXT NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_unack ON alerts(acknowledged, ts DESC);

CREATE TABLE IF NOT EXISTS webhooks (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    label    TEXT NOT NULL DEFAULT '',
    url      TEXT NOT NULL,
    min_severity TEXT NOT NULL DEFAULT 'info',  -- info/warning/critical
    enabled  INTEGER NOT NULL DEFAULT 1,
    added    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dhcp_servers (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL NOT NULL,
    ip     TEXT NOT NULL,
    mac    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dhcp_ts ON dhcp_servers(ts DESC);

CREATE TABLE IF NOT EXISTS wan_mappings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    internal_ip  TEXT NOT NULL,
    internal_port INTEGER NOT NULL,
    external_port INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    description  TEXT
);
CREATE INDEX IF NOT EXISTS idx_wan_ts ON wan_mappings(ts DESC);

CREATE TABLE IF NOT EXISTS health_snapshots (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    score    INTEGER NOT NULL,
    reasons  TEXT NOT NULL   -- JSON array of {weight, label}
);
CREATE INDEX IF NOT EXISTS idx_health_ts ON health_snapshots(ts DESC);

CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    mac        TEXT NOT NULL,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bw_mac_ts ON bandwidth_samples(mac, ts);
CREATE INDEX IF NOT EXISTS idx_bw_ts ON bandwidth_samples(ts);

CREATE TABLE IF NOT EXISTS dns_queries (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL NOT NULL,
    mac    TEXT NOT NULL,
    qname  TEXT NOT NULL,
    qtype  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dns_mac_ts ON dns_queries(mac, ts);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts);
"""

# Extra columns added in v2.1 on existing installs. Each entry:
#   (table, column, ddl_fragment) — applied only if the column is missing.
_TABLE_MIGRATIONS = [
    ("devices", "no_probe", "INTEGER NOT NULL DEFAULT 0"),
]


class DeviceStore:
    def __init__(self, data_dir: Path | None = None):
        self._data = Path(data_dir) if data_dir else _DATA
        self._data.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data / _DB_NAME
        self._lock = threading.RLock()
        # check_same_thread=False so the scanner threads can share one connection;
        # we serialize via self._lock for write safety.
        self._db = sqlite3.connect(str(self._db_path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        self._db.executescript(_SCHEMA)
        self._apply_table_migrations()
        self._migrate_json_if_present()

    def _apply_table_migrations(self):
        for table, column, ddl in _TABLE_MIGRATIONS:
            cols = {r["name"] for r in self._q(f"PRAGMA table_info({table})")}
            if column not in cols:
                self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    # ── connection helper ────────────────────────────────────────────────────

    @contextmanager
    def _tx(self):
        with self._lock:
            self._db.execute("BEGIN")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._db.execute(sql, args))

    def _qone(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            cur = self._db.execute(sql, args)
            return cur.fetchone()

    # ── one-time migration from v1.x JSON files ──────────────────────────────

    def _migrate_json_if_present(self):
        flag = self._qone("SELECT value FROM settings WHERE key='migrated_json_v1'")
        if flag:
            return

        def _load(name, default):
            p = self._data / name
            try:
                return json.loads(p.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return default

        known   = _load("known.json",   {})
        seen    = _load("seen.json",    {})
        history = _load("history.json", [])
        hook    = _load("hook.json",    {"on_join": ""})

        with self._tx() as db:
            for mac, rec in known.items():
                db.execute(
                    "INSERT OR IGNORE INTO known(mac,name,added) VALUES(?,?,?)",
                    (mac, rec.get("name", ""), rec.get("added", time.time())),
                )
            for mac, rec in seen.items():
                db.execute(
                    """INSERT OR IGNORE INTO devices(
                         mac, first_seen, last_seen, seen_count, last_ip,
                         hostname, vendor, fingerprint, ports
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        mac,
                        rec.get("first_seen", time.time()),
                        rec.get("last_seen", time.time()),
                        rec.get("seen_count", 1),
                        rec.get("ip"),
                        rec.get("hostname", "—"),
                        rec.get("vendor", "—"),
                        json.dumps(rec.get("fingerprint", {})) if rec.get("fingerprint") else None,
                        json.dumps(rec.get("ports", [])) if rec.get("ports") else None,
                    ),
                )
            for row in history:
                db.execute(
                    "INSERT INTO scans(ts,count,ssid) VALUES(?,?,?)",
                    (row.get("ts", 0), row.get("count", 0), row.get("ssid", "")),
                )
            if hook.get("on_join"):
                db.execute(
                    "INSERT OR REPLACE INTO settings(key,value) VALUES('hook_on_join', ?)",
                    (hook["on_join"],),
                )
            db.execute(
                "INSERT INTO settings(key,value) VALUES('migrated_json_v1', ?)",
                (str(time.time()),),
            )

        # Rename old files so they don't get re-imported.
        for n in ("known.json", "seen.json", "history.json", "hook.json"):
            p = self._data / n
            if p.exists():
                try:
                    p.rename(p.with_suffix(p.suffix + ".v1.bak"))
                except OSError:
                    pass

    # ── Allowlist ────────────────────────────────────────────────────────────

    def is_known(self, mac: str) -> bool:
        return self._qone("SELECT 1 FROM known WHERE mac=?", (mac,)) is not None

    def known_name(self, mac: str) -> str:
        row = self._qone("SELECT name FROM known WHERE mac=?", (mac,))
        return row["name"] if row else ""

    def add_known(self, mac: str, name: str = ""):
        with self._tx() as db:
            db.execute(
                "INSERT INTO known(mac,name,added) VALUES(?,?,?) "
                "ON CONFLICT(mac) DO UPDATE SET name=excluded.name",
                (mac, name, time.time()),
            )

    def remove_known(self, mac: str):
        with self._tx() as db:
            db.execute("DELETE FROM known WHERE mac=?", (mac,))

    @property
    def known(self) -> dict:
        rows = self._q("SELECT mac,name,added FROM known ORDER BY added DESC")
        return {r["mac"]: {"name": r["name"], "added": r["added"]} for r in rows}

    # ── Seen devices ─────────────────────────────────────────────────────────

    def touch(self, device: dict) -> dict:
        """Record this sighting; return device enriched with history fields.

        Also returns:
          device["_is_new"]         — True if first time we've ever seen this MAC
          device["_vendor_changed"] — old vendor string if it changed (else None)
        """
        mac     = device["mac"]
        now     = time.time()
        latency = device.get("latency")
        existing = self._qone(
            "SELECT first_seen, vendor, hostname, last_ip FROM devices WHERE mac=?",
            (mac,),
        )

        is_new          = existing is None
        vendor_changed  = None
        new_vendor      = device.get("vendor", "—")

        if existing and new_vendor not in ("—", "") and existing["vendor"] not in ("—", "", None):
            if new_vendor != existing["vendor"]:
                vendor_changed = existing["vendor"]

        with self._tx() as db:
            if existing:
                db.execute(
                    """UPDATE devices SET
                         last_seen=?, seen_count=seen_count+1,
                         last_ip=?, hostname=?, vendor=?
                       WHERE mac=?""",
                    (now, device.get("ip"), device.get("hostname", "—"),
                     new_vendor, mac),
                )
            else:
                db.execute(
                    """INSERT INTO devices(
                         mac, first_seen, last_seen, seen_count,
                         last_ip, hostname, vendor
                       ) VALUES(?,?,?,1,?,?,?)""",
                    (mac, now, now, device.get("ip"),
                     device.get("hostname", "—"), new_vendor),
                )
            db.execute(
                "INSERT INTO sightings(mac,ip,ts,latency_ms) VALUES(?,?,?,?)",
                (mac, device.get("ip"), now, latency),
            )

        device["first_seen"]       = existing["first_seen"] if existing else now
        device["is_known"]         = self.is_known(mac)
        device["known_name"]       = self.known_name(mac)
        device["_is_new"]          = is_new
        device["_vendor_changed"]  = vendor_changed
        return device

    def update_ports(self, mac: str, ports: list[int]) -> list[int]:
        """Return list of NEWLY-opened ports (compared to previous state)."""
        row = self._qone("SELECT ports FROM devices WHERE mac=?", (mac,))
        prev = set(json.loads(row["ports"])) if row and row["ports"] else set()
        new = sorted(set(ports) - prev)
        with self._tx() as db:
            db.execute(
                "UPDATE devices SET ports=? WHERE mac=?",
                (json.dumps(sorted(ports)), mac),
            )
        return new

    def update_fingerprint(self, mac: str, hints: dict):
        with self._tx() as db:
            db.execute(
                "UPDATE devices SET fingerprint=? WHERE mac=?",
                (json.dumps(hints), mac),
            )

    def merge_fingerprint(self, mac: str, hints: dict):
        """Merge `hints` into the existing fingerprint blob for `mac`.

        Sources like the DHCP sniffer drip-feed individual signals (e.g. just
        option 55) and shouldn't clobber probe results from scanner.py. Creates
        a stub device row if we've never seen the MAC before — the next ARP
        sweep will fill in IP / vendor.
        """
        mac = (mac or "").upper()
        if not mac:
            return
        with self._tx() as db:
            row = db.execute(
                "SELECT fingerprint FROM devices WHERE mac=?", (mac,)
            ).fetchone()
            if row is None:
                now = time.time()
                db.execute(
                    "INSERT INTO devices(mac, first_seen, last_seen, seen_count, "
                    "fingerprint) VALUES(?,?,?,0,?)",
                    (mac, now, now, json.dumps(hints)),
                )
                return
            existing = {}
            if row["fingerprint"]:
                try:
                    existing = json.loads(row["fingerprint"]) or {}
                except (json.JSONDecodeError, TypeError):
                    existing = {}
            existing.update(hints)
            db.execute(
                "UPDATE devices SET fingerprint=? WHERE mac=?",
                (json.dumps(existing), mac),
            )

    def update_device_type(self, mac: str, device_type: str, confidence: float):
        with self._tx() as db:
            db.execute(
                "UPDATE devices SET device_type=?, type_confidence=? WHERE mac=?",
                (device_type, confidence, mac),
            )

    def get_device(self, mac: str) -> dict | None:
        row = self._qone("SELECT * FROM devices WHERE mac=?", (mac,))
        return self._row_to_device(row) if row else None

    @property
    def all_seen(self) -> dict:
        rows = self._q("SELECT * FROM devices")
        return {r["mac"]: self._row_to_device(r) for r in rows}

    def _row_to_device(self, row: sqlite3.Row) -> dict:
        # _row_to_device is also called against rows that don't have every
        # column (e.g. result of PRAGMA-shaped reads in tests). Default to
        # safe values when keys are missing.
        keys = row.keys()
        return {
            "mac":             row["mac"],
            "ip":              row["last_ip"],
            "hostname":        row["hostname"],
            "vendor":          row["vendor"],
            "first_seen":      row["first_seen"],
            "last_seen":       row["last_seen"],
            "seen_count":      row["seen_count"],
            "device_type":     row["device_type"] or "unknown",
            "type_confidence": row["type_confidence"] or 0.0,
            "fingerprint":     json.loads(row["fingerprint"]) if row["fingerprint"] else {},
            "ports":           json.loads(row["ports"]) if row["ports"] else [],
            "no_probe":        bool(row["no_probe"]) if "no_probe" in keys else False,
        }

    # ── Per-device probe opt-out ─────────────────────────────────────────────

    def set_no_probe(self, mac: str, no_probe: bool):
        with self._tx() as db:
            db.execute(
                "UPDATE devices SET no_probe=? WHERE mac=?",
                (1 if no_probe else 0, mac),
            )

    def is_probe_blocked(self, mac: str) -> bool:
        row = self._qone("SELECT no_probe FROM devices WHERE mac=?", (mac,))
        return bool(row and row["no_probe"])

    # ── DHCP-server observations ─────────────────────────────────────────────

    def record_dhcp_server(self, ip: str, mac: str):
        """Stamp a DHCP server sighting. Aggregation happens at read time."""
        with self._tx() as db:
            db.execute(
                "INSERT INTO dhcp_servers(ts, ip, mac) VALUES(?,?,?)",
                (time.time(), ip, mac.upper()),
            )
            # Cap rows to avoid runaway growth on flappy networks.
            db.execute(
                "DELETE FROM dhcp_servers WHERE id IN ("
                " SELECT id FROM dhcp_servers ORDER BY ts DESC LIMIT -1 OFFSET 5000"
                ")"
            )

    # ── WAN port mappings (UPnP IGD enumeration) ─────────────────────────────

    def record_wan_mappings(self, mappings: list):
        """Snapshot the current set of router WAN mappings. Replaces prior set."""
        with self._tx() as db:
            db.execute("DELETE FROM wan_mappings")
            for m in mappings:
                db.execute(
                    "INSERT INTO wan_mappings(ts, internal_ip, internal_port,"
                    " external_port, protocol, description) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        time.time(), m.internal_client, m.internal_port,
                        m.external_port, m.protocol, m.description,
                    ),
                )

    def wan_mappings(self) -> list[dict]:
        rows = self._q(
            "SELECT internal_ip, internal_port, external_port, protocol, description, ts "
            "FROM wan_mappings ORDER BY external_port"
        )
        return [dict(r) for r in rows]

    def wan_mappings_for(self, internal_ip: str) -> list[dict]:
        rows = self._q(
            "SELECT internal_port, external_port, protocol, description "
            "FROM wan_mappings WHERE internal_ip=? ORDER BY external_port",
            (internal_ip,),
        )
        return [dict(r) for r in rows]

    # ── Health snapshots ─────────────────────────────────────────────────────

    def record_health(self, score: int, reasons: list[dict]):
        with self._tx() as db:
            db.execute(
                "INSERT INTO health_snapshots(ts, score, reasons) VALUES(?,?,?)",
                (time.time(), score, json.dumps(reasons)),
            )
            # Keep last 5000.
            db.execute(
                "DELETE FROM health_snapshots WHERE id IN ("
                " SELECT id FROM health_snapshots ORDER BY ts DESC LIMIT -1 OFFSET 5000"
                ")"
            )

    def latest_health(self) -> dict | None:
        row = self._qone(
            "SELECT ts, score, reasons FROM health_snapshots ORDER BY ts DESC LIMIT 1"
        )
        if not row:
            return None
        return {
            "ts": row["ts"],
            "score": row["score"],
            "reasons": json.loads(row["reasons"]),
        }

    # ── Bandwidth (passive sniffer) ──────────────────────────────────────────

    def record_bandwidth_samples(self, samples: list[tuple[str, int, int]]):
        """Batch-insert (mac, bytes_in, bytes_out) snapshots."""
        if not samples:
            return
        now = time.time()
        with self._tx() as db:
            db.executemany(
                "INSERT INTO bandwidth_samples(ts, mac, bytes_in, bytes_out) "
                "VALUES(?,?,?,?)",
                [(now, mac.upper(), bi, bo) for mac, bi, bo in samples],
            )
            # Cap: keep last 50k samples (≈ 35 days at 1 sample / device / min
            # for a small home network).
            db.execute(
                "DELETE FROM bandwidth_samples WHERE id IN ("
                " SELECT id FROM bandwidth_samples ORDER BY ts DESC LIMIT -1 OFFSET 50000"
                ")"
            )

    def bandwidth_for(self, mac: str, since_seconds: int = 3600) -> list[dict]:
        cutoff = time.time() - since_seconds
        rows = self._q(
            "SELECT ts, bytes_in, bytes_out FROM bandwidth_samples "
            "WHERE mac=? AND ts>=? ORDER BY ts ASC",
            (mac.upper(), cutoff),
        )
        return [dict(r) for r in rows]

    def bandwidth_recent(self, since_seconds: int = 1800) -> dict[str, list[tuple[int, int, int]]]:
        """Batch-fetch recent samples for every MAC.

        Returns `{mac: [(ts, bytes_in, bytes_out), ...]}`. One query, used by
        the dashboard to draw per-row sparklines without N round-trips.
        """
        cutoff = time.time() - since_seconds
        rows = self._q(
            "SELECT mac, ts, bytes_in, bytes_out FROM bandwidth_samples "
            "WHERE ts>=? ORDER BY mac, ts ASC",
            (cutoff,),
        )
        out: dict[str, list[tuple[int, int, int]]] = {}
        for r in rows:
            out.setdefault(r["mac"], []).append((int(r["ts"]), int(r["bytes_in"]), int(r["bytes_out"])))
        return out

    # ── DNS queries (passive sniffer) ────────────────────────────────────────

    def record_dns_query(self, mac: str, qname: str, qtype: int = 0):
        if not mac or not qname:
            return
        with self._tx() as db:
            db.execute(
                "INSERT INTO dns_queries(ts, mac, qname, qtype) VALUES(?,?,?,?)",
                (time.time(), mac.upper(), qname, qtype),
            )
            db.execute(
                "DELETE FROM dns_queries WHERE id IN ("
                " SELECT id FROM dns_queries ORDER BY ts DESC LIMIT -1 OFFSET 100000"
                ")"
            )

    def dns_queries_for(self, mac: str, limit: int = 100) -> list[dict]:
        rows = self._q(
            "SELECT ts, qname, qtype FROM dns_queries WHERE mac=? "
            "ORDER BY ts DESC LIMIT ?",
            (mac.upper(), limit),
        )
        return [dict(r) for r in rows]

    # ── Scan history ─────────────────────────────────────────────────────────

    def record_scan(self, count: int, ssid: str):
        with self._tx() as db:
            db.execute(
                "INSERT INTO scans(ts,count,ssid) VALUES(?,?,?)",
                (time.time(), count, ssid or ""),
            )
            # Cap history at 5000 rows.
            db.execute(
                "DELETE FROM scans WHERE id IN ("
                " SELECT id FROM scans ORDER BY ts DESC LIMIT -1 OFFSET 5000"
                ")"
            )

    @property
    def history(self) -> list:
        rows = self._q("SELECT ts, count, ssid FROM scans ORDER BY ts ASC")
        return [{"ts": r["ts"], "count": r["count"], "ssid": r["ssid"]} for r in rows]

    # ── Alerts ───────────────────────────────────────────────────────────────

    def add_alert(
        self, kind: str, severity: str, title: str, message: str, mac: str | None = None
    ) -> int:
        """Insert an alert. Returns its id."""
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO alerts(ts,mac,kind,severity,title,message) VALUES(?,?,?,?,?,?)",
                (time.time(), mac, kind, severity, title, message),
            )
            return cur.lastrowid

    def alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM alerts"
        if unacknowledged_only:
            sql += " WHERE acknowledged=0"
        sql += " ORDER BY ts DESC LIMIT ?"
        rows = self._q(sql, (limit,))
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int):
        with self._tx() as db:
            db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    def acknowledge_all_alerts(self):
        with self._tx() as db:
            db.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0")

    def unack_alert_count(self) -> int:
        row = self._qone("SELECT COUNT(*) AS n FROM alerts WHERE acknowledged=0")
        return row["n"] if row else 0

    # ── Webhooks ─────────────────────────────────────────────────────────────

    def add_webhook(self, url: str, label: str = "", min_severity: str = "info") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO webhooks(label,url,min_severity,enabled,added) VALUES(?,?,?,1,?)",
                (label, url, min_severity, time.time()),
            )
            return cur.lastrowid

    def remove_webhook(self, hook_id: int):
        with self._tx() as db:
            db.execute("DELETE FROM webhooks WHERE id=?", (hook_id,))

    def set_webhook_enabled(self, hook_id: int, enabled: bool):
        with self._tx() as db:
            db.execute(
                "UPDATE webhooks SET enabled=? WHERE id=?",
                (1 if enabled else 0, hook_id),
            )

    def webhooks(self) -> list[dict]:
        rows = self._q("SELECT * FROM webhooks ORDER BY added DESC")
        return [dict(r) for r in rows]

    def active_webhooks_for(self, severity: str) -> list[dict]:
        order = {"info": 0, "warning": 1, "critical": 2}
        s = order.get(severity, 0)
        return [w for w in self.webhooks()
                if w["enabled"] and order.get(w["min_severity"], 0) <= s]

    # ── Hook (legacy single-script on_join) ──────────────────────────────────

    @property
    def hook_script(self) -> str:
        row = self._qone("SELECT value FROM settings WHERE key='hook_on_join'")
        return row["value"] if row else ""

    def set_hook_script(self, script: str):
        with self._tx() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES('hook_on_join', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (script,),
            )

    def run_hook(self, device: dict, ssid: str):
        script = self.hook_script.strip()
        if not script:
            return
        env = {**os.environ,
               "DEVICE_IP":       device.get("ip", ""),
               "DEVICE_MAC":      device.get("mac", ""),
               "DEVICE_VENDOR":   device.get("vendor", ""),
               "DEVICE_HOSTNAME": device.get("hostname", ""),
               "DEVICE_TYPE":     device.get("device_type", ""),
               "SSID":            ssid or ""}
        subprocess.Popen(script, shell=True, env=env)

    # ── Settings ─────────────────────────────────────────────────────────────

    def get_setting(self, key: str, default: str = "") -> str:
        row = self._qone("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        with self._tx() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # ── Test/dev support ─────────────────────────────────────────────────────

    def _flush_now(self):
        """No-op for compatibility with v1.x test fixtures (WAL is auto-flushed)."""
        pass

    def close(self):
        with self._lock:
            self._db.close()
