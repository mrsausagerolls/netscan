"""Local threat-intel list.

A flat text file of one domain per line, read at startup and reloaded when
its mtime changes. Lines starting with `#` are comments. Suffix matching:
`tracker.example` matches `tracker.example` and `foo.tracker.example`.

Why local-only: shipping a fetcher that pulls from URLhaus / abuse.ch is
tempting but turns every INS install into a periodic outbound caller, and
gives someone with control of those endpoints the ability to direct INS at
arbitrary domains. Local file = user controls exactly what's on the list.

Default location:
  ~/Library/Application Support/InglNetScan/threats.txt   (frozen .app)
  ./data/threats.txt                                       (run from source)

A small starter list is created on first launch if the file doesn't exist,
populated from `_DEFAULT_THREATS` below.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path


# Conservative starter list: well-known abuse infrastructure that any
# everyday user is safe to flag. Easy to add to via the file.
_DEFAULT_THREATS = """\
# Inglorious Network Scanner — local threat-intel list
# One domain per line. Lines starting with `#` are comments.
# Suffix-matched: tracker.example matches foo.tracker.example too.
#
# Edit this file to add your own. INS reloads it automatically.

# Tor — flag IoT devices reaching the Tor network as suspicious.
torproject.org
tor2web.org

# Known mining pool front-ends — IoT shouldn't be mining.
nanopool.org
ethermine.org
flexpool.io
2miners.com
"""


def _default_data_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path.home() / "Library" / "Application Support" / "InglNetScan"
    return Path(__file__).parent / "data"


class ThreatList:
    """In-memory threat list with mtime-driven reload."""

    # matches() is called once per captured DNS packet on the sniffer's capture
    # thread, so it must not touch the filesystem every call. We stat() for a
    # changed mtime at most this often; edits are still picked up within a few
    # seconds.
    _CHECK_INTERVAL = 5.0

    def __init__(self, path: Path | None = None):
        self.path = path or (_default_data_dir() / "threats.txt")
        self._lock = threading.Lock()
        self._domains: set[str] = set()
        self._mtime: float = 0.0
        self._last_check: float = 0.0
        self._ensure_seed_file()
        self._load_locked()

    def _ensure_seed_file(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                self.path.write_text(_DEFAULT_THREATS)
        except OSError:
            pass

    def _load_locked(self):
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            with self._lock:
                self._domains = set()
                self._mtime = 0.0
            return
        if mtime == self._mtime:
            return
        try:
            text = self.path.read_text()
        except OSError:
            return
        domains: set[str] = set()
        for line in text.splitlines():
            line = line.strip().lower().rstrip(".")
            if not line or line.startswith("#"):
                continue
            domains.add(line)
        with self._lock:
            self._domains = domains
            self._mtime = mtime

    def reload_if_stale(self):
        """Cheap — only re-reads when the file's mtime changed. Public callers
        (and domains()) get an immediate check."""
        self._load_locked()

    def _maybe_reload(self):
        """Throttled reload for the packet hot path: stat() for a changed mtime
        at most once every _CHECK_INTERVAL seconds. matches() runs per DNS
        packet on the capture thread, so a stat() syscall per call would
        serialize capture on the filesystem."""
        now = time.monotonic()
        with self._lock:
            if now - self._last_check < self._CHECK_INTERVAL:
                return
            self._last_check = now
        self._load_locked()

    def domains(self) -> set[str]:
        self.reload_if_stale()
        with self._lock:
            return set(self._domains)

    def matches(self, qname: str) -> str | None:
        """Return the matched suffix if `qname` is on the list, else None.

        Matches exact OR suffix-with-dot. So `tracker.example` matches both
        `tracker.example` and `foo.tracker.example`, but NOT `evil-tracker.example`.

        Uses the throttled reload and iterates the domain set in place under the
        lock (no per-call copy) — this is the packet hot path.
        """
        q = (qname or "").strip().lower().rstrip(".")
        if not q:
            return None
        self._maybe_reload()
        with self._lock:
            if q in self._domains:
                return q
            for d in self._domains:
                if q.endswith("." + d):
                    return d
        return None
