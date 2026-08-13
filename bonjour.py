"""Publish the INS dashboard as a Bonjour / DNS-SD service so the iOS companion
can discover the Mac on the LAN without a manually-typed IP.

Service type: ``_ins._tcp`` on the dashboard port (8765). We publish only while
LAN remote access is enabled — there's nothing to reach otherwise.

Implementation notes
--------------------
Uses ``NSNetService`` from Foundation, which ships with the already-bundled
``pyobjc-framework-Cocoa`` — so this adds no new dependency and no ``zeroconf``
pip package. ``NSNetService`` needs a live run loop to service its publish
callbacks, so we run it on a dedicated daemon thread with its own
``NSRunLoop``. Everything here is best-effort and macOS-only: if Foundation
isn't importable (Linux, a stripped test env) every call is a safe no-op, so
``import bonjour`` always succeeds.

TXT record keys (all advisory, for the client):
    path  = "/"            the dashboard root
    v     = "1"            TXT schema version
    auth  = "token"        the client must send a Bearer token (see SECURITY.md)
"""

from __future__ import annotations

import threading

try:
    from Foundation import (                    # type: ignore
        NSNetService, NSRunLoop, NSDate, NSDefaultRunLoopMode, NSData,
    )
    _HAVE_FOUNDATION = True
except Exception:                               # pragma: no cover - platform dependent
    NSNetService = NSRunLoop = NSDate = NSDefaultRunLoopMode = NSData = None  # type: ignore
    _HAVE_FOUNDATION = False


_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()
_service = None
_published: tuple | None = None   # (name, port) currently advertised, or None


def _encode_txt(txt: dict[str, str]):
    """Build the NSData TXT-record blob NSNetService expects from a str->str
    dict. Returns None when Foundation is unavailable."""
    if not _HAVE_FOUNDATION:
        return None
    d = {}
    for k, v in (txt or {}).items():
        b = str(v).encode("utf-8")
        d[str(k)] = NSData.dataWithBytes_length_(b, len(b))
    return NSNetService.dataFromTXTRecordDictionary_(d)


def _run(name: str, port: int, txt: dict[str, str]):
    global _service
    try:
        svc = NSNetService.alloc().initWithDomain_type_name_port_(
            "", "_ins._tcp.", name, int(port))
        blob = _encode_txt(txt)
        if blob is not None:
            svc.setTXTRecordData_(blob)
        svc.publish()
        _service = svc
        rl = NSRunLoop.currentRunLoop()
        # Pump the run loop in short slices so we notice the stop event promptly.
        while not _stop.is_set():
            rl.runMode_beforeDate_(
                NSDefaultRunLoopMode, NSDate.dateWithTimeIntervalSinceNow_(0.5))
        try:
            svc.stop()
        except Exception:
            pass
    except Exception:
        pass
    finally:
        _service = None


def publish(name: str, port: int = 8765, txt: dict[str, str] | None = None) -> bool:
    """(Re)publish ``_ins._tcp`` as `name` on `port`. Idempotent for an unchanged
    (name, port). Returns True if a service is now being advertised (or would be
    on a Foundation-capable host), False on a no-op/failure."""
    global _thread, _published
    if not _HAVE_FOUNDATION or not name:
        return False
    txt = txt or {"path": "/", "v": "1", "auth": "token"}
    with _lock:
        if _published == (name, port) and _thread and _thread.is_alive():
            return True
        _unpublish_locked()
        _stop.clear()
        _thread = threading.Thread(
            target=_run, args=(name, port, txt), daemon=True)
        _thread.start()
        _published = (name, port)
        return True


def _unpublish_locked():
    global _thread, _published
    if _thread and _thread.is_alive():
        _stop.set()
        _thread.join(timeout=2)
    _thread = None
    _published = None


def unpublish() -> None:
    """Stop advertising the service. Safe to call when nothing is published."""
    with _lock:
        _unpublish_locked()


def is_published() -> bool:
    with _lock:
        return _published is not None
