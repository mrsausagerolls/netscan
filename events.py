"""Tiny synchronous event bus.

Subscribers are plain callables. Errors in one subscriber don't stop the others.
The bus is intentionally synchronous — events fire on the scanner thread; if a
subscriber needs to do slow work (HTTP, subprocess), it must spawn its own thread.
"""

import threading
import traceback
from collections import defaultdict
from typing import Callable

# Event kinds — string constants so subscribers can't typo them.
DEVICE_JOINED    = "device.joined"
DEVICE_LEFT      = "device.left"
DEVICE_UPDATED   = "device.updated"
PORTS_CHANGED    = "device.ports_changed"
VENDOR_CHANGED   = "device.vendor_changed"
ALERT_RAISED     = "alert.raised"
SCAN_COMPLETED   = "scan.completed"

_subs: dict[str, list[Callable]] = defaultdict(list)
_lock = threading.Lock()


def subscribe(event: str, fn: Callable):
    with _lock:
        _subs[event].append(fn)


def publish(event: str, payload: dict) -> None:
    with _lock:
        handlers = list(_subs.get(event, []))
    for fn in handlers:
        try:
            fn(payload)
        except Exception:
            traceback.print_exc()
