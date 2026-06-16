"""Webhook dispatcher.

Posts JSON alerts to user-configured URLs. Auto-detects the receiver by URL
shape and formats the payload accordingly. Supported flavors:

  - Discord    (discord.com / discordapp.com webhooks)
  - Slack      (hooks.slack.com)
  - Pushover   (api.pushover.net) — needs ?token=APP&user=USER in the URL,
                or use the api.pushover.net/1/messages.json endpoint with
                token+user encoded in the URL fragment we read here
  - ntfy.sh    (ntfy.sh/<topic> or self-hosted /<topic>)
  - Generic    (clean default JSON shape; works with IFTTT, Zapier, Pipedream,
                n8n, custom scripts)

Everything fires off the main scanner thread.
"""

import json
import threading
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

from version import __app_name__


SEVERITY_COLOR = {
    "info":     0x3AAFE8,
    "warning":  0xF5A623,
    "critical": 0xF0435A,
}

NTFY_PRIORITY = {
    "info":     3,   # default
    "warning":  4,   # high
    "critical": 5,   # max — bypasses Do-Not-Disturb on most clients
}

PUSHOVER_PRIORITY = {
    "info":     0,
    "warning":  1,
    "critical": 2,   # emergency — requires ack; we don't set the retry/expire
                     # fields because INS alerts are advisory, not on-call pages.
}


def _discord_payload(alert: dict, _: dict) -> dict:
    color = SEVERITY_COLOR.get(alert.get("severity", "info"), 0x3AAFE8)
    return {
        "username": __app_name__,
        "embeds": [{
            "title":       alert.get("title", "Alert"),
            "description": alert.get("message", ""),
            "color":       color,
            "footer": {"text": f"severity: {alert.get('severity', 'info')}"},
        }],
    }


def _slack_payload(alert: dict, _: dict) -> dict:
    sev = alert.get("severity", "info")
    icon = {"critical": ":rotating_light:", "warning": ":warning:", "info": ":satellite:"}.get(sev, ":satellite:")
    color = {"info": "#3AAFE8", "warning": "#F5A623", "critical": "#F0435A"}.get(sev, "#3AAFE8")
    return {
        "username": __app_name__,
        "icon_emoji": icon,
        "attachments": [{
            "color":     color,
            "title":     alert.get("title", "Alert"),
            "text":      alert.get("message", ""),
            "fields": [{"title": "Severity", "value": sev, "short": True}],
        }],
    }


def _ntfy_payload(alert: dict, _: dict) -> dict:
    sev = alert.get("severity", "info")
    tags = {"critical": "rotating_light,warning",
            "warning":  "warning",
            "info":     "satellite"}.get(sev, "satellite")
    return {
        "title":    alert.get("title", "Alert"),
        "message":  alert.get("message", ""),
        "priority": NTFY_PRIORITY.get(sev, 3),
        "tags":     tags,
    }


def _pushover_payload(alert: dict, parsed_url) -> dict:
    """Pushover wants application/x-www-form-urlencoded with token + user.

    The user encodes their token+user in the URL query string, e.g.
        https://api.pushover.net/1/messages.json?token=APP&user=USER
    We extract them and rebuild the body Pushover expects.
    """
    sev = alert.get("severity", "info")
    qs = urllib.parse.parse_qs(parsed_url.query)
    return {
        "token":    (qs.get("token") or [""])[0],
        "user":     (qs.get("user")  or [""])[0],
        "title":    alert.get("title", "Alert"),
        "message":  alert.get("message", ""),
        "priority": PUSHOVER_PRIORITY.get(sev, 0),
    }


def _generic_payload(alert: dict, _: dict) -> dict:
    return {
        "source":  __app_name__,
        "alert":   alert,
    }


# Detection table: (predicate, payload_builder, content_type, target_url_fn).
# target_url_fn lets a flavor rewrite the URL (Pushover sends to /1/messages.json
# regardless of what the user pasted; we drop the query string from the body).
def _flavor_for(url: str):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.netloc or "").lower()
    if "discord.com" in host or "discordapp.com" in host:
        return _discord_payload, "application/json", url
    if "hooks.slack.com" in host:
        return _slack_payload, "application/json", url
    if "api.pushover.net" in host:
        return _pushover_payload, "application/x-www-form-urlencoded", \
               "https://api.pushover.net/1/messages.json"
    # Detect ntfy by 'ntfy' in the host (ntfy.sh or a self-hosted ntfy.* host).
    # We don't guess from path shape — a single-segment path matches almost any
    # webhook URL (Slack/Discord/generic), so guessing would misclassify them.
    if "ntfy" in host:
        return _ntfy_payload, "application/json", url
    return _generic_payload, "application/json", url


def _payload_for(url: str, alert: dict) -> dict:
    builder, _, _ = _flavor_for(url)
    parsed = urllib.parse.urlparse(url)
    return builder(alert, parsed)


def _post(url: str, payload: dict, content_type: str, timeout: float = 5.0):
    if content_type == "application/x-www-form-urlencoded":
        body = urllib.parse.urlencode(payload).encode("utf-8")
    else:
        body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": content_type,
                 "User-Agent":   f"InglNetScan/2.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        pass


def dispatch(store, alert: dict) -> None:
    """Fire-and-forget dispatch to every active webhook matching severity."""
    hooks = store.active_webhooks_for(alert.get("severity", "info"))
    if not hooks:
        return

    def _send_all():
        for hook in hooks:
            builder, ctype, target = _flavor_for(hook["url"])
            parsed = urllib.parse.urlparse(hook["url"])
            payload = builder(alert, parsed)
            _post(target, payload, ctype)

    threading.Thread(target=_send_all, daemon=True).start()
