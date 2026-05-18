"""Check GitHub Releases for a newer NetScan version."""

import json
import urllib.request

from version import GITHUB_REPO, __version__

_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


def _version_tuple(v: str) -> tuple[int, ...]:
    """Parse '1.2.3' or 'v1.2.3' → (1, 2, 3). Unparseable → empty tuple."""
    v = v.strip().lstrip("v")
    try:
        return tuple(int(part) for part in v.split("."))
    except ValueError:
        return ()


def check_for_update(current: str = __version__) -> dict | None:
    """Hit the Releases API; return {tag, url, body} if a newer release exists, else None.

    Returns None on any error (no network, rate-limited, malformed response).
    """
    try:
        req = urllib.request.Request(
            _API_URL,
            headers={
                "Accept":     "application/vnd.github+json",
                "User-Agent": f"NetScan/{current}",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    tag = data.get("tag_name", "")
    latest = _version_tuple(tag)
    current_t = _version_tuple(current)
    if not latest or not current_t or latest <= current_t:
        return None

    return {
        "tag":  tag.lstrip("v"),
        "url":  data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases"),
        "body": data.get("body", ""),
    }
