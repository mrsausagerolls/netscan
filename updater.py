"""Check GitHub Releases for a newer Inglorious Network Scanner version."""

import json
import os
import re
import urllib.request

from version import GITHUB_REPO, __version__

_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


def _version_tuple(v: str) -> tuple[int, ...]:
    """Parse '1.2.3' or 'v1.2.3' → (1, 2, 3). Unparseable → empty tuple.

    A leading 'v' and any trailing pre-release/build suffix ('-beta', 'rc1',
    '+build') are stripped before parsing the numeric MAJOR.MINOR.PATCH so a
    slightly off-convention tag still parses to its release number. Pre-release
    handling itself is in check_for_update (we don't offer pre-releases).
    """
    m = re.match(r"v?(\d+(?:\.\d+)*)", v.strip())
    if not m:
        return ()
    try:
        return tuple(int(part) for part in m.group(1).split("."))
    except ValueError:
        return ()


def _is_prerelease(tag: str) -> bool:
    """True if the tag carries a pre-release/build suffix (anything after the
    numeric MAJOR.MINOR.PATCH). We never auto-offer those as stable updates."""
    return bool(re.search(r"\d(?:[-+~]|rc|alpha|beta)", tag.strip().lstrip("v"), re.I))


def _newer(latest: tuple[int, ...], current: tuple[int, ...]) -> bool:
    """Version-tuple compare that's insensitive to component count, so '2.5'
    and '2.5.0' compare equal rather than the shorter looking older."""
    n = max(len(latest), len(current))
    return tuple(latest + (0,) * n)[:n] > tuple(current + (0,) * n)[:n]


def check_for_update(current: str = __version__) -> dict | None:
    """Hit the Releases API; return {tag, url, body} if a newer release exists, else None.

    Returns None on any error (no network, rate-limited, malformed response).
    Honors INS_NO_UPDATE_CHECK=1 (documented in SECURITY.md) as a hard opt-out.
    """
    if os.environ.get("INS_NO_UPDATE_CHECK") == "1":
        return None
    try:
        req = urllib.request.Request(
            _API_URL,
            headers={
                "Accept":     "application/vnd.github+json",
                "User-Agent": f"InglNetScan/{current}",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    tag = data.get("tag_name", "")
    if _is_prerelease(tag):
        return None
    latest = _version_tuple(tag)
    current_t = _version_tuple(current)
    if not latest or not current_t or not _newer(latest, current_t):
        return None

    return {
        "tag":  tag.lstrip("v"),
        "url":  data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases"),
        "body": data.get("body", ""),
    }
