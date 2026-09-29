"""Vérification des nouvelles versions de CMA (Releases GitHub du projet)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from cma import REPO_URL, __version__
from cma.core.cloudflared.binary import USER_AGENT, is_newer

LATEST_API = REPO_URL.replace("https://github.com/", "https://api.github.com/repos/") + "/releases/latest"


@dataclass(frozen=True)
class UpdateInfo:
    current: str
    latest: str | None
    url: str | None

    @property
    def available(self) -> bool:
        return is_newer(self.latest, self.current)


def check_for_update(timeout: float = 10) -> UpdateInfo:
    """Dernière release publiée. `latest` vaut None si le projet n'a encore publié aucune release."""
    request = urllib.request.Request(
        LATEST_API, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return UpdateInfo(__version__, None, None)
        raise
    return UpdateInfo(__version__, str(data.get("tag_name", "")).lstrip("vV") or None, data.get("html_url"))
