"""Notes de version lues dans CHANGELOG.md, pour la boîte « Quoi de neuf ».

Le fichier est embarqué dans les paquets (`cma/resources/CHANGELOG.md`) ; en développement, celui du dépôt est lu.
S'il manque (installation par pip, paquet ancien), rien n'est montré : ce n'est jamais une erreur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cma.paths import resource_path

# « ## [2.10.0] - 2026-10-09 », « ## [Non publié] ».
HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?:[ \t]*-[ \t]*(?P<date>\S+))?[ \t]*$", re.MULTILINE)
# Définitions de liens de Keep a Changelog (« [2.10.0]: https://… ») : hors de toute section.
LINK_DEFINITION = re.compile(r"^\[[^\]]+\]:\s*\S+\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Release:
    version: str
    date: str | None
    body: str


def version_key(version: str | None) -> tuple[int, ...]:
    """(2, 10, 0) pour « 2.10.0 » (suffixe ignoré) ; () pour un titre qui n'est pas un numéro (« Non publié »)."""
    match = re.match(r"\d+(?:\.\d+)*", (version or "").strip())
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def parse(text: str) -> list[Release]:
    """Sections des versions publiées, la plus récente d'abord ; « Non publié » est écartée."""
    matches = list(HEADING.finditer(text))
    releases: list[Release] = []
    for index, match in enumerate(matches):
        version = match.group("version").strip()
        if not version_key(version):
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = LINK_DEFINITION.sub("", text[match.end() : end]).strip()
        releases.append(Release(version, match.group("date"), body))
    releases.sort(key=lambda r: version_key(r.version), reverse=True)
    return releases


def new_since(text: str, seen: str | None, current: str) -> list[Release]:
    """Versions installées depuis `seen` (exclue) jusqu'à `current` (incluse), la plus récente d'abord. Sans version
    vue (mise à jour depuis une version qui ne la notait pas), la version courante seulement."""
    upper = version_key(current)
    lower = version_key(seen) if seen else None
    if not upper:
        return []
    return [
        release
        for release in parse(text)
        if (key := version_key(release.version)) <= upper and (key == upper if lower is None else key > lower)
    ]


def recent(text: str, current: str, count: int = 3) -> list[Release]:
    """Les `count` dernières versions jusqu'à `current` : « Quoi de neuf » ouvert depuis l'aide."""
    upper = version_key(current)
    return [r for r in parse(text) if version_key(r.version) <= upper][:count]


def changelog_text() -> str | None:
    """CHANGELOG.md embarqué (exécutable, paquet) ou celui du dépôt ; None s'il est introuvable ou illisible."""
    for candidate in (resource_path("CHANGELOG.md"), Path(__file__).resolve().parents[3] / "CHANGELOG.md"):
        try:
            return candidate.read_text(encoding="utf-8")
        except OSError:
            continue
    return None
