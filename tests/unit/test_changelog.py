"""Notes de version (P21) : sections du CHANGELOG, versions installées depuis la dernière ouverture."""

from __future__ import annotations

from cma import __version__
from cma.core import changelog
from cma.core.changelog import changelog_text, new_since, parse, recent, version_key

SAMPLE = """# Historique des versions

## [Non publié]

### Ajouté
- À venir.

## [2.10.0] - 2026-10-09

### Ajouté
- **Surveillance** des services.

## [2.9.0] - 2026-10-09
- Neuf.

## [2.8.0] - 2026-10-08
- Huit.

[2.10.0]: https://example.invalid/compare/v2.9.0...v2.10.0
"""


def test_version_key():
    assert version_key("2.10.0") == (2, 10, 0) > version_key("2.9.0") == (2, 9, 0)
    assert version_key("Non publié") == () == version_key(None)
    assert version_key("2.11.0.dev1") == (2, 11, 0)


def test_parse_skips_unreleased_and_link_definitions():
    releases = parse(SAMPLE)
    assert [r.version for r in releases] == ["2.10.0", "2.9.0", "2.8.0"]
    assert releases[0].date == "2026-10-09" and releases[0].body.startswith("### Ajouté")
    assert "example.invalid" not in releases[-1].body and releases[-1].body == "- Huit."


def test_new_since():
    assert [r.version for r in new_since(SAMPLE, "2.8.0", "2.10.0")] == ["2.10.0", "2.9.0"]
    # Sans version notée (mise à jour depuis une version qui ne la notait pas) : la version courante seulement.
    assert [r.version for r in new_since(SAMPLE, None, "2.10.0")] == ["2.10.0"]
    assert new_since(SAMPLE, "2.10.0", "2.10.0") == []
    assert new_since(SAMPLE, "2.8.0", "inconnue") == []
    # Une version installée plus récente que le CHANGELOG lu : rien n'est inventé.
    assert [r.version for r in new_since(SAMPLE, "2.9.0", "2.11.0")] == ["2.10.0"]


def test_recent():
    assert [r.version for r in recent(SAMPLE, "2.10.0", 2)] == ["2.10.0", "2.9.0"]
    assert [r.version for r in recent(SAMPLE, "2.9.0")] == ["2.9.0", "2.8.0"]


def test_repository_changelog_has_the_current_version():
    """Une version publiée a sa section dans le CHANGELOG (la boîte « Quoi de neuf » la montre)."""
    text = changelog_text()
    assert text is not None
    assert recent(text, __version__, 1)[0].version == __version__


def test_missing_changelog_is_silent(tmp_path, monkeypatch):
    monkeypatch.setattr(changelog, "resource_path", lambda *_p: tmp_path / "absent.md")
    monkeypatch.setattr(changelog, "__file__", str(tmp_path / "a" / "b" / "c" / "changelog.py"))
    assert changelog_text() is None
