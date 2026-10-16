"""Journal de diagnostic des processus de test (`tests/diagnostic_workers.py`, P42)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from tests import diagnostic_workers as diag


def test_snapshot_gives_memory_and_disk_figures(tmp_path: Path) -> None:
    free = diag.free_disk_mb(tmp_path)
    assert free is not None and free > 0
    assert diag.free_disk_mb(tmp_path / "absent" / "x") is None  # un chemin absent ne lève jamais
    memory = diag.free_memory_mb()
    if memory is not None:
        assert memory["ram_free"] > 0
    private = diag.own_private_mb()
    assert private is None or private > 0
    line = diag.snapshot()
    assert "commit_processus=" in line
    assert "disque_temp=" in line and "disque_travail=" in line and "controleur_vivant=" in line


def test_process_alive_tells_a_live_process_from_an_unknown_one() -> None:
    assert diag.process_alive(os.getpid()) is True
    assert diag.process_alive(None) is None


def test_journal_keeps_the_last_test_and_ends_with_a_closing_line(tmp_path: Path) -> None:
    journal = diag.Journal(tmp_path / "session", "contrôleur", os.getpid())
    journal.test_started("tests/x.py::test_un")
    journal.test_started("tests/x.py::test_deux")
    journal.close("fin d'essai")
    journal.close("deuxième fermeture ignorée")
    text = (tmp_path / "session" / f"{os.getpid()}.log").read_text(encoding="utf-8")
    assert "test 2 tests/x.py::test_deux" in text
    assert text.count("fin d'essai") == 1 and "deuxième fermeture" not in text
    assert "dernier test=tests/x.py::test_deux" in text
    journal.note("après fermeture : ignoré sans erreur")  # jamais d'exception vers un test


def test_journal_never_raises_when_its_folder_is_unwritable(tmp_path: Path) -> None:
    blocker = tmp_path / "fichier"
    blocker.write_text("pas un dossier", encoding="utf-8")
    journal = diag.Journal(blocker / "sous-dossier", "travailleur gw9", None)  # mkdir impossible
    journal.test_started("tests/x.py::test_un")
    journal.close("fin")


def test_purge_old_removes_only_old_session_folders(tmp_path: Path) -> None:
    old, recent = tmp_path / "100", tmp_path / "200"
    old.mkdir()
    recent.mkdir()
    ancient = time.time() - (diag.KEEP_DAYS + 1) * 86400
    os.utime(old, (ancient, ancient))
    diag.purge_old(tmp_path)
    assert not old.exists() and recent.exists()
    diag.purge_old(tmp_path / "absent")  # dossier racine absent : sans effet
