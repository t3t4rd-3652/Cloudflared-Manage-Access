"""Surveillance des tunnels quand CMA est fermé : tâche planifiée Windows qui lance `tunnels --notify`.

La tâche lance l'exécutable fenêtré (aucune console ne s'ouvre toutes les 15 minutes), sous le compte de
l'utilisateur et seulement quand il a ouvert sa session : la notification a besoin de son bureau.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TASK_NAME = r"Cloudflared Manage Access\Surveillance des tunnels"
INTERVAL_MINUTES = 15


def supported() -> bool:
    return sys.platform == "win32"


def monitor_command() -> list[str]:
    """Commande de la tâche : l'exécutable fenêtré figé, sinon `pythonw -m cma` (sources)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "tunnels", "--notify"]
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else python
    return [str(interpreter), "-m", "cma", "tunnels", "--notify"]


def _schtasks(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["schtasks.exe", *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def is_enabled() -> bool:
    if not supported():
        return False
    try:
        return _schtasks("/Query", "/TN", TASK_NAME).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def set_enabled(enabled: bool) -> None:
    """Crée (ou remplace) la tâche, ou la supprime. Lève OSError avec le message de schtasks en cas d'échec."""
    if not supported():
        raise OSError("tâche planifiée non prise en charge sur ce système")
    if enabled:
        result = _schtasks(
            "/Create",
            "/TN",
            TASK_NAME,
            "/TR",
            subprocess.list2cmdline(monitor_command()),
            "/SC",
            "MINUTE",
            "/MO",
            str(INTERVAL_MINUTES),
            "/F",
        )
    else:
        if not is_enabled():
            return
        result = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout).strip() or f"schtasks : code {result.returncode}")
