"""Démarrage avec la session : clé Run de l'utilisateur sous Windows, fichier .desktop sous Linux."""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path

from cma import APP_ID, APP_NAME

_DESKTOP_FILE = Path.home() / ".config" / "autostart" / "cloudflared-manage-access.desktop"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def supported() -> bool:
    return sys.platform == "win32" or sys.platform.startswith("linux")


def launch_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--minimized"]
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    interpreter = pythonw if sys.platform == "win32" and pythonw.exists() else python
    return [str(interpreter), "-m", "cma", "--minimized"]


def is_enabled() -> bool:
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
                winreg.QueryValueEx(key, APP_ID)
                return True
        except OSError:
            return False
    return _DESKTOP_FILE.exists()


def set_enabled(enabled: bool) -> None:
    if sys.platform == "win32":
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, APP_ID, 0, winreg.REG_SZ, subprocess.list2cmdline(launch_command()))
            else:
                with contextlib.suppress(FileNotFoundError):
                    winreg.DeleteValue(key, APP_ID)
        return
    if not supported():
        raise NotImplementedError("démarrage automatique non pris en charge sur ce système")
    if enabled:
        _DESKTOP_FILE.parent.mkdir(parents=True, exist_ok=True)
        _DESKTOP_FILE.write_text(
            "[Desktop Entry]\nType=Application\n"
            f"Name={APP_NAME}\nExec={' '.join(launch_command())}\nX-GNOME-Autostart-enabled=true\n",
            encoding="utf-8",
        )
    else:
        _DESKTOP_FILE.unlink(missing_ok=True)
