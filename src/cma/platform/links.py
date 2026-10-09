"""Ouverture des liens `cma://` et des fichiers `.cma` par CMA.

Windows : clés de l'utilisateur courant (`HKCU\\Software\\Classes`), sans droits d'administration ; l'installeur
les pose lui-même, ce module sert aux versions portable et Scoop. Linux : fichier `.desktop` déclarant
`x-scheme-handler/cma`, enregistré par `xdg-mime`.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path

from cma import APP_NAME

PROG_ID = "CloudflaredManageAccess.Profile"
_CLASSES = r"Software\Classes"
_DESKTOP_FILE = Path.home() / ".local" / "share" / "applications" / "cloudflared-manage-access-links.desktop"
MIME_TYPE = "application/x-cma-profile"


def supported() -> bool:
    return sys.platform == "win32" or sys.platform.startswith("linux")


def open_command() -> list[str]:
    """Commande qui reçoit le lien ou le fichier (`%1` sous Windows, `%u` sous Linux)."""
    placeholder = "%1" if sys.platform == "win32" else "%u"
    if getattr(sys, "frozen", False):
        return [sys.executable, placeholder]
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    interpreter = pythonw if sys.platform == "win32" and pythonw.exists() else python
    return [str(interpreter), "-m", "cma", placeholder]


def _windows_keys() -> dict[str, dict[str, str]]:
    command = " ".join(f'"{part}"' for part in open_command())  # « "C:\…\CMA.exe" "%1" »
    icon = f"{open_command()[0]},0"
    return {
        rf"{_CLASSES}\cma": {"": f"URL:{APP_NAME}", "URL Protocol": ""},
        rf"{_CLASSES}\cma\DefaultIcon": {"": icon},
        rf"{_CLASSES}\cma\shell\open\command": {"": command},
        rf"{_CLASSES}\.cma": {"": PROG_ID},
        rf"{_CLASSES}\{PROG_ID}": {"": f"{APP_NAME} — profil partagé"},
        rf"{_CLASSES}\{PROG_ID}\DefaultIcon": {"": icon},
        rf"{_CLASSES}\{PROG_ID}\shell\open\command": {"": command},
    }


def is_registered() -> bool:
    """Les liens `cma://` ouvrent-ils cette copie de CMA ?"""
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{_CLASSES}\cma\shell\open\command") as key:
                value, _kind = winreg.QueryValueEx(key, "")
        except OSError:
            return False
        return str(value) == _windows_keys()[rf"{_CLASSES}\cma\shell\open\command"][""]
    return _DESKTOP_FILE.exists()


def register() -> None:
    """Associe les liens `cma://` et les fichiers `.cma` à cette copie de CMA."""
    if sys.platform == "win32":
        import winreg

        for path, values in _windows_keys().items():
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                for name, value in values.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        return
    if not supported():
        raise NotImplementedError("liens cma:// non pris en charge sur ce système")
    _DESKTOP_FILE.parent.mkdir(parents=True, exist_ok=True)
    _DESKTOP_FILE.write_text(
        "[Desktop Entry]\nType=Application\nNoDisplay=true\n"
        f"Name={APP_NAME}\nExec={' '.join(open_command())}\n"
        f"MimeType=x-scheme-handler/cma;{MIME_TYPE};\n",
        encoding="utf-8",
    )
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        for mime in ("x-scheme-handler/cma", MIME_TYPE):
            subprocess.run(["xdg-mime", "default", _DESKTOP_FILE.name, mime], check=False, timeout=10)
