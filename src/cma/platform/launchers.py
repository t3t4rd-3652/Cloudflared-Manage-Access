"""Lancement d'outils externes pour les actions rapides : terminal SSH, Bureau à distance, MongoDB Compass."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from cma.i18n import tr


class LaunchError(RuntimeError):
    pass


def _spawn(args: list[str], *, new_console: bool = False) -> None:
    kwargs: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.CREATE_NEW_CONSOLE if new_console else subprocess.DETACHED_PROCESS
        )
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(args, **kwargs)  # type: ignore[call-overload]
    except OSError as exc:
        raise LaunchError(
            tr("Impossible de lancer {program} : {error}").format(program=args[0], error=exc)
        ) from exc


def ssh_command(host: str, port: int, user: str = "") -> list[str]:
    target = f"{user}@{host}" if user else host
    return ["ssh", "-p", str(port), target]


def open_ssh_terminal(host: str, port: int, user: str = "", title: str = "SSH") -> None:
    command = ssh_command(host, port, user)
    if sys.platform == "win32":
        if shutil.which("wt.exe"):
            _spawn(["wt.exe", "new-tab", "--title", title, *command])
        else:
            _spawn(["cmd.exe", "/k", *command], new_console=True)
        return
    if sys.platform == "darwin":
        script = " ".join(command)
        _spawn(["osascript", "-e", f'tell application "Terminal" to do script "{script}"'])
        return
    for terminal in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
        if shutil.which(terminal):
            separator = ["--"] if terminal == "gnome-terminal" else ["-e"]
            _spawn([terminal, *separator, *command])
            return
    raise LaunchError(tr("Aucun terminal trouvé."))


def rdp_available() -> bool:
    return sys.platform == "win32" or shutil.which("xfreerdp") is not None


def open_rdp(host: str, port: int) -> None:
    if sys.platform == "win32":
        _spawn(["mstsc.exe", f"/v:{host}:{port}"])
    elif shutil.which("xfreerdp"):
        _spawn(["xfreerdp", f"/v:{host}:{port}"])
    else:
        raise LaunchError(tr("Aucun client Bureau à distance trouvé."))


def find_mongodb_compass() -> Path | None:
    candidates: list[Path] = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        candidates += [
            Path(local) / "MongoDBCompass" / "MongoDBCompass.exe",
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
            / "MongoDB Compass"
            / "MongoDBCompass.exe",
        ]
    elif sys.platform == "darwin":
        candidates.append(Path("/Applications/MongoDB Compass.app/Contents/MacOS/MongoDB Compass"))
    else:
        which = shutil.which("mongodb-compass")
        if which:
            candidates.append(Path(which))
    return next((c for c in candidates if c.is_file()), None)


def open_mongodb_compass(uri: str) -> None:
    compass = find_mongodb_compass()
    if compass is None:
        raise LaunchError(tr("MongoDB Compass est introuvable."))
    _spawn([str(compass), uri])
