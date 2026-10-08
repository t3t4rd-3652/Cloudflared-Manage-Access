"""Notification du système, hors de l'interface (commande `cma tunnels --notify` lancée par une tâche planifiée).

Titre et texte passent par l'environnement (Windows) ou par les arguments (macOS, Linux), jamais dans le texte
d'un script : un nom de tunnel ne peut rien exécuter.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from cma.core.cloudflared.binary import powershell_env

# Notification « toast » par Windows PowerShell 5.1 ; l'identifiant d'application est celui de PowerShell, déjà
# enregistré sur tout Windows (CMA n'en déclare pas).
_TOAST = (
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]"
    " | Out-Null; "
    "$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
    "$texts = $xml.GetElementsByTagName('text'); "
    "$texts.Item(0).AppendChild($xml.CreateTextNode($env:CMA_TOAST_TITLE)) | Out-Null; "
    "$texts.Item(1).AppendChild($xml.CreateTextNode($env:CMA_TOAST_TEXT)) | Out-Null; "
    "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
    "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show($toast)"
)


def system_notification(title: str, text: str) -> bool:
    """Affiche une notification du système ; renvoie False si aucun moyen n'est disponible ou si elle échoue."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    _TOAST,
                ],
                env=powershell_env(CMA_TOAST_TITLE=title, CMA_TOAST_TEXT=text),
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return result.returncode == 0
        if sys.platform == "darwin":
            script = [
                "-e",
                "on run argv",
                "-e",
                "display notification (item 2 of argv) with title (item 1 of argv)",
            ]
            result = subprocess.run(
                ["osascript", *script, "-e", "end run", title, text],
                capture_output=True,
                timeout=30,
                check=False,
            )
            return result.returncode == 0
        notifier = shutil.which("notify-send")
        if notifier is None:
            return False
        return (
            subprocess.run([notifier, title, text], capture_output=True, timeout=30, check=False).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False
