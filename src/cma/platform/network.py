"""Nom du réseau Wi-Fi auquel ce poste est relié (SSID) : pour n'ouvrir un espace de travail au démarrage que hors
d'un réseau donné (par exemple pas à la maison, où les services sont joignables directement).

Windows : `netsh wlan show interfaces` ; Linux : `nmcli`. Sans Wi-Fi (câble, réseau inconnu) ou sans outil : None.
"""

from __future__ import annotations

import subprocess
import sys


def parse_netsh(output: str) -> str | None:
    """SSID de la sortie de `netsh wlan show interfaces` (toutes langues : la ligne commence par « SSID »)."""
    for line in output.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().upper() == "SSID" and value.strip():
            return value.strip()
    return None


def parse_nmcli(output: str) -> str | None:
    """SSID actif de `nmcli -t -f active,ssid dev wifi` (lignes « oui:Nom » ou « yes:Nom »)."""
    for line in output.splitlines():
        active, sep, ssid = line.partition(":")
        if sep and active.strip().lower() in ("yes", "oui", "ja", "sí", "si") and ssid.strip():
            return ssid.strip()
    return None


def current_wifi() -> str | None:
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=False,
            )
            return parse_netsh(result.stdout)
        if sys.platform.startswith("linux"):
            result = subprocess.run(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return parse_nmcli(result.stdout)
    except (OSError, subprocess.SubprocessError):
        return None
    return None
