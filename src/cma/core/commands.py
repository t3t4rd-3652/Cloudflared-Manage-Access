"""Commandes texte partagées par la ligne de commande et le canal local de l'instance graphique."""

from __future__ import annotations

from typing import Any

from cma.core.manager import ManagerError, SessionManager
from cma.core.models import CloudflareProfile, Config, SshProfile
from cma.core.sessions import SessionInfo
from cma.i18n import tr


def profile_summaries(config: Config) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for profile in config.cloudflare_profiles:
        result.append(
            {
                "id": profile.id,
                "type": "cloudflare",
                "name": profile.name,
                "group": profile.group,
                "target": profile.hostname,
                "local": f"{profile.local_host}:{profile.local_port}" if profile.local_port else "",
            }
        )
    for ssh in config.ssh_profiles:
        result.append(
            {
                "id": ssh.id,
                "type": "ssh",
                "name": ssh.name,
                "group": ssh.group,
                "target": f"{ssh.user}@{ssh.host}:{ssh.port}",
                "local": ", ".join(str(f.local_port) for f in ssh.saved_forwards),
            }
        )
    return result


def session_summary(info: SessionInfo) -> dict[str, Any]:
    return {
        "id": info.id,
        "name": info.name,
        "kind": info.kind.value,
        "state": info.state.value,
        "state_label": info.state.label,
        "local": info.local_address,
        "target": info.subtitle,
        "message": info.message,
    }


async def execute(manager: SessionManager, message: dict[str, Any]) -> dict[str, Any]:
    command = message.get("cmd")
    config = manager.store.snapshot()
    try:
        if command == "list":
            return {"ok": True, "profiles": profile_summaries(config)}
        if command == "status":
            return {"ok": True, "sessions": [session_summary(i) for i in manager.list_sessions()]}
        if command == "connect":
            if message.get("group"):
                infos = await manager.start_group(str(message["group"]))
                return {"ok": True, "sessions": [session_summary(i) for i in infos]}
            profile = config.find_profile_by_name(str(message.get("profile", "")))
            if isinstance(profile, CloudflareProfile):
                info = await manager.start_cloudflare(profile.id)
                return {"ok": True, "sessions": [session_summary(info)]}
            if isinstance(profile, SshProfile):
                if not profile.saved_forwards:
                    await manager.ssh_connect(profile.id)
                    return {
                        "ok": True,
                        "sessions": [],
                        "message": tr("Connecté ; ce profil n'a aucune redirection enregistrée."),
                    }
                infos = await manager.start_saved_forwards(profile.id)
                return {"ok": True, "sessions": [session_summary(i) for i in infos]}
            return {
                "ok": False,
                "error": tr("Profil introuvable : {name}").format(name=message.get("profile")),
            }
        if command == "disconnect":
            if message.get("all"):
                await manager.stop_all()
                return {"ok": True}
            if message.get("group"):
                await manager.stop_group(str(message["group"]))
                return {"ok": True}
            profile = config.find_profile_by_name(str(message.get("profile", "")))
            if profile is None:
                return {
                    "ok": False,
                    "error": tr("Profil introuvable : {name}").format(name=message.get("profile")),
                }
            if isinstance(profile, SshProfile):
                await manager.ssh_disconnect(profile.id)
            else:
                await manager.stop_profile(profile.id)
            return {"ok": True}
    except ManagerError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": tr("Commande inconnue : {cmd}").format(cmd=command)}
