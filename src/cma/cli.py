"""Ligne de commande : `cma list`, `cma status`, `cma connect`, `cma disconnect`, `cma doctor`.

Si l'application graphique tourne, les commandes lui sont transmises par le canal local.
Sinon, `cma connect` ouvre la connexion au premier plan jusqu'à Ctrl+C.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from typing import Any

from cma import APP_NAME, __version__
from cma.core.commands import execute, profile_summaries
from cma.core.events import Event, LogLine, Notification, SessionChanged
from cma.core.instance import send_command
from cma.core.prompts import PassphraseRequest, PasswordAnswer, PasswordRequest
from cma.core.secrets import SecretStore
from cma.core.ssh.hostkeys import HostKeyPrompt
from cma.i18n import tr
from cma.paths import AppPaths, resolve_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cma",
        description=tr("Cloudflared Manage Access : accès Cloudflare Access et redirections SSH."),
    )
    parser.add_argument("--version", action="version", version=f"cma {__version__}")
    parser.add_argument("--data-dir", help=tr("dossier de données à utiliser"))
    parser.add_argument(
        "--minimized", action="store_true", help=tr("démarrer réduit dans la zone de notification")
    )
    parser.add_argument(
        "--debug", action="store_true", help=tr("journal détaillé et détection des gels de l'interface")
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMANDE")
    sub.add_parser("gui", help=tr("ouvrir l'interface graphique (par défaut)"))
    listing = sub.add_parser("list", help=tr("lister les profils"))
    listing.add_argument("--json", action="store_true")
    status = sub.add_parser("status", help=tr("sessions ouvertes par l'application en cours"))
    status.add_argument("--json", action="store_true")
    connect = sub.add_parser("connect", help=tr("ouvrir la connexion d'un profil"))
    connect.add_argument("profile", nargs="?", help=tr("nom ou identifiant du profil"))
    connect.add_argument("--group", help=tr("connecter tous les profils Cloudflare de ce groupe"))
    connect.add_argument("--favorites", action="store_true", help=tr("connecter tous les favoris"))
    connect.add_argument("--workspace", help=tr("connecter un espace de travail (nom)"))
    connect.add_argument(
        "--foreground", action="store_true", help=tr("ne pas passer par l'application en cours")
    )
    disconnect = sub.add_parser("disconnect", help=tr("fermer la connexion d'un profil"))
    disconnect.add_argument("profile", nargs="?")
    disconnect.add_argument("--group", help=tr("fermer les connexions de ce groupe"))
    disconnect.add_argument("--all", action="store_true", help=tr("fermer toutes les connexions"))
    tunnels = sub.add_parser(
        "tunnels", help=tr("état des tunnels du compte Cloudflare (code 2 si l'un est en panne)")
    )
    tunnels.add_argument("--json", action="store_true")
    tunnels.add_argument(
        "--notify",
        action="store_true",
        help=tr("notification du système si un tunnel est en panne et que CMA n'est pas ouvert"),
    )
    sub.add_parser("doctor", help=tr("créer un rapport de diagnostic"))
    sub.add_parser("quit", help=tr("fermer l'application en cours (et toutes ses sessions)"))
    return parser


def _print_sessions(sessions: list[dict[str, Any]]) -> None:
    if not sessions:
        print(tr("Aucune session ouverte."))
        return
    for s in sessions:
        message = f"  ({s['message']})" if s.get("message") else ""
        print(f"{s['state_label']:<12} {s['name']:<30} {s['local']:<22} {s['target']}{message}")


class CliPrompter:
    async def confirm_host_key(self, prompt: HostKeyPrompt) -> bool:
        print()
        if prompt.changed:
            print(tr("ATTENTION : la clé d'hôte de {host} a CHANGÉ.").format(host=prompt.identity))
            for fingerprint in prompt.previous_fingerprints:
                print(tr("  ancienne : {fp}").format(fp=fingerprint))
        else:
            print(tr("Premier contact avec {host}.").format(host=prompt.identity))
        print(tr("  clé {alg} : {fp}").format(alg=prompt.algorithm, fp=prompt.fingerprint))
        answer = await asyncio.to_thread(input, tr("Faire confiance à cette clé ? [o/N] "))
        return answer.strip().lower() in ("o", "oui", "y", "yes", "j", "ja", "s", "si", "sí")

    async def ask_password(self, request: PasswordRequest) -> PasswordAnswer | None:
        if request.error:
            print(request.error)
        try:
            value = await asyncio.to_thread(
                getpass.getpass, tr("Mot de passe pour {target} : ").format(target=request.target)
            )
        except (EOFError, KeyboardInterrupt):
            return None
        return PasswordAnswer(value) if value else None

    async def ask_passphrase(self, request: PassphraseRequest) -> str | None:
        if request.error:
            print(request.error)
        try:
            value = await asyncio.to_thread(
                getpass.getpass, tr("Phrase de passe de {key} : ").format(key=request.key_path)
            )
        except (EOFError, KeyboardInterrupt):
            return None
        return value or None


def portable_secret_store(paths: AppPaths) -> SecretStore | None:
    """Version portable : le coffre chiffré de data/, déverrouillé au clavier ; ailleurs, le trousseau du système."""
    if not paths.portable:
        return None
    from cma.core.crypto import WrongPassphraseError
    from cma.core.secrets import EncryptedFileSecretStore, MemorySecretStore

    if not paths.encrypted_secrets_file.exists():
        return MemorySecretStore(reason=tr("coffre portable pas encore créé : lancez l'interface une fois"))
    from cma.core import dpapi

    remembered = dpapi.remembered_passphrase(paths.data_dir)
    if remembered:
        # Phrase de passe mémorisée sur ce poste (DPAPI) : aucune question, utile à la tâche planifiée.
        try:
            return EncryptedFileSecretStore(paths.encrypted_secrets_file, remembered)
        except WrongPassphraseError:
            pass
    try:
        passphrase = getpass.getpass(tr("Phrase de passe du coffre portable : "))
    except (EOFError, KeyboardInterrupt):
        passphrase = ""
    if not passphrase:
        return MemorySecretStore(reason=tr("coffre portable non déverrouillé"))
    try:
        return EncryptedFileSecretStore(paths.encrypted_secrets_file, passphrase)
    except WrongPassphraseError:
        print(tr("Phrase de passe incorrecte."), file=sys.stderr)
        return MemorySecretStore(reason=tr("coffre portable non déverrouillé"))


def show_tunnels(
    paths: AppPaths,
    *,
    as_json: bool,
    secrets: SecretStore | None = None,
    base_url: str | None = None,
    notify: bool = False,
) -> int:
    """État des tunnels du compte choisi dans CMA, avec le jeton d'API du coffre.

    Code de retour : 0 si tout va bien, 2 si un tunnel est dégradé ou hors ligne, 1 si la lecture échoue. Une
    supervision (tâche planifiée, script) peut s'en servir sans ouvrir l'interface.

    `notify` (tâche planifiée) : notification du système si un tunnel est en panne, seulement quand CMA n'est pas
    ouvert (sinon il surveille déjà et prévient lui-même). Une lecture en échec ne notifie rien.
    """
    from cma.core.cfadmin import CloudflareAdmin
    from cma.core.cfapi import API_BASE, CloudflareApiError
    from cma.core.config_store import ConfigStore
    from cma.core.secrets import open_secret_store
    from cma.core.tunnelwatch import severity, status_label, troubled_summary

    store = ConfigStore(paths)
    store.load()
    vault = secrets or portable_secret_store(paths) or open_secret_store()
    admin = CloudflareAdmin(store, vault, lambda _port, _taken: None, base_url=base_url or API_BASE)
    try:
        tunnels = asyncio.run(admin.tunnel_states())
    except (CloudflareApiError, OSError) as exc:
        print(tr("Erreur : {error}").format(error=exc), file=sys.stderr)
        return 1
    if as_json:
        rows = [
            {"id": t.id, "name": t.name, "status": t.status, "label": status_label(t.status)} for t in tunnels
        ]
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    elif not tunnels:
        print(tr("Aucun tunnel disponible dans ce compte."))
    else:
        for tunnel in tunnels:
            mark = "!" if severity(tunnel.status) else " "
            print(f"{mark} {status_label(tunnel.status):<12} {tunnel.name}")
    troubled = [t for t in tunnels if severity(t.status)]
    if notify and troubled and send_command(paths, {"cmd": "status"}, timeout=5) is None:
        from cma.platform.notify import system_notification

        system_notification(
            APP_NAME, troubled_summary(troubled) + " — " + tr("ouvrez CMA pour le diagnostic.")
        )
    return 2 if troubled else 0


async def _foreground_connect(args: argparse.Namespace) -> int:
    from cma.context import create_context
    from cma.logging_setup import setup_logging

    paths = resolve_paths(args.data_dir)
    setup_logging(paths, "DEBUG" if args.debug else "INFO", console=True)
    ctx = create_context(paths, CliPrompter(), secrets=portable_secret_store(paths))
    for warning in ctx.warnings:
        print(tr("Avertissement : {text}").format(text=warning), file=sys.stderr)

    def on_event(event: Event) -> None:
        if isinstance(event, SessionChanged):
            info = event.info
            suffix = f" : {info.message}" if info.message else ""
            print(f"[{info.state.label}] {info.name} {info.local_address}{suffix}")
        elif isinstance(event, Notification):
            print(f"! {event.title} : {event.message}")
        elif isinstance(event, LogLine) and event.level in ("WARNING", "ERROR") and args.debug:
            print(f"  {event.source_label} {event.level} {event.message}")

    ctx.bus.subscribe(on_event)
    reply = await execute(ctx.manager, connect_message(args))
    if not reply.get("ok"):
        print(tr("Erreur : {error}").format(error=reply.get("error")), file=sys.stderr)
        await ctx.manager.shutdown()
        return 1
    print(tr("Connexion ouverte au premier plan. Ctrl+C pour l'arrêter."))
    try:
        while (
            any(s.state.active for s in ctx.manager.sessions.values()) or ctx.manager.ssh.connected_profiles()
        ):
            await asyncio.sleep(1)
        return 1
    except asyncio.CancelledError:
        return 0
    finally:
        await ctx.manager.shutdown()


def connect_message(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "cmd": "connect",
        "profile": args.profile,
        "group": args.group,
        "favorites": getattr(args, "favorites", False),
        "workspace": getattr(args, "workspace", None),
    }


def run(args: argparse.Namespace) -> int:
    paths = resolve_paths(args.data_dir)
    command = args.command

    if command == "list":
        from cma.core.config_store import ConfigStore

        store = ConfigStore(paths)
        store.load()
        profiles = profile_summaries(store.snapshot())
        if args.json:
            print(json.dumps(profiles, indent=2, ensure_ascii=False))
        else:
            for p in profiles:
                print(f"{p['type']:<11} {p['name']:<30} {p['target']:<40} {p['local']}")
        return 0

    if command == "tunnels":
        return show_tunnels(paths, as_json=args.json, notify=args.notify)

    if command == "doctor":
        from cma.core.config_store import ConfigStore
        from cma.core.diagnostics import build_report

        store = ConfigStore(paths)
        store.load()
        print(build_report(paths, store))
        return 0

    if command == "status":
        reply = send_command(paths, {"cmd": "status"})
        if reply is None:
            print(tr("Aucune instance de l'application n'est en cours."))
            return 1
        if args.json:
            print(json.dumps(reply.get("sessions", []), indent=2, ensure_ascii=False))
        else:
            _print_sessions(reply.get("sessions", []))
        return 0 if reply.get("ok") else 1

    if command == "quit":
        reply = send_command(paths, {"cmd": "quit"})
        if reply is None:
            print(tr("Aucune instance de l'application n'est en cours."))
            return 1
        return 0

    if command == "disconnect":
        if not args.all and not args.profile and not args.group:
            print(tr("Indiquez un profil, --group ou --all."), file=sys.stderr)
            return 2
        reply = send_command(
            paths, {"cmd": "disconnect", "profile": args.profile, "group": args.group, "all": args.all}
        )
        if reply is None:
            print(tr("Aucune instance de l'application n'est en cours."))
            return 1
        if not reply.get("ok"):
            print(tr("Erreur : {error}").format(error=reply.get("error")), file=sys.stderr)
            return 1
        return 0

    if command == "connect":
        if not (args.profile or args.group or args.favorites or args.workspace):
            print(tr("Indiquez un profil, --group, --favorites ou --workspace."), file=sys.stderr)
            return 2
        if not args.foreground:
            reply = send_command(paths, connect_message(args), timeout=120)
            if reply is not None:
                if not reply.get("ok"):
                    print(tr("Erreur : {error}").format(error=reply.get("error")), file=sys.stderr)
                    return 1
                _print_sessions(reply.get("sessions", []))
                if reply.get("message"):
                    print(reply["message"])
                return 0
            print(tr("Aucune instance graphique en cours : connexion au premier plan."))
        try:
            return asyncio.run(_foreground_connect(args))
        except KeyboardInterrupt:
            return 0

    build_parser().print_help()
    return 2
