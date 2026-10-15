"""Ligne de commande : `cma list`, `cma status`, `cma connect`, `cma disconnect`, `cma doctor`.

Si l'application graphique tourne, les commandes lui sont transmises par le canal local.
Sinon, `cma connect` ouvre la connexion au premier plan jusqu'à Ctrl+C.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import io
import json
import sys
from pathlib import Path
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
    tunnels.add_argument(
        "--services",
        action="store_true",
        help=tr("tester aussi depuis Internet les services HTTP publiés (code 2 si l'un est en panne)"),
    )
    sub.add_parser(
        "snapshot",
        help=tr(
            "enregistrer un instantané de la configuration Cloudflare et dire ce qui a changé depuis le précédent "
            "(code 2 si quelque chose a changé)"
        ),
    )
    review = sub.add_parser(
        "review",
        help=tr(
            "bilan de sécurité du compte Cloudflare (code 2 si un constat de gravité élevée n'est pas ignoré)"
        ),
    )
    review.add_argument("--json", action="store_true")
    review.add_argument("--all", action="store_true", help=tr("montrer aussi les constats ignorés"))
    alerts = sub.add_parser("alerts", help=tr("canaux d'alerte"))
    alerts_sub = alerts.add_subparsers(dest="alerts_command", metavar="ACTION")
    alerts_sub.add_parser("test", help=tr("envoyer un test à chaque canal actif (code 1 si l'un échoue)"))
    alerts_sub.add_parser(
        "digest",
        help=tr(
            "envoyer tout de suite le résumé de la semaine à chaque canal actif (code 1 sans canal ou en échec)"
        ),
    )
    availability = sub.add_parser(
        "availability",
        help=tr("disponibilité des tunnels et services relevés (code 2 si un incident est en cours)"),
    )
    availability.add_argument("--days", type=int, default=30, choices=(1, 7, 30, 90))
    availability.add_argument("--json", action="store_true")
    availability.add_argument(
        "--output",
        metavar="FICHIER",
        help=tr("écrire le rapport dans un fichier .html, .csv ou .json (selon l'extension)"),
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
    services: bool = False,
) -> int:
    """État des tunnels du compte choisi dans CMA, avec le jeton d'API du coffre.

    Code de retour : 0 si tout va bien, 2 si un tunnel est dégradé ou hors ligne (ou, avec `services`, si un
    service publié ne répond plus), 1 si la lecture échoue. Une supervision (tâche planifiée, script) peut s'en
    servir sans ouvrir l'interface.

    `notify` (tâche planifiée) : notification du système si un tunnel ou un service est en panne, seulement quand
    CMA n'est pas ouvert (sinon il surveille déjà et prévient lui-même). Les services y sont testés si le réglage
    « Tester aussi les services publiés » est actif. Une lecture en échec ne notifie rien.
    """
    from datetime import datetime

    from cma.core.cfadmin import CloudflareAdmin
    from cma.core.cfapi import API_BASE, CloudflareApiError
    from cma.core.config_store import ConfigStore
    from cma.core.secrets import open_secret_store
    from cma.core.servicewatch import ServiceResult
    from cma.core.servicewatch import severity as service_severity
    from cma.core.tunnelwatch import severity, status_label

    store = ConfigStore(paths)
    store.load()
    vault = secrets or portable_secret_store(paths) or open_secret_store()
    admin = CloudflareAdmin(store, vault, lambda _port, _taken: None, base_url=base_url or API_BASE)
    check_services = services or (notify and store.snapshot().settings.watch_services)
    try:
        tunnels = asyncio.run(admin.tunnel_states())
    except (CloudflareApiError, OSError) as exc:
        print(tr("Erreur : {error}").format(error=exc), file=sys.stderr)
        return 1
    services_complete = False
    try:
        tested = asyncio.run(admin.check_services()) if check_services else []
        services_complete = bool(check_services)
    except (CloudflareApiError, OSError) as exc:
        if services:
            print(tr("Erreur : {error}").format(error=exc), file=sys.stderr)
            return 1
        tested = []  # tâche planifiée : l'état des tunnels suffit à prévenir
    rows = [
        {"id": t.id, "name": t.name, "status": t.status, "label": status_label(t.status)} for t in tunnels
    ]
    if as_json and services:
        checks = [
            {
                "hostname": t.label,
                "tunnel": t.tunnel_name,
                "state": p.state,
                "status": p.status,
                "summary": p.summary(t.label),
            }
            for t, p in tested
        ]
        print(json.dumps({"tunnels": rows, "services": checks}, indent=2, ensure_ascii=False))
    elif as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    elif not tunnels:
        print(tr("Aucun tunnel disponible dans ce compte."))
    else:
        for tunnel in tunnels:
            mark = "!" if severity(tunnel.status) else " "
            print(f"{mark} {status_label(tunnel.status):<12} {tunnel.name}")
        if services:
            print()
            for target, probe in tested:
                mark = "!" if service_severity(probe.state) else " "
                print(f"{mark} {probe.summary(target.label)}")
    troubled = [t for t in tunnels if severity(t.status)]
    now = datetime.now()
    down = [ServiceResult(t, p, now) for t, p in tested if service_severity(p.state)]
    if notify and send_command(paths, {"cmd": "status"}, timeout=5) is None:
        # CMA fermé : la tâche tient le journal de disponibilité, et ne prévient qu'à un changement (nouvelle panne
        # ou retour), pas à chaque passage tant que la panne dure.
        _record_and_alert(
            paths, store.snapshot(), vault, tunnels, tested, services_complete=services_complete
        )
    return 2 if troubled or down else 0


def _record_and_alert(
    paths: AppPaths,
    config: Any,
    secrets: SecretStore,
    tunnels: list[Any],
    tested: list[Any],
    *,
    services_complete: bool = False,
) -> None:
    """`services_complete` : le relevé des services a réussi (une liste vide veut alors dire « plus aucun nom »)."""
    from cma.core.alertstate import AlertState, state_path
    from cma.core.availability import AvailabilityLog
    from cma.core.monitoring import (
        deliver_follow_up,
        prepare_follow_up,
        record_services,
        record_tunnels,
        send_events,
        service_key,
    )
    from cma.platform.notify import system_notification

    log = AvailabilityLog(paths.data_dir / "availability.json")
    events = record_tunnels(log, config, tunnels) + record_services(
        log, config, tested, complete=True if services_complete else None
    )
    with contextlib.suppress(OSError):  # un journal non écrit ne doit pas empêcher de prévenir
        log.save()
    shown = [e for e in events if not e.muted]
    problems = [e.label for e in shown if not e.recovered]
    back = [e.label for e in shown if e.recovered]
    if len(shown) == 1:
        text = shown[0].text
    else:
        parts = []
        if problems:
            parts.append(tr("En panne : {list}").format(list=", ".join(problems)))
        if back:
            parts.append(tr("Rétablis : {list}").format(list=", ".join(back)))
        text = " · ".join(parts)
    if text:
        if problems:
            text += " " + tr("Ouvrez CMA pour le diagnostic.")
        system_notification(APP_NAME, text)
    send_events(events, config, secrets)
    # Rappels des pannes qui durent et résumé du lundi : la tâche n'écrit `alert_state.json` que si CMA est fermé,
    # comme le journal (cette fonction n'est appelée que dans ce cas).
    if config.settings.alert_channels:
        plan = prepare_follow_up(
            log,
            config,
            AlertState(state_path(paths.data_dir)),
            check_digest=True,
            tunnel_of={service_key(target): target.tunnel_id for target, _probe in tested},
        )
        deliver_follow_up(plan, config, secrets)


def _admin(paths: AppPaths, secrets: SecretStore | None, base_url: str | None) -> Any:
    from cma.core.cfadmin import CloudflareAdmin
    from cma.core.cfapi import API_BASE
    from cma.core.config_store import ConfigStore
    from cma.core.secrets import open_secret_store

    store = ConfigStore(paths)
    store.load()
    vault = secrets or portable_secret_store(paths) or open_secret_store()
    return CloudflareAdmin(store, vault, lambda _port, _taken: None, base_url=base_url or API_BASE)


def show_review(
    paths: AppPaths,
    *,
    as_json: bool = False,
    include_ignored: bool = False,
    secrets: SecretStore | None = None,
    base_url: str | None = None,
) -> int:
    """Bilan de sécurité du compte choisi dans CMA. Code 0 : rien d'élevé ; 2 : au moins un constat élevé non
    ignoré ; 1 : lecture impossible. Les constats ignorés dans l'interface le restent ici."""
    from cma.core.cfapi import CloudflareApiError
    from cma.core.security import severity_label

    admin = _admin(paths, secrets, base_url)
    try:
        findings = asyncio.run(admin.security_review())
    except (CloudflareApiError, OSError) as exc:
        print(tr("Erreur : {error}").format(error=exc), file=sys.stderr)
        return 1
    ignored = set(admin.store.snapshot().settings.ignored_findings)
    shown = [f for f in findings if include_ignored or f.ident not in ignored]
    if as_json:
        rows = [
            {
                "severity": f.severity,
                "kind": f.kind,
                "title": f.title(),
                "target": f.target,
                "fix": f.fix or None,
                "ignored": f.ident in ignored,
                "detail": f.detail(),
            }
            for f in shown
        ]
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    elif not shown:
        print(tr("Aucun constat : rien à signaler sur ce compte."))
    else:
        for finding in shown:
            mark = tr("(ignoré)") if finding.ident in ignored else ""
            print(
                f"{severity_label(finding.severity):<8} {finding.title()} : {finding.target} {mark}".rstrip()
            )
    high = [f for f in findings if f.severity == "high" and f.ident not in ignored]
    return 2 if high else 0


def send_test_alerts(paths: AppPaths, *, secrets: SecretStore | None = None) -> int:
    """Un test vers chaque canal actif. Code 0 si tous l'ont accepté ; 1 sinon (ou sans canal)."""
    from cma.core.alerts import Alert, AlertError, send_alert
    from cma.core.config_store import ConfigStore
    from cma.core.monitoring import channels
    from cma.core.secrets import open_secret_store

    store = ConfigStore(paths)
    store.load()
    vault = secrets or portable_secret_store(paths) or open_secret_store()
    targets = channels(store.snapshot(), vault)
    if not targets:
        print(
            tr("Aucun canal d'alerte actif : ajoutez-en un dans Paramètres › Général › Alertes."),
            file=sys.stderr,
        )
        return 1
    alert = Alert(
        tr("CMA — test d'alerte"), tr("Ce canal recevra les pannes et les retours de vos services."), "info"
    )
    failed = 0
    for name, kind, url, _recoveries in targets:
        try:
            send_alert(kind, url, alert)
        except AlertError as exc:
            failed += 1
            print(f"✗ {name} : {exc}")
        else:
            print(f"✓ {name}")
    return 1 if failed else 0


def send_digest(paths: AppPaths, *, secrets: SecretStore | None = None) -> int:
    """Le résumé de la semaine, tout de suite, vers chaque canal actif. Code 0 si tous l'ont accepté ; 1 sinon (ou
    sans canal). N'écrit pas `alert_state.json` : le résumé automatique du lundi part quand même."""
    from cma.core.alerts import AlertError, send_alert
    from cma.core.availability import AvailabilityLog
    from cma.core.config_store import ConfigStore
    from cma.core.digest import build_digest
    from cma.core.monitoring import channels
    from cma.core.secrets import open_secret_store

    store = ConfigStore(paths)
    store.load()
    vault = secrets or portable_secret_store(paths) or open_secret_store()
    config = store.snapshot()
    targets = channels(config, vault)
    if not targets:
        print(
            tr("Aucun canal d'alerte actif : ajoutez-en un dans Paramètres › Général › Alertes."),
            file=sys.stderr,
        )
        return 1
    alert = build_digest(AvailabilityLog(paths.data_dir / "availability.json"), config)
    failed = 0
    for name, kind, url, _recoveries in targets:
        try:
            send_alert(kind, url, alert)
        except AlertError as exc:
            failed += 1
            print(f"✗ {name} : {exc}")
        else:
            print(f"✓ {name}")
    return 1 if failed else 0


def write_availability_report(path: Path, rows: list[Any], incidents: list[Any], days: int) -> None:
    """Rapport de disponibilité dans un fichier : CSV (avec BOM pour Excel), JSON ou HTML selon l'extension."""
    from cma.core.availability_report import report_csv, report_html, report_json
    from cma.core.fsutil import atomic_write_text

    suffix = path.suffix.lower()
    if suffix == ".csv":
        atomic_write_text(path, "﻿" + report_csv(rows, incidents))
    elif suffix == ".json":
        atomic_write_text(path, report_json(rows, incidents, days) + "\n")
    elif suffix in (".html", ".htm"):
        atomic_write_text(path, report_html(rows, incidents, days))
    else:
        raise ValueError(
            tr("Extension inconnue « {suffix} » : utilisez .html, .csv ou .json.").format(suffix=suffix)
        )


def show_availability(
    paths: AppPaths, *, days: int = 30, as_json: bool = False, output: str | None = None
) -> int:
    """Disponibilité lue dans le journal tenu par la surveillance. Code 2 si un incident est encore ouvert ; avec
    `output`, le rapport est écrit dans ce fichier (le code de retour ne change pas, 1 si l'écriture échoue)."""
    from cma.core.availability import AvailabilityLog
    from cma.core.availability_report import build, report_json

    log = AvailabilityLog(paths.data_dir / "availability.json")
    rows, incidents = build(log, days)
    if output:
        try:
            write_availability_report(Path(output), rows, incidents, days)
        except (OSError, ValueError) as exc:
            print(tr("Erreur : {error}").format(error=exc), file=sys.stderr)
            return 1
        print(tr("Rapport enregistré : {file}").format(file=output))
    elif as_json:
        print(report_json(rows, incidents, days))
    elif not rows:
        print(tr("Aucun relevé : la surveillance remplit ce journal (CMA ouvert, ou la tâche planifiée)."))
    else:
        for row in rows:
            uptime = f"{row.stats.uptime * 100:6.2f} %" if row.stats.uptime is not None else "     — "
            mean = f"{row.stats.mean_ms:5.0f} ms" if row.stats.mean_ms is not None else "        "
            print(f"{uptime}  {mean}  {row.incidents:>3}  {row.label}")
    return 2 if any(i.open for i in incidents) else 0


def take_snapshot_cli(
    paths: AppPaths, *, secrets: SecretStore | None = None, base_url: str | None = None
) -> int:
    """Instantané du compte choisi dans CMA, enregistré avec ceux de l'interface, puis comparé au précédent.

    Code de retour : 0 sans changement (ou premier instantané), 2 si la configuration a changé, 1 si la lecture
    échoue.
    """
    from cma.core.cfadmin import CloudflareAdmin
    from cma.core.cfapi import API_BASE, Account, CloudflareApiError
    from cma.core.config_store import ConfigStore
    from cma.core.secrets import open_secret_store
    from cma.core.snapshot import diff_snapshots, list_snapshots, load_snapshot, save_snapshot, section_label

    store = ConfigStore(paths)
    store.load()
    vault = secrets or portable_secret_store(paths) or open_secret_store()
    admin = CloudflareAdmin(store, vault, lambda _port, _taken: None, base_url=base_url or API_BASE)
    directory = paths.data_dir / "snapshots"
    try:
        account_id = admin.account_id()
        api = admin.api()
        try:
            names = {a.id: a.name for a in api.list_accounts()}
        except CloudflareApiError:
            names = {}
        previous = list_snapshots(directory, account_id)
        snapshot = asyncio.run(admin.snapshot(Account(account_id, names.get(account_id, account_id))))
    except (CloudflareApiError, OSError) as exc:
        print(tr("Erreur : {error}").format(error=exc), file=sys.stderr)
        return 1
    path = save_snapshot(directory, snapshot)
    print(tr("Instantané enregistré : {path}").format(path=path))
    if not previous:
        return 0
    changes = diff_snapshots(load_snapshot(previous[0].path), snapshot)
    if not changes:
        print(tr("Aucun changement depuis le précédent."))
        return 0
    marks = {"added": "+", "removed": "-", "changed": "~"}
    for change in changes:
        print(f"{marks.get(change.kind, '?')} {section_label(change.section)} · {change.name}")
        for detail in change.details:
            print(f"    {detail}")
    return 2


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


def safe_output() -> None:
    """Sortie redirigée vers un fichier ou un autre programme : sous Windows, elle est encodée en cp1252, qui ne
    connaît ni « ✓ » ni « → ». Un caractère impossible devient « ? » au lieu d'arrêter la commande."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="replace")


def run(args: argparse.Namespace) -> int:
    safe_output()
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
        return show_tunnels(paths, as_json=args.json, notify=args.notify, services=args.services)

    if command == "review":
        return show_review(paths, as_json=args.json, include_ignored=args.all)

    if command == "alerts":
        if args.alerts_command == "digest":
            return send_digest(paths)
        if args.alerts_command != "test":
            print(tr("Action attendue : cma alerts test ou cma alerts digest"), file=sys.stderr)
            return 1
        return send_test_alerts(paths)

    if command == "availability":
        return show_availability(paths, days=args.days, as_json=args.json, output=args.output)

    if command == "snapshot":
        return take_snapshot_cli(paths)

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
