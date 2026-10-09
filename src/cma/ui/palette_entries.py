"""Entrées de la palette Ctrl+K : accès Cloudflare et serveurs SSH (le verbe suit l'état réel de chaque accès),
groupes et espaces de travail, actions, objets du compte Cloudflare lu, et pages de la fenêtre."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cma.i18n import tr
from cma.ui.dialogs.diagnose import open_diagnosis
from cma.ui.dialogs.history import show_history
from cma.ui.dialogs.palette import PaletteEntry
from cma.ui.dialogs.workspaces import launch_workspace
from cma.ui.states import RUNNING
from cma.ui.views.cloud.search import palette_entries as cloud_palette_entries

if TYPE_CHECKING:
    from cma.ui.main_window import MainWindow


def build_palette_entries(window: MainWindow) -> list[PaletteEntry]:
    """Toutes les commandes de la palette Ctrl+K, le verbe suivant l'état réel de chaque accès."""
    config = window.ctx.config()
    dashboard = window.dashboard
    running = {r.info.profile_id for r in dashboard.cards.values() if r.info.state in RUNNING}
    entries: list[PaletteEntry] = []
    section = tr("Accès Cloudflare")
    for profile in sorted(config.cloudflare_profiles, key=lambda p: (not p.favorite, p.name.lower())):
        if profile.id in running:
            entries.append(
                PaletteEntry(
                    section,
                    tr("Arrêter « {name} »").format(name=profile.name),
                    lambda p=profile: window.ctx.run(window.ctx.manager.stop_profile(p.id)),
                    profile.hostname,
                    "player-stop-filled",
                    profile.group,
                )
            )
        else:
            entries.append(
                PaletteEntry(
                    section,
                    tr("Connecter « {name} »").format(name=profile.name),
                    lambda p=profile: dashboard.start_cloudflare(p.id),
                    profile.hostname,
                    "player-play-filled",
                    profile.group,
                )
            )
        entries.append(
            PaletteEntry(
                section,
                tr("Diagnostiquer « {name} »").format(name=profile.name),
                lambda p=profile: open_diagnosis(window, window.ctx, p.id),
                profile.hostname,
                "bug",
                profile.group,
            )
        )
        entries.append(
            PaletteEntry(
                section,
                tr("Modifier « {name} »").format(name=profile.name),
                lambda p=profile: window.open_profile(p.id),
                profile.hostname,
                "pencil",
                profile.group,
            )
        )
    section = tr("Serveurs SSH")
    for server in sorted(config.ssh_profiles, key=lambda p: (not p.favorite, p.name.lower())):
        target = f"{server.user}@{server.host}" if server.host else server.user
        entries.append(
            PaletteEntry(
                section,
                tr("Ouvrir le serveur « {name} »").format(name=server.name),
                lambda s=server: window.open_ssh_server(s.id),
                target,
                "server",
                server.group,
            )
        )
        for forward in server.saved_forwards:
            name = f"{server.name} › {forward.short_label}"
            entries.append(
                PaletteEntry(
                    section,
                    tr("Connecter « {name} »").format(name=name),
                    lambda s=server, f=forward: dashboard.start_forward(s.id, f),
                    forward.describe(),
                    "arrows-right-left",
                    server.group,
                )
            )
    section = tr("Groupes et espaces de travail")
    if config.favorite_items():
        entries.append(
            PaletteEntry(section, tr("Connecter tous les favoris"), dashboard.launch_favorites, icon="star")
        )
    for workspace in sorted(config.workspaces, key=lambda w: w.name.lower()):
        entries.append(
            PaletteEntry(
                section,
                tr("Connecter l'espace « {name} »").format(name=workspace.name),
                lambda w=workspace: launch_workspace(window.ctx, w),
                tr("{n} élément(s)").format(n=len(workspace.items)),
                "layout-dashboard",
            )
        )
    for group in sorted({p.group for p in config.cloudflare_profiles if p.group}, key=str.lower):
        entries.append(
            PaletteEntry(
                section,
                tr("Connecter le groupe « {name} »").format(name=group),
                lambda g=group: dashboard.start_group(g),
                icon="player-play-filled",
            )
        )
    section = tr("Actions")
    entries += [
        PaletteEntry(
            section,
            tr("Nouvel accès Cloudflare"),
            window.new_cloudflare_profile,
            icon="plus",
        ),
        PaletteEntry(
            section,
            tr("Nouveau serveur SSH"),
            window.new_ssh_server,
            icon="plus",
        ),
        PaletteEntry(
            section,
            tr("Gérer les espaces de travail…"),
            dashboard.manage_workspaces,
            icon="layout-dashboard",
        ),
        PaletteEntry(
            section,
            tr("Historique des sessions…"),
            lambda: show_history(window, window.ctx),
            icon="history",
        ),
        PaletteEntry(section, tr("Notifications récentes…"), window.open_notifications, icon="bell"),
        PaletteEntry(section, tr("Raccourcis clavier…"), window.open_shortcuts, "F1", "keyboard"),
        PaletteEntry(
            section,
            tr("Quoi de neuf dans CMA…"),
            window.open_whats_new,
            icon="sparkles",
            keywords=tr("nouveautés version notes"),
        ),
    ]
    if window.can_lock():
        entries.append(PaletteEntry(section, tr("Verrouiller CMA"), window.lock_now, "Ctrl+L", "lock"))
    if running:
        entries.append(
            PaletteEntry(
                section,
                tr("Tout arrêter"),
                lambda: window.ctx.run(window.ctx.manager.stop_all()),
                icon="player-stop-filled",
            )
        )
    entries += cloud_palette_entries(window.cloud, lambda: window.show_view("cloud"))
    section = tr("Aller à")
    for key, item in window._nav_items.items():
        entries.append(
            PaletteEntry(
                section, item.text(), lambda k=key: window.show_view(k), icon="arrow-right", keywords=key
            )
        )
    return entries
