"""« Quoi de neuf » : notes des versions installées depuis la dernière ouverture de CMA.

Montrée une fois après une mise à jour (jamais à la première installation), et à la demande depuis Paramètres ›
À propos ou la palette. Les notes viennent du CHANGELOG embarqué (`cma.core.changelog`) ; elles sont en français.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog, QHBoxLayout, QTextBrowser, QVBoxLayout, QWidget

from cma import REPO_URL, __version__
from cma.core.changelog import Release, changelog_text, new_since, recent, version_key
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.widgets import button, label, primary_button, title

if TYPE_CHECKING:
    from cma.ui.main_window import MainWindow

RELEASES_URL = f"{REPO_URL}/releases"


def release_markdown(releases: list[Release]) -> str:
    parts: list[str] = []
    for release in releases:
        heading = f"## {release.version}" + (f" · {release.date}" if release.date else "")
        parts.append(f"{heading}\n\n{release.body}")
    return "\n\n".join(parts)


class WhatsNewDialog(QDialog):
    def __init__(self, parent: QWidget | None, releases: list[Release], language: str = "fr") -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Quoi de neuf dans CMA"))
        self.setWindowIcon(app_icon())
        self.resize(780, 620)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Quoi de neuf dans CMA"), "SectionTitle"))
        if releases:
            intro = tr("Version installée : {version}.").format(version=__version__)
            if language != "fr":
                intro += " " + tr("Les notes de version sont rédigées en français.")
        else:
            intro = tr(
                "Les notes de version ne sont pas incluses dans cette installation : voyez la page des versions."
            )
        layout.addWidget(label(intro, "muted", wrap=True))
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        self.browser.setAccessibleName(tr("Notes de version"))
        self.browser.setMarkdown(release_markdown(releases))
        self.browser.setVisible(bool(releases))
        layout.addWidget(self.browser, 1)
        footer = QHBoxLayout()
        all_versions = button(tr("Toutes les versions sur GitHub"), "brand-github")
        all_versions.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(RELEASES_URL)))
        footer.addWidget(all_versions)
        footer.addStretch()
        close = primary_button(tr("Fermer"))
        close.setDefault(True)
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)


def show_whats_new(parent: QWidget | None, releases: list[Release], language: str = "fr") -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    WhatsNewDialog(parent, releases, language).exec()


def open_whats_new(parent: QWidget | None, language: str = "fr") -> None:
    """Depuis l'aide : les notes de la version installée et des deux précédentes."""
    text = changelog_text()
    show_whats_new(parent, recent(text, __version__) if text else [], language)


def releases_to_announce(ctx: GuiContext, *, fresh: bool) -> list[Release]:
    """Notes à montrer au démarrage, une seule fois par version. La version est notée dans tous les cas ; une
    première installation (`fresh`) ou un retour à une version plus ancienne ne montre rien."""
    seen = ctx.config().settings.last_seen_version
    if seen == __version__:
        return []
    ctx.update_config(lambda c: setattr(c.settings, "last_seen_version", __version__))
    if fresh or (seen is not None and version_key(__version__) <= version_key(seen)):
        return []
    text = changelog_text()
    return new_since(text, seen, __version__) if text else []


def announce_update(window: MainWindow, releases: list[Release]) -> None:
    """Après une mise à jour : la boîte si la fenêtre est affichée ; sinon (démarrage dans la zone de notification),
    une notification discrète, sans bulle, dont l'action ouvre la boîte."""
    if not releases:
        return
    language = window.ctx.config().settings.language

    def show() -> None:
        show_whats_new(window, releases, language)

    if window.isVisible() and not window.isMinimized():
        show()
        return
    window.notices.add(
        "info",
        tr("CMA est passé en version {version}.").format(version=__version__),
        (tr("Quoi de neuf"), show),
    )
    window._update_notices()  # pyright: ignore[reportPrivateUsage]
