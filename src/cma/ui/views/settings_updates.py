"""Mises à jour depuis les Paramètres : cloudflared (téléchargé, vérifié par SHA-256 et signature) et CMA lui-même
(installeur, version portable ou AppImage). Les champs et l'état (version installée, dernière version connue)
appartiennent à la vue des Paramètres, lue par `self.view`."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QMessageBox

from cma import REPO_URL
from cma.core.cloudflared.binary import (
    ReleaseInfo,
    asset_name,
    download_release_binary,
    fetch_latest_release,
    is_newer,
)
from cma.core.updates import (
    UpdateInfo,
    appimage_path,
    check_for_update,
    download_asset,
    download_installer,
    download_portable,
    install_appimage,
    launch_installer,
    launch_portable_update,
    prepare_portable,
    relaunch_after_exit,
    update_mode,
)
from cma.i18n import tr

if TYPE_CHECKING:
    from cma.ui.views.settings import SettingsView


class UpdateActions:
    def __init__(self, view: SettingsView) -> None:
        self.view = view
        self.ctx = view.ctx

    def check_cloudflared_release(self, *, quiet: bool = False) -> None:
        self.view.check_button.setEnabled(False)
        cache = self.ctx.paths.cache_dir / "cloudflared-release.json"

        async def fetch() -> ReleaseInfo:
            return await asyncio.to_thread(fetch_latest_release, cache, max_age=0 if not quiet else 86400)

        def done(release: ReleaseInfo) -> None:
            self.view.check_button.setEnabled(True)
            self.view._release = release
            self._update_download_state()

        def failed(error: BaseException) -> None:
            self.view.check_button.setEnabled(True)
            if not quiet:
                self.ctx.notify("error", tr("Impossible de joindre GitHub : {error}").format(error=error))

        self.ctx.run(fetch(), done, failed)

    def _update_download_state(self) -> None:
        release = self.view._release
        if release is None:
            self.view.release_label.setText("")
            self.view.download_button.setEnabled(False)
            return
        newer = is_newer(release.version, self.view._installed_version)
        if self.view._installed_version is None:
            text = tr("Dernière version : {v}.").format(v=release.version)
        elif newer:
            text = tr("Mise à jour disponible : {v} (installée : {cur}).").format(
                v=release.version, cur=self.view._installed_version
            )
        else:
            text = tr("Vous avez la dernière version ({v}).").format(v=release.version)
        self.view.release_label.setText(
            text + " " + tr("Fichier : {name}, vérifié par SHA-256 et signature.").format(name=asset_name())
        )
        self.view.download_button.setEnabled(self.view._installed_version is None or newer)
        self.view.download_button.setText(
            tr("Mettre à jour") if self.view._installed_version else tr("Télécharger")
        )

    def _download(self) -> None:
        release = self.view._release
        if release is None:
            return
        self.view.download_button.setEnabled(False)
        self.view.progress.setValue(0)
        self.view.progress.show()
        self.view._cancel_download.clear()

        def progress(received: int, total: int | None) -> None:
            self.view.download_progress.emit(received, total)

        async def run() -> Path:
            return await asyncio.to_thread(
                download_release_binary,
                release,
                self.ctx.paths.bin_dir,
                progress=progress,
                cancel=self.view._cancel_download,
            )

        def done(path: Path) -> None:
            self.view.progress.hide()
            self.ctx.update_config(lambda c: setattr(c.settings, "cloudflared_path", str(path)))
            self.ctx.notify(
                "success",
                tr("cloudflared {v} installé et vérifié : {path}").format(v=release.version, path=path),
            )
            self.view.refresh_cloudflared_version()

        def failed(error: BaseException) -> None:
            self.view.progress.hide()
            self.view.download_button.setEnabled(True)
            self.ctx.notify("error", str(error))

        self.ctx.run(run(), done, failed)

    def _on_progress(self, received: int, total: object) -> None:
        if isinstance(total, int) and total > 0:
            self.view.progress.setMaximum(1000)
            self.view.progress.setValue(int(received * 1000 / total))
        else:
            self.view.progress.setMaximum(0)

    def _on_cma_progress(self, received: int, total: object) -> None:
        if isinstance(total, int) and total > 0:
            self.view.cma_progress_bar.setMaximum(1000)
            self.view.cma_progress_bar.setValue(int(received * 1000 / total))
        else:
            self.view.cma_progress_bar.setMaximum(0)

    def install_cma_update(self) -> None:
        info = self.view._cma_update
        if info is not None and update_mode() == "portable":
            self._install_portable_update(info)
            return
        if info is not None and update_mode() == "appimage":
            self._install_appimage_update(info)
            return
        if info is None or info.installer is None:
            return
        answer = QMessageBox.question(
            self.view,
            tr("Mettre à jour CMA"),
            tr(
                "La version {v} va être téléchargée et vérifiée. CMA se fermera ensuite (les sessions "
                "ouvertes seront arrêtées), s'installera puis redémarrera. Continuer ?"
            ).format(v=info.latest),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.view.cma_install.setEnabled(False)
        self.view.cma_progress_bar.setValue(0)
        self.view.cma_progress_bar.show()

        def progress(received: int, total: int | None) -> None:
            self.view.cma_progress.emit(received, total)

        async def run() -> Path:
            return await asyncio.to_thread(
                download_installer, info, self.ctx.paths.cache_dir / "updates", progress=progress
            )

        def done(installer: Path) -> None:
            self.view.cma_progress_bar.hide()
            launch_installer(installer)
            window = self.view.window()
            quit_now = getattr(window, "quit_now", None)
            if callable(quit_now):
                quit_now()

        def failed(error: BaseException) -> None:
            self.view.cma_progress_bar.hide()
            self.view.cma_install.setEnabled(True)
            self.ctx.notify("error", str(error))

        self.ctx.run(run(), done, failed)

    def _install_portable_update(self, info: UpdateInfo) -> None:
        """Version portable : zip vérifié, fichiers du programme remplacés après fermeture, data/ conservé."""
        if info.portable_zip is None:
            return
        answer = QMessageBox.question(
            self.view,
            tr("Mettre à jour CMA"),
            tr(
                "La version {v} va être téléchargée et vérifiée. CMA se fermera (les sessions ouvertes seront "
                "arrêtées), remplacera ses fichiers en gardant le dossier data/, puis redémarrera. Continuer ?"
            ).format(v=info.latest),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.view.cma_install.setEnabled(False)
        self.view.cma_progress_bar.setValue(0)
        self.view.cma_progress_bar.show()
        updates_dir = self.ctx.paths.cache_dir / "updates"
        staging = updates_dir / "portable"
        app_dir = Path(sys.executable).resolve().parent

        def progress(received: int, total: int | None) -> None:
            self.view.cma_progress.emit(received, total)

        async def run() -> Path:
            archive = await asyncio.to_thread(download_portable, info, updates_dir, progress=progress)
            return await asyncio.to_thread(prepare_portable, archive, staging)

        def done(new_app: Path) -> None:
            self.view.cma_progress_bar.hide()
            launch_portable_update(new_app, app_dir, staging)
            window = self.view.window()
            quit_now = getattr(window, "quit_now", None)
            if callable(quit_now):
                quit_now()

        def failed(error: BaseException) -> None:
            self.view.cma_progress_bar.hide()
            self.view.cma_install.setEnabled(True)
            self.ctx.notify("error", str(error))

        self.ctx.run(run(), done, failed)

    def _install_appimage_update(self, info: UpdateInfo) -> None:
        """AppImage Linux : fichier vérifié, puis remplacé d'un coup ; CMA se relance sur la nouvelle version."""
        target, asset = appimage_path(), info.appimage
        if target is None or asset is None:
            return
        answer = QMessageBox.question(
            self.view,
            tr("Mettre à jour CMA"),
            tr(
                "La version {v} va être téléchargée et vérifiée, puis remplacer {path}. CMA se fermera ensuite "
                "(les sessions ouvertes seront arrêtées) et redémarrera. Continuer ?"
            ).format(v=info.latest, path=target),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.view.cma_install.setEnabled(False)
        self.view.cma_progress_bar.setValue(0)
        self.view.cma_progress_bar.show()
        updates_dir = self.ctx.paths.cache_dir / "updates"

        def progress(received: int, total: int | None) -> None:
            self.view.cma_progress.emit(received, total)

        async def run() -> Path:
            downloaded = await asyncio.to_thread(download_asset, info, asset, updates_dir, progress=progress)
            try:
                return await asyncio.to_thread(install_appimage, downloaded, target)
            finally:
                downloaded.unlink(missing_ok=True)

        def done(installed: Path) -> None:
            self.view.cma_progress_bar.hide()
            relaunch_after_exit(installed)
            window = self.view.window()
            quit_now = getattr(window, "quit_now", None)
            if callable(quit_now):
                quit_now()

        def failed(error: BaseException) -> None:
            self.view.cma_progress_bar.hide()
            self.view.cma_install.setEnabled(True)
            self.ctx.notify("error", str(error))

        self.ctx.run(run(), done, failed)

    def check_cma_update(self, *, quiet: bool = False) -> None:
        async def fetch() -> UpdateInfo:
            return await asyncio.to_thread(check_for_update)

        def done(info: UpdateInfo) -> None:
            self.view._cma_update = info
            mode = update_mode()
            asset = info.asset_for(mode)
            installable = info.available and asset is not None and self.view.self_update_possible()
            self.view.cma_install.setVisible(installable)
            if info.latest is None:
                self.view.cma_update_label.setText(tr("Aucune version publiée pour l'instant."))
            elif info.available:
                text = tr("Version {v} disponible.").format(v=info.latest)
                if mode == "scoop":
                    text += " " + tr("Mettez à jour avec Scoop : scoop update cloudflared-manage-access")
                elif not installable:
                    text += " " + tr(
                        "Mise à jour automatique réservée à la version installée : "
                        "téléchargez-la depuis la page de la release."
                    )
                self.view.cma_update_label.setText(text)
                action = (
                    (tr("Installer"), self.install_cma_update)
                    if installable
                    else (tr("Voir"), lambda: QDesktopServices.openUrl(QUrl(info.url or REPO_URL)))
                )
                self.ctx.notify(
                    "info",
                    tr("Une nouvelle version de CMA est disponible : {v}.").format(v=info.latest),
                    action=action,
                )
            else:
                self.view.cma_update_label.setText(tr("Vous utilisez la dernière version."))

        def failed(error: BaseException) -> None:
            if not quiet:
                self.view.cma_update_label.setText(
                    tr("Vérification impossible : {error}").format(error=error)
                )

        self.ctx.run(fetch(), done, failed)
