"""Amorçage commun à l'interface graphique et à la ligne de commande."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cma.core.config_store import ConfigStore
from cma.core.events import EventBus
from cma.core.manager import SessionManager
from cma.core.migrations import MigrationError, MigrationReport, migrate_v1, needs_migration
from cma.core.prompts import Prompter
from cma.core.secrets import SecretStore, open_secret_store
from cma.i18n import set_language, tr
from cma.paths import AppPaths
from cma.platform.winjob import ProcessJob

log = logging.getLogger(__name__)


@dataclass
class AppContext:
    paths: AppPaths
    store: ConfigStore
    secrets: SecretStore
    bus: EventBus
    manager: SessionManager
    warnings: list[str] = field(default_factory=list[str])
    migration: MigrationReport | None = None


def create_context(paths: AppPaths, prompter: Prompter, *, secrets: SecretStore | None = None) -> AppContext:
    paths.ensure()
    secrets = secrets or open_secret_store()
    store = ConfigStore(paths)
    warnings = store.load()
    migration: MigrationReport | None = None

    if needs_migration(paths.data_dir):
        try:
            config, migration = migrate_v1(paths.data_dir, secrets)
            store.replace(config)
        except MigrationError as exc:
            warnings.append(str(exc))
        except Exception as exc:
            log.exception("Migration v1 impossible")
            warnings.append(tr("La migration des données de la v1 a échoué : {error}").format(error=exc))

    if not secrets.persistent:
        warnings.append(
            tr(
                "Aucun trousseau système n'est disponible : les secrets saisis ne seront pas conservés "
                "après la fermeture de l'application."
            )
        )

    set_language(store.snapshot().settings.language)
    bus = EventBus()
    manager = SessionManager(
        paths=paths, store=store, secrets=secrets, bus=bus, prompter=prompter, job=ProcessJob()
    )
    return AppContext(
        paths=paths,
        store=store,
        secrets=secrets,
        bus=bus,
        manager=manager,
        warnings=warnings,
        migration=migration,
    )
