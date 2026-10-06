"""Recette de l'administration Cloudflare de CMA sur un vrai compte, avec le jeton d'API du coffre de CMA.

    python scripts/cloudflare_recette.py              lecture seule : rien n'est modifié
    python scripts/cloudflare_recette.py --ecriture   essais en écriture sur des ressources jetables « cma-essai »

Le mode écriture crée un tunnel, une application Access, une politique réutilisable et un service token, tous
nommés « cma-essai », les fait passer par les fonctions de CMA (renommer, modifier un service et ses options
d'origine, attacher et retirer une politique, prolonger et changer le secret d'un token…), puis les supprime.
Il ne crée ni ne modifie AUCUN enregistrement DNS et ne touche à aucune ressource existante. Les secrets (jeton
du connecteur, secret des tokens) ne sont jamais affichés.

Le compte est celui choisi dans CMA (`--data-dir` pour une autre copie), sinon le premier lisible.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cma.core.cfadmin import CloudflareAdmin
from cma.core.cfapi import TOKEN_SECRET_KEY, CloudflareApiError
from cma.core.models import Config
from cma.core.policies import AccessPolicy, PolicyRule
from cma.core.secrets import MemorySecretStore, open_secret_store
from cma.core.tunnelhealth import diagnose_connectors
from cma.paths import resolve_paths

NAME = "cma-essai"
failures: list[str] = []


def step(label: str, call: Callable[[], Any]) -> Any:
    try:
        result = call()
    except CloudflareApiError as exc:
        print(f"  [ÉCHEC] {label} : statut {exc.status}, codes {list(exc.codes)} : {exc}")
        failures.append(label)
        return None
    print(f"  [OK]    {label}")
    return result


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def read_only(admin: CloudflareAdmin, account: str) -> None:
    api = admin.api()
    print("== Lecture")
    tunnels = step("tunnels", lambda: api.list_tunnels(account)) or []
    for tunnel in tunnels:
        connectors = step(
            f"connecteurs de {tunnel.name}", lambda t=tunnel: api.tunnel_connectors(account, t.id)
        )
        if connectors is not None:
            print("          ", diagnose_connectors(connectors)[0].message)
    apps = step("applications Access", lambda: api.list_access_apps(account)) or []
    step("politiques du compte", lambda: api.list_account_policies(account))
    for app in (a for a in apps if a.type == "self_hosted"):
        step(f"politiques de {app.name}", lambda a=app: run(admin.policies(a)))
        step(f"{app.name} modifiable sans risque", lambda a=app: api.app_for_update(account, a.id))
    step("service tokens", lambda: api.list_service_tokens(account))
    groups = run(admin.groups())
    print(f"  [info]  {len(groups)} groupe(s) Access lisible(s) (permission facultative)")


def write_tests(admin: CloudflareAdmin, account: str, zone: str) -> None:
    api = admin.api()
    host = f"{NAME}.{zone}"
    if [t for t in api.list_tunnels(account) if t.name.startswith(NAME)]:
        sys.exit(f"Un tunnel {NAME}… existe déjà : supprimez-le avant de relancer.")
    if [a for a in api.list_access_apps(account) if a.domain.split("/")[0] == host]:
        sys.exit(f"Une application {host} existe déjà : supprimez-la avant de relancer.")
    created: dict[str, Any] = {}
    print(f"== Écriture (ressources « {NAME} », aucun DNS)")
    try:
        new = step("créer un tunnel", lambda: run(admin.create_tunnel(NAME)))
        if new:
            created["tunnel"] = new.tunnel
            print("           jeton du connecteur reçu :", len(new.token) > 50, "(non affiché)")
            renamed = step("renommer le tunnel", lambda: run(admin.rename_tunnel(new.tunnel, NAME + "-2")))
            if renamed:
                created["tunnel"] = renamed
            # Règle d'ingress posée directement dans la configuration : pas d'enregistrement DNS.
            config = {
                "ingress": [
                    {"hostname": host, "service": "http://localhost:8080"},
                    {"service": "http_status:404"},
                ]
            }
            step(
                "règle d'ingress de test (sans DNS)",
                lambda: api._result(
                    "PUT",
                    f"/accounts/{account}/cfd_tunnel/{created['tunnel'].id}/configurations",
                    body={"config": config},
                ),
            )
            origin = {"noTLSVerify": True, "httpHostHeader": "interne.local", "originServerName": ""}
            rule = step(
                "modifier le service et les options d'origine",
                lambda: run(admin.edit_hostname(created["tunnel"], host, "https://localhost:8443", origin)),
            )
            if rule:
                ok = rule.service == "https://localhost:8443" and rule.origin == {
                    "noTLSVerify": True,
                    "httpHostHeader": "interne.local",
                }
                print("           relu :", "conforme" if ok else f"INATTENDU {rule}")
                if not ok:
                    failures.append("relecture du service")
            step("état des connecteurs (aucun attendu)", lambda: run(admin.connectors(created["tunnel"])))

        app = step("créer une application Access", lambda: api.create_access_app(account, host, host))
        if app:
            created["app"] = app
            policy = AccessPolicy("", NAME, "allow", (PolicyRule("email", "cma-essai@example.invalid"),))
            saved = step("nouvelle politique (compte + attache)", lambda: run(admin.save_policy(app, policy)))
            if saved:
                created["policy"] = saved
                listed = run(admin.policies(app))[0]
                print(
                    "           attachée :",
                    [p.name for p in listed] == [NAME],
                    "| partagée :",
                    listed[0].app_count,
                )
                step(
                    "modifier la politique",
                    lambda: run(
                        admin.save_policy(
                            app, AccessPolicy(saved.id, NAME + "-2", "deny", saved.include, reusable=True)
                        )
                    ),
                )
                step("retirer la politique de l'application", lambda: run(admin.remove_policy(app, saved)))
                print("           retirée :", run(admin.policies(app))[0] == [])
                step("la remettre (politique existante)", lambda: run(admin.attach_policy(app, saved)))
                step("la retirer à nouveau", lambda: run(admin.remove_policy(app, saved)))

        token = step(
            "créer un service token", lambda: run(admin.create_service_token(NAME, duration="8760h"))
        )
        if token:
            remote = next(t for t in api.list_service_tokens(account) if t.client_id == token.client_id)
            created["token"] = remote
            if app:
                step("autoriser le token sur l'application", lambda: run(admin.allow_token(app, token.id)))
                created["token_policy"] = True
            step("prolonger le token", lambda: run(admin.extend_token(remote)))
            before = admin.secrets.get(token.secret_key)
            step("changer le secret", lambda: run(admin.rotate_token(token.id)))
            print(
                "           nouveau secret dans le coffre de test :",
                admin.secrets.get(token.secret_key) != before,
            )
    except Exception:
        traceback.print_exc()
        failures.append("exception")
    finally:
        print("== Nettoyage")
        if "app" in created:
            step("supprimer l'application", lambda: run(admin.delete_app(created["app"])))
        if "token" in created:
            step("supprimer le token", lambda: run(admin.delete_remote_token(created["token"])))
        for policy in api.list_account_policies(account):
            if policy.name.startswith(NAME) and not policy.app_count:
                step(
                    f"supprimer la politique {policy.name}",
                    lambda p=policy: run(admin.delete_account_policy(p)),
                )
        if "tunnel" in created:
            step("supprimer le tunnel", lambda: run(admin.delete_tunnel(created["tunnel"], [])))
        leftovers = (
            [t.name for t in api.list_tunnels(account) if t.name.startswith(NAME)]
            + [a.name for a in api.list_access_apps(account) if a.name.startswith(NAME)]
            + [t.name for t in api.list_service_tokens(account) if t.name.startswith(NAME)]
            + [p.name for p in api.list_account_policies(account) if p.name.startswith(NAME)]
        )
        print("  Restes :", leftovers or "aucun")
        if leftovers:
            failures.append("nettoyage incomplet")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--ecriture", action="store_true", help="essais en écriture sur des ressources « cma-essai »"
    )
    parser.add_argument(
        "--data-dir", help="dossier de données de CMA (par défaut celui de la copie installée)"
    )
    args = parser.parse_args()
    paths = resolve_paths(args.data_dir)
    vault = open_secret_store()
    token = vault.get(TOKEN_SECRET_KEY)
    if not token:
        print("Aucun jeton d'API dans le coffre de CMA : connectez-vous d'abord dans la vue Cloudflare.")
        return 2
    # Coffre et configuration de travail en mémoire : la recette ne touche ni au coffre ni aux profils de CMA.
    config = (
        Config.model_validate_json(paths.config_file.read_text(encoding="utf-8"))
        if paths.config_file.exists()
        else Config()
    )
    work = MemorySecretStore(reason="recette")
    work.set(TOKEN_SECRET_KEY, token)
    del token
    admin = CloudflareAdmin(_ReadOnlyStore(config), work, lambda *_a: None)  # type: ignore[arg-type]
    accounts = run(admin.connect())
    account = admin.account_id()
    print(f"Compte : {next(a.name for a in accounts if a.id == account)}")
    read_only(admin, account)
    if args.ecriture:
        zones = admin.api().list_zones(account)
        if not zones:
            print("Aucune zone lisible : le mode écriture a besoin d'un domaine pour nommer l'application.")
            return 2
        write_tests(admin, account, zones[0].name)
    print("\nRÉSULTAT :", "tout fonctionne" if not failures else f"{len(failures)} échec(s) : {failures}")
    return 1 if failures else 0


class _ReadOnlyStore:
    """Configuration de CMA lue une fois, modifiée seulement en mémoire (choix du compte, tokens de test)."""

    def __init__(self, config: Any) -> None:
        self.config = config

    def snapshot(self) -> Any:
        return self.config.model_copy(deep=True)

    def update(self, mutator: Callable[[Any], Any]) -> Any:
        mutator(self.config)
        return self.config


if __name__ == "__main__":
    sys.exit(main())
