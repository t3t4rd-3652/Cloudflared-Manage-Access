"""Liens `cma://` et profils partagés.

- `cma://connect/<profil>` ouvre la connexion d'un profil (nom ou identifiant), depuis un favori du navigateur, un
  document ou un ticket. CMA demande confirmation, sauf pour un profil marqué « lien sûr » : une page web peut
  déclencher ce lien, elle ne doit pas pouvoir ouvrir un accès sans que l'utilisateur le voie.
- `cma://import?p=<données>` et les fichiers `.cma` transmettent un profil Cloudflare **sans aucun secret** : nom,
  nom d'hôte, port local, mode d'authentification, type de service. Pour un service token, seul son Client ID part
  (il n'est pas secret) : le destinataire retrouve le token s'il l'a déjà, sinon il l'ajoute à part. Les en-têtes
  et le proxy ne sont pas partagés (ils peuvent contenir des identifiants).
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, cast

from pydantic import ValidationError

from cma.core.models import AuthMode, CloudflareProfile, Config, ServiceType, unique_name
from cma.i18n import tr

SCHEME = "cma"
SHARE_VERSION = 1
FILE_SUFFIX = ".cma"
MAX_LINK = 4096


class LinkError(ValueError):
    """Lien ou fichier de partage illisible (message lisible)."""


@dataclass(frozen=True)
class Link:
    action: str  # « connect » ou « import »
    profile: str = ""  # connect : nom ou identifiant du profil
    share: dict[str, Any] = field(default_factory=dict[str, Any])  # import : profil partagé


def is_link(text: str) -> bool:
    return text.lower().startswith(f"{SCHEME}:")


def connect_link(profile_name: str) -> str:
    return f"{SCHEME}://connect/{urllib.parse.quote(profile_name, safe='')}"


def share_payload(profile: CloudflareProfile, config: Config) -> dict[str, Any]:
    """Le profil partageable : ce qu'il faut pour le recréer, sans secret ni réglage propre au poste."""
    payload: dict[str, Any] = {
        "cma_share": SHARE_VERSION,
        "name": profile.name,
        "hostname": profile.hostname,
        "local_port": profile.local_port,
        "auth": profile.auth.value,
        "service_type": profile.service_type.value,
    }
    if profile.group:
        payload["group"] = profile.group
    if profile.service_user:
        payload["service_user"] = profile.service_user
    token = config.token(profile.token_id) if profile.auth == AuthMode.SERVICE_TOKEN else None
    if token is not None:
        payload["token_client_id"] = token.client_id
        payload["token_name"] = token.name
    return payload


def share_link(profile: CloudflareProfile, config: Config) -> str:
    data = json.dumps(share_payload(profile, config), ensure_ascii=False, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(data.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{SCHEME}://import?p={encoded}"


def share_file_text(profile: CloudflareProfile, config: Config) -> str:
    return json.dumps(share_payload(profile, config), ensure_ascii=False, indent=2) + "\n"


def read_share(text: str) -> dict[str, Any]:
    """Contenu d'un fichier `.cma` ; LinkError s'il n'en est pas un."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise LinkError(tr("Ce fichier n'est pas un profil CMA partagé.")) from exc
    if not isinstance(data, dict) or cast(dict[str, Any], data).get("cma_share") != SHARE_VERSION:
        raise LinkError(tr("Ce fichier n'est pas un profil CMA partagé."))
    return cast(dict[str, Any], data)


def parse_link(url: str) -> Link:
    """`cma://connect/<profil>` ou `cma://import?p=…` ; LinkError pour tout le reste."""
    if len(url) > MAX_LINK:
        raise LinkError(tr("Lien trop long."))
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme.lower() != SCHEME:
        raise LinkError(tr("Ce n'est pas un lien CMA : {url}").format(url=url[:80]))
    action = parts.netloc.lower()
    if action == "connect":
        name = urllib.parse.unquote(parts.path.strip("/"))
        if not name:
            raise LinkError(tr("Le lien ne nomme aucun profil."))
        return Link("connect", profile=name)
    if action == "import":
        encoded = urllib.parse.parse_qs(parts.query).get("p", [""])[0]
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            return Link("import", share=read_share(raw.decode("utf-8")))
        except (binascii.Error, UnicodeDecodeError, LinkError) as exc:
            raise LinkError(tr("Lien de partage abîmé : copiez-le en entier.")) from exc
    raise LinkError(tr("Action inconnue dans le lien : {action}").format(action=action or "—"))


@dataclass(frozen=True)
class SharedProfile:
    profile: CloudflareProfile
    # Service token attendu mais absent de ce poste : (nom, Client ID) à ajouter.
    missing_token: tuple[str, str] | None = None


def profile_from_share(share: dict[str, Any], config: Config) -> SharedProfile:
    """Le profil à créer depuis un partage : nom rendu unique, token retrouvé par son Client ID. LinkError si le
    contenu est invalide."""
    try:
        auth = AuthMode(str(share.get("auth", AuthMode.BROWSER.value)))
        service = ServiceType(str(share.get("service_type", ServiceType.GENERIC.value)))
    except ValueError as exc:
        raise LinkError(tr("Profil partagé invalide : {error}").format(error=exc)) from exc
    client_id = str(share.get("token_client_id") or "")
    token = next((t for t in config.tokens if client_id and t.client_id == client_id), None)
    names = [p.name for p in [*config.cloudflare_profiles, *config.ssh_profiles]]
    try:
        profile = CloudflareProfile(
            name=unique_name(str(share.get("name") or ""), names),
            hostname=str(share.get("hostname") or ""),
            local_port=share.get("local_port"),
            auth=auth,
            token_id=token.id if token is not None else None,
            service_type=service,
            service_user=str(share.get("service_user") or ""),
            group=str(share.get("group") or ""),
        )
    except ValidationError as exc:
        details = "; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())
        raise LinkError(tr("Profil partagé invalide : {error}").format(error=details)) from exc
    missing = None
    if auth == AuthMode.SERVICE_TOKEN and token is None:
        missing = (str(share.get("token_name") or ""), client_id)
    return SharedProfile(profile, missing)
