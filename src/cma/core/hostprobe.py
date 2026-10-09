"""Test d'un nom d'hôte publié, depuis Internet : ce qu'un visiteur obtient en le demandant.

Résolution DNS publique, puis requête HTTPS sans suivre les redirections. La réponse se lit ainsi :
- redirection vers `*.cloudflareaccess.com` : Access protège le nom et demande de se connecter ; le tunnel n'est pas
  atteint (sans service token, impossible d'aller plus loin) ;
- 530 avec l'erreur 1033 : le tunnel n'a aucun connecteur en ligne ;
- 502 ou 504 : le tunnel répond, mais pas le service derrière lui ;
- en-tête `cf-mitigated: challenge` (page « Just a moment… ») : la protection contre les robots de Cloudflare demande
  une vérification de navigateur ; un test automatique ne peut pas aller plus loin (relevé sur un vrai compte : les
  403 d'une requête sans navigateur venaient de là, pas d'Access ni du service) ;
- toute autre réponse : le service répond.
Un nom générique (`*.exemple.fr`) ne se demande pas tel quel : il faut tester un nom précis.
Avec un service token, les en-têtes `CF-Access-Client-Id` et `CF-Access-Client-Secret` font passer Access. Le
secret ne sort que dans la requête vers le nom d'hôte, jamais dans un journal.
"""

from __future__ import annotations

import asyncio
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field, replace

from cma import __version__
from cma.i18n import tr

TIMEOUT = 10.0
ACCESS_DOMAIN = "cloudflareaccess.com"


@dataclass(frozen=True)
class HostProbe:
    # « not_found », « wildcard », « access », « challenge », « no_connector », « origin_down », « refused », « ok »
    # ou « unreachable »
    state: str
    status: int | None = None
    detail: str = ""
    # Temps de réponse (ms) de la requête, réponse reçue ; None sans réponse.
    ms: float | None = field(default=None, compare=False)

    @property
    def tone(self) -> str:
        """Teinte de la notification : success, info, warning ou error."""
        return {
            "ok": "success",
            "access": "info",
            "challenge": "info",
            "wildcard": "info",
            "refused": "warning",
            "origin_down": "warning",
        }.get(self.state, "error")

    def advice(self) -> str:
        """Ce qu'il faut faire, quand le résultat le demande ; vide sinon."""
        texts = {
            "not_found": tr(
                "Le nom n'existe pas dans le DNS public : « Corriger le DNS… » crée le CNAME vers le tunnel, ou "
                "vérifiez que la zone est bien servie par Cloudflare."
            ),
            "no_connector": tr(
                "Aucun cloudflared n'est relié au tunnel : relancez le service cloudflared sur le serveur "
                "(« État des connecteurs… » dans le menu du tunnel)."
            ),
            "origin_down": tr(
                "cloudflared tourne, mais le service vers lequel il renvoie ne répond pas : vérifiez que ce service "
                "est démarré sur le serveur et que l'adresse de la règle (« Modifier le service… ») est la bonne."
            ),
            "refused": tr(
                "Le service token n'est autorisé par aucune politique de l'application : « Autoriser un service "
                "token… » dans l'onglet Applications."
            ),
            "challenge": tr(
                "Un réglage de sécurité de la zone (Bot Fight Mode, mode « I'm Under Attack » ou règle WAF avec "
                "défi) demande une vérification de navigateur. Un navigateur la passe ; un script ou une machine "
                "munie d'un service token est bloqué. Réglage dans le tableau de bord Cloudflare : Sécurité › Bots "
                "et Sécurité › WAF. Une règle WAF ou Super Bot Fight Mode admet une exception par nom d'hôte ; "
                "Bot Fight Mode, non. CMA ne modifie pas ces réglages."
            ),
            "unreachable": tr(
                "Aucune réponse : vérifiez la connexion de ce poste, puis l'état du nom dans le tableau de bord."
            ),
        }
        return texts.get(self.state, "")

    def summary(self, hostname: str) -> str:
        texts = {
            "not_found": tr("{host} : nom introuvable dans le DNS public."),
            "wildcard": tr("{host} est un nom générique : testez un nom précis qu'il couvre."),
            "challenge": tr(
                "{host} : Cloudflare demande une vérification de navigateur (protection contre les robots). Le test "
                "automatique s'arrête là : ouvrez le nom dans un navigateur."
            ),
            "access": tr(
                "{host} : protégé par Cloudflare Access (page de connexion). Le tunnel n'est pas atteint sans "
                "service token."
            ),
            "no_connector": tr("{host} : le tunnel n'a aucun connecteur en ligne (erreur 1033)."),
            "origin_down": tr(
                "{host} : le tunnel répond, mais pas le service derrière lui (erreur {status})."
            ),
            "refused": tr(
                "{host} : accès refusé ({status}), le service token n'est pas autorisé sur l'application."
            ),
            "ok": tr("{host} : le service répond ({status})."),
            "unreachable": tr("{host} : injoignable ({detail})."),
        }
        return texts.get(self.state, "").format(host=hostname, status=self.status or "", detail=self.detail)


def classify(status: int, headers: dict[str, str], body: str, *, with_token: bool) -> HostProbe:
    """Lecture d'une réponse HTTP reçue pour un nom d'hôte publié (fonction pure ; en-têtes en minuscules)."""
    if 300 <= status < 400 and ACCESS_DOMAIN in headers.get("location", "").lower():
        return HostProbe("access", status)
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return HostProbe("challenge", status)
    if status == 530 or (status >= 500 and "1033" in body):
        return HostProbe("no_connector", status)
    if status in (502, 504):
        return HostProbe("origin_down", status)
    if status in (401, 403) and with_token:
        return HostProbe("refused", status)
    return HostProbe("ok", status)


def probe_hostname(
    hostname: str,
    *,
    token: tuple[str, str] | None = None,
    path: str = "/",
    timeout: float = TIMEOUT,
    connect: tuple[str, int] | None = None,
    tls: bool = True,
) -> HostProbe:
    """Demande `https://hostname{path}` comme un visiteur. `token` : (Client ID, secret) d'un service token.

    `connect` et `tls` servent aux tests (serveur local en HTTP) ; sans eux, le nom est résolu par le DNS public.
    """
    if hostname.startswith("*."):
        return HostProbe("wildcard")
    if connect is None:
        try:
            socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return HostProbe("not_found")
    host, port = connect or (hostname, 443)
    connection: http.client.HTTPConnection
    if tls:
        connection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ssl.create_default_context()
        )
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {"Host": hostname, "User-Agent": f"CloudflaredManageAccess/{__version__}"}
    if token is not None:
        headers["CF-Access-Client-Id"], headers["CF-Access-Client-Secret"] = token
    try:
        started = time.perf_counter()
        connection.request("GET", path or "/", headers=headers)
        response = connection.getresponse()
        elapsed = (time.perf_counter() - started) * 1000
        body = response.read(4096).decode("utf-8", "replace")
        received = {name.lower(): value for name, value in response.getheaders()}
        return replace(
            classify(response.status, received, body, with_token=token is not None), ms=round(elapsed, 1)
        )
    except (OSError, http.client.HTTPException) as exc:
        return HostProbe("unreachable", detail=str(exc) or type(exc).__name__)
    finally:
        connection.close()


async def probe_hostname_async(hostname: str, **kwargs: object) -> HostProbe:
    return await asyncio.to_thread(probe_hostname, hostname, **kwargs)  # type: ignore[arg-type]
