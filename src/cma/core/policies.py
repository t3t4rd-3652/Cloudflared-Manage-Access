"""Politiques Cloudflare Access : qui a le droit d'atteindre une application.

Une politique a une décision (autoriser, refuser, Service Auth, contourner) et des règles « include ». CMA sait
lire et écrire les règles courantes (e-mail, domaine d'e-mail, groupe, service token, tout service token valide,
tout le monde) ; toute autre règle est conservée telle quelle quand la politique est modifiée. Les conditions
« exclude » et « require » ne sont pas modifiées par CMA.

La saisie se fait une règle par ligne :

    alice@exemple.fr        e-mail
    @exemple.fr             domaine d'e-mail
    groupe : Admins         groupe Access (par son nom)
    token : Robot           service token (par son nom)
    tout service token      n'importe quel service token valide du compte
    tout le monde           n'importe qui (à réserver à « Contourner » ou « Refuser »)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, cast

from cma.i18n import tr

DECISIONS = ("allow", "deny", "non_identity", "bypass")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^@?([a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)
EVERYONE_WORDS = ("tout le monde", "everyone")
ANY_TOKEN_WORDS = ("tout service token", "any service token")
GROUP_PREFIXES = ("groupe", "group")
TOKEN_PREFIXES = ("token",)


@dataclass(frozen=True)
class AccessGroup:
    id: str
    name: str


@dataclass(frozen=True)
class PolicyRule:
    """`kind` : email, email_domain, group, service_token, any_valid_service_token, everyone, ou raw (inconnue)."""

    kind: str
    value: str = ""
    raw: dict[str, Any] | None = field(default=None, compare=False)

    @property
    def editable(self) -> bool:
        return self.kind != "raw"


@dataclass(frozen=True)
class AccessPolicy:
    """Une politique Access.

    `reusable` : politique du compte, partagée entre applications (`app_count` d'entre elles) ; elle se modifie
    par `/access/policies/{id}`. Sinon, politique « legacy » propre à une application. `precedence` est son rang
    dans l'application lue. `extra` garde les champs que CMA ne gère pas (`connection_rules` pour le RDP,
    approbations, isolation…) : ils repartent tels quels à l'enregistrement.
    """

    id: str
    name: str
    decision: str
    include: tuple[PolicyRule, ...] = ()
    exclude: tuple[dict[str, Any], ...] = ()
    require: tuple[dict[str, Any], ...] = ()
    precedence: int | None = None
    reusable: bool = False
    app_count: int | None = None
    extra: dict[str, Any] = field(default_factory=dict[str, Any], compare=False, hash=False)

    @property
    def shared(self) -> bool:
        """Partagée avec au moins une autre application : la modifier change aussi leur accès."""
        return self.reusable and (self.app_count or 0) > 1


# --- Conversion depuis et vers l'API -----------------------------------------------------------------------


def rule_from_api(data: dict[str, Any]) -> PolicyRule:
    if len(data) == 1:
        (kind, body), *_ = data.items()
        body = cast(dict[str, Any], body or {})
        if kind == "email" and body.get("email"):
            return PolicyRule("email", str(body["email"]))
        if kind == "email_domain" and body.get("domain"):
            return PolicyRule("email_domain", str(body["domain"]))
        if kind == "group" and body.get("id"):
            return PolicyRule("group", str(body["id"]))
        if kind == "service_token" and body.get("token_id"):
            return PolicyRule("service_token", str(body["token_id"]))
        if kind in ("any_valid_service_token", "everyone"):
            return PolicyRule(kind)
    return PolicyRule("raw", raw=data)


def rule_to_api(rule: PolicyRule) -> dict[str, Any]:
    if rule.kind == "raw":
        return dict(rule.raw or {})
    key = {"email": "email", "email_domain": "domain", "group": "id", "service_token": "token_id"}.get(
        rule.kind
    )
    return {rule.kind: {key: rule.value} if key else {}}


_MANAGED = {"name", "decision", "include", "exclude", "require"}
# Champs calculés par Cloudflare, jamais renvoyés.
_READ_ONLY = {"id", "uid", "created_at", "updated_at", "app_count", "reusable", "precedence"}


def policy_from_api(data: dict[str, Any]) -> AccessPolicy:
    precedence = data.get("precedence")
    app_count = data.get("app_count")
    return AccessPolicy(
        id=str(data.get("id", "")),
        name=str(data.get("name", "")),
        decision=str(data.get("decision", "allow")),
        include=tuple(rule_from_api(r) for r in cast(list[dict[str, Any]], data.get("include") or [])),
        exclude=tuple(cast(list[dict[str, Any]], data.get("exclude") or [])),
        require=tuple(cast(list[dict[str, Any]], data.get("require") or [])),
        precedence=int(precedence) if isinstance(precedence, int) else None,
        reusable=bool(data.get("reusable", False)),
        app_count=int(app_count) if isinstance(app_count, int) else None,
        extra={k: v for k, v in data.items() if k not in _MANAGED | _READ_ONLY},
    )


def policy_to_api(policy: AccessPolicy) -> dict[str, Any]:
    """Corps d'une création ou d'une modification. Le rang n'est envoyé que pour une politique legacy : celui
    d'une politique réutilisable dépend de l'application et se règle en l'y attachant."""
    body: dict[str, Any] = {
        **policy.extra,
        "name": policy.name,
        "decision": policy.decision,
        "include": [rule_to_api(r) for r in policy.include],
        "exclude": list(policy.exclude),
        "require": list(policy.require),
    }
    if policy.precedence is not None and not policy.reusable:
        body["precedence"] = policy.precedence
    return body


# --- Saisie en texte, une règle par ligne -------------------------------------------------------------------


def _prefixed(line: str, prefixes: tuple[str, ...]) -> str | None:
    """« groupe : Admins » → « Admins » (si le préfixe est l'un de `prefixes`), sinon None."""
    head, sep, rest = line.partition(":")
    if sep and head.strip().lower() in prefixes:
        return rest.strip()
    return None


def parse_rules(
    text: str, groups: list[AccessGroup], tokens: dict[str, str]
) -> tuple[list[PolicyRule], list[str]]:
    """Analyse la saisie. `tokens` associe le nom d'un service token du compte à son id. Renvoie les règles et
    les erreurs (une par ligne incomprise) ; les doublons sont ignorés."""
    by_group = {g.name.lower(): g.id for g in groups}
    by_token = {name.lower(): token_id for name, token_id in tokens.items()}
    rules: list[PolicyRule] = []
    errors: list[str] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        rule: PolicyRule | None = None
        if lowered in EVERYONE_WORDS:
            rule = PolicyRule("everyone")
        elif lowered in ANY_TOKEN_WORDS:
            rule = PolicyRule("any_valid_service_token")
        elif (name := _prefixed(line, GROUP_PREFIXES)) is not None:
            if name.lower() in by_group:
                rule = PolicyRule("group", by_group[name.lower()])
            else:
                errors.append(tr("Ligne {n} : groupe Access inconnu « {name} ».").format(n=number, name=name))
                continue
        elif (name := _prefixed(line, TOKEN_PREFIXES)) is not None:
            if name.lower() in by_token:
                rule = PolicyRule("service_token", by_token[name.lower()])
            else:
                errors.append(
                    tr("Ligne {n} : service token inconnu dans ce compte « {name} ».").format(
                        n=number, name=name
                    )
                )
                continue
        elif line.startswith("@") and _DOMAIN.match(line):
            rule = PolicyRule("email_domain", lowered.lstrip("@"))
        elif _EMAIL.match(line):
            rule = PolicyRule("email", lowered)
        if rule is None:
            errors.append(tr("Ligne {n} non comprise : « {line} ».").format(n=number, line=line))
        elif rule not in rules:
            rules.append(rule)
    return rules, errors


def format_rule(rule: PolicyRule, groups: list[AccessGroup], tokens: dict[str, str]) -> str:
    """Inverse de `parse_rules` pour une règle modifiable : la ligne à afficher dans la saisie."""
    if rule.kind == "email":
        return rule.value
    if rule.kind == "email_domain":
        return "@" + rule.value
    if rule.kind == "group":
        name = next((g.name for g in groups if g.id == rule.value), rule.value)
        return tr("groupe") + " : " + name
    if rule.kind == "service_token":
        name = next((n for n, token_id in tokens.items() if token_id == rule.value), rule.value)
        return f"token : {name}"
    if rule.kind == "any_valid_service_token":
        return tr("tout service token")
    if rule.kind == "everyone":
        return tr("tout le monde")
    return str(rule.raw)


def decision_label(decision: str) -> str:
    return {
        "allow": tr("Autoriser"),
        "deny": tr("Refuser"),
        "non_identity": tr("Service Auth"),
        "bypass": tr("Contourner"),
    }.get(decision, decision)


def describe_rules(policy: AccessPolicy, groups: list[AccessGroup], tokens: dict[str, str]) -> str:
    """Résumé d'une ligne : « alice@exemple.fr, @exemple.fr, token : Robot (+1 règle conservée) »."""
    shown = [format_rule(r, groups, tokens) for r in policy.include if r.editable]
    kept = sum(1 for r in policy.include if not r.editable)
    text = ", ".join(shown) or "—"
    if kept:
        text += " " + tr("(+{n} règle(s) gérée(s) hors de CMA)").format(n=kept)
    return text
