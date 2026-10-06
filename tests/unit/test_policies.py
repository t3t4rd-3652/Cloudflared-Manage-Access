"""Politiques Access : conversion depuis et vers l'API, saisie une règle par ligne."""

from __future__ import annotations

from cma.core.policies import (
    AccessGroup,
    AccessPolicy,
    PolicyRule,
    decision_label,
    describe_rules,
    format_rule,
    parse_rules,
    policy_from_api,
    policy_to_api,
    rule_from_api,
    rule_to_api,
)

GROUPS = [AccessGroup("g1", "Admins")]
TOKENS = {"Robot": "tok1"}
UNKNOWN = {"github-organization": {"name": "acme", "identity_provider_id": "idp"}}


def test_rules_round_trip_and_unknown_rules_are_kept():
    api_rules = [
        {"email": {"email": "alice@exemple.fr"}},
        {"email_domain": {"domain": "exemple.fr"}},
        {"group": {"id": "g1"}},
        {"service_token": {"token_id": "tok1"}},
        {"any_valid_service_token": {}},
        {"everyone": {}},
        UNKNOWN,
    ]
    rules = [rule_from_api(r) for r in api_rules]
    assert [r.kind for r in rules] == [
        "email",
        "email_domain",
        "group",
        "service_token",
        "any_valid_service_token",
        "everyone",
        "raw",
    ]
    assert [rule_to_api(r) for r in rules] == api_rules
    assert not rules[-1].editable and rules[0].editable
    assert rule_from_api({"email": {}}).kind == "raw"  # incomplète : conservée telle quelle


def test_policy_round_trip_keeps_exclude_require_and_precedence():
    data = {
        "id": "p1",
        "name": "Équipe",
        "decision": "allow",
        "include": [{"email_domain": {"domain": "exemple.fr"}}, UNKNOWN],
        "exclude": [{"email": {"email": "stagiaire@exemple.fr"}}],
        "require": [{"geo": {"country_code": "FR"}}],
        "precedence": 2,
    }
    policy = policy_from_api(data)
    assert policy.precedence == 2 and len(policy.include) == 2
    body = policy_to_api(policy)
    assert body == {k: v for k, v in data.items() if k != "id"}
    assert "precedence" not in policy_to_api(AccessPolicy("", "Nouvelle", "allow"))
    assert policy_from_api({"precedence": "?"}).precedence is None


def test_parse_rules_reads_each_line():
    text = """
        Alice@Exemple.fr
        @exemple.fr
        groupe : admins
        token : robot
        tout service token
        Everyone
        alice@exemple.fr
    """
    rules, errors = parse_rules(text, GROUPS, TOKENS)
    assert errors == []
    assert rules == [
        PolicyRule("email", "alice@exemple.fr"),
        PolicyRule("email_domain", "exemple.fr"),
        PolicyRule("group", "g1"),
        PolicyRule("service_token", "tok1"),
        PolicyRule("any_valid_service_token"),
        PolicyRule("everyone"),
    ]  # le doublon d'Alice est ignoré


def test_parse_rules_reports_each_wrong_line():
    rules, errors = parse_rules(
        "groupe : Inconnus\ntoken : Absent\nn'importe quoi\n@pas-un-domaine", GROUPS, TOKENS
    )
    assert rules == []
    assert [e.split(" ")[1] for e in errors] == ["1", "2", "3", "4"]
    assert "groupe Access inconnu" in errors[0] and "service token inconnu" in errors[1]


def test_formatting_is_the_inverse_of_parsing():
    rules, _ = parse_rules(
        "a@b.fr\n@b.fr\ngroupe : Admins\ntoken : Robot\ntout service token\ntout le monde", GROUPS, TOKENS
    )
    lines = [format_rule(r, GROUPS, TOKENS) for r in rules]
    assert parse_rules("\n".join(lines), GROUPS, TOKENS)[0] == rules
    assert format_rule(PolicyRule("group", "disparu"), GROUPS, TOKENS) == "groupe : disparu"
    assert format_rule(PolicyRule("raw", raw=UNKNOWN), GROUPS, TOKENS) == str(UNKNOWN)


def test_descriptions():
    policy = AccessPolicy(
        "p1", "Équipe", "non_identity", (PolicyRule("service_token", "tok1"), PolicyRule("raw", raw=UNKNOWN))
    )
    assert describe_rules(policy, GROUPS, TOKENS) == "token : Robot (+1 règle(s) gérée(s) hors de CMA)"
    assert describe_rules(AccessPolicy("p2", "Vide", "deny"), GROUPS, TOKENS) == "—"
    assert [decision_label(d) for d in ("allow", "deny", "non_identity", "bypass", "autre")] == [
        "Autoriser",
        "Refuser",
        "Service Auth",
        "Contourner",
        "autre",
    ]
