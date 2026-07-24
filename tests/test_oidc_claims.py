import pytest

from repeater.web.auth.claims import evaluate_claim_rules
from repeater.web.auth.config import ClaimRule


def rule(claim, *values):
    return ClaimRule(claim=claim, any_of=values)


@pytest.mark.parametrize(
    ("claims", "rules"),
    [
        ({"groups": "openhop-admins"}, [rule("groups", "openhop-admins")]),
        ({"groups": ["other", "openhop-admins"]}, [rule("groups", "openhop-admins")]),
        ({"realm_access": {"roles": ["admin"]}}, [rule("realm_access.roles", "admin")]),
        ({"tier": 2}, [rule("tier", 2)]),
        ({"enabled": True}, [rule("enabled", True)]),
        ({"groups": ["ops"], "tier": 2}, [rule("groups", "ops"), rule("tier", 2)]),
        ({"groups": ["openhop-admins"]}, [rule("groups", "openhop-admins")]),
    ],
)
def test_claim_allow_cases(claims, rules):
    result = evaluate_claim_rules(claims, rules)

    assert result.allowed is True
    assert result.failed_claim is None


@pytest.mark.parametrize(
    ("claims", "rules", "reason"),
    [
        ({}, [rule("groups", "openhop-admins")], "missing"),
        ({"groups": []}, [rule("groups", "openhop-admins")], "empty"),
        ({"groups": ["OpenHop-Admins"]}, [rule("groups", "openhop-admins")], "no_match"),
        ({"enabled": True}, [rule("enabled", "true")], "no_match"),
        ({"realm_access": []}, [rule("realm_access.roles", "admin")], "malformed"),
        ({"groups": ["openhop-users"]}, [rule("groups", "openhop-admins")], "no_match"),
        ({"groups": ["ops"], "tier": 1}, [rule("groups", "ops"), rule("tier", 2)], "no_match"),
    ],
)
def test_claim_deny_cases(claims, rules, reason):
    result = evaluate_claim_rules(claims, rules)

    assert result.allowed is False
    assert result.reason == reason
    assert result.failed_claim in {"groups", "enabled", "realm_access.roles", "tier"}


def test_any_of_is_or_with_type_preservation():
    result = evaluate_claim_rules({"roles": [2, "admin"]}, [rule("roles", "operator", 2)])

    assert result.allowed is True


@pytest.mark.parametrize(
    "claim_value,allowed_value",
    [(True, 1), (1, True), (False, 0), (0, False), (1, 1.0), (1.0, 1)],
)
def test_boolean_and_integer_claim_values_do_not_compare_equal(claim_value, allowed_value):
    result = evaluate_claim_rules({"value": claim_value}, [rule("value", allowed_value)])

    assert result.allowed is False
    assert result.reason == "no_match"


@pytest.mark.parametrize("claim_value", [None, "", "   ", []])
def test_empty_claim_values_always_deny(claim_value):
    result = evaluate_claim_rules({"value": claim_value}, [rule("value", claim_value)])

    assert result.allowed is False
    assert result.reason == "empty"


def test_malformed_claims_deny_without_uncaught_exception():
    result = evaluate_claim_rules(None, [rule("groups", "openhop-admins")])

    assert result.allowed is False
    assert result.reason == "malformed"
