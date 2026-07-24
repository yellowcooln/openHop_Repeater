from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import ClaimRule


@dataclass(frozen=True)
class ClaimEvaluationResult:
    allowed: bool
    reason: str = "allowed"
    failed_claim: str | None = None


_MISSING = object()
_MALFORMED = object()


def evaluate_claim_rules(
    claims: Any, rules: tuple[ClaimRule, ...] | list[ClaimRule]
) -> ClaimEvaluationResult:
    if not isinstance(claims, dict):
        return ClaimEvaluationResult(False, "malformed")

    for rule in rules:
        value = _get_claim_path(claims, rule.claim)
        if value is _MALFORMED:
            return ClaimEvaluationResult(False, "malformed", rule.claim)
        if value is _MISSING:
            return ClaimEvaluationResult(False, "missing", rule.claim)
        if value is None or value == [] or (isinstance(value, str) and not value.strip()):
            return ClaimEvaluationResult(False, "empty", rule.claim)
        values = value if isinstance(value, list) else [value]
        if not any(
            _same_json_scalar(candidate, allowed) for candidate in values for allowed in rule.any_of
        ):
            return ClaimEvaluationResult(False, "no_match", rule.claim)

    return ClaimEvaluationResult(True)


def _same_json_scalar(candidate: Any, allowed: Any) -> bool:
    """Compare JSON scalar values without Python's bool/int coercion."""
    return type(candidate) is type(allowed) and candidate == allowed


def _get_claim_path(claims: dict[str, Any], path: str) -> Any:
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, dict):
            return _MALFORMED
        if part not in current:
            return _MISSING
        current = current[part]
    if isinstance(current, dict):
        return _MALFORMED
    return current
