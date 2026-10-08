"""Offline DTO lease and exact receipt binding only; no node execution."""

import json
from hashlib import sha256
from uuid import uuid4

import pytest

from repeater.glass.contracts import (
    InformV2,
    JobV2,
    QueryV2,
    ResponseV2,
    ResultAcceptanceV2,
    ResultV2,
    result_sha256,
)
from tests.test_glass_contracts import fixture, job, query


@pytest.mark.parametrize("model,raw", [(QueryV2, query()), (JobV2, job())])
def test_optional_delivery_and_complete_lease_round_trip(model, raw):
    assert "lease_id" not in model.model_validate(raw).model_dump(mode="json")
    raw.update(lease_id=str(uuid4()), attempt=1, lease_expires_at="2026-01-01T00:01:00Z")
    parsed = model.model_validate(raw)
    assert json.loads(parsed.model_dump_json())["attempt"] == 1
    assert parsed.lease_expires_at <= parsed.expires_at


@pytest.mark.parametrize(
    "changes",
    [
        {"lease_id": str(uuid4())},
        {"attempt": 1},
        {"attempt": True},
        {"attempt": "1"},
        {"attempt": 4},
        {"lease_expires_at": "2026-01-01T00:06:00Z"},
        {"lease_expires_at": "2026-01-01T00:00:00Z"},
        {"lease_expires_at": "2026-01-01T00:01:00"},
    ],
)
def test_bad_delivery_lease_fails_closed(changes):
    raw = query()
    if set(changes) != {"lease_id"} and set(changes) != {"attempt"}:
        raw.update(lease_id=str(uuid4()), attempt=1, lease_expires_at="2026-01-01T00:01:00Z")
    raw.update(changes)
    with pytest.raises(ValueError):
        QueryV2.model_validate(raw)


@pytest.mark.parametrize("status", ["received", "awaiting_verification", "unknown"])
def test_progress_unknown_not_completed(status):
    raw = fixture("proposed_v2_result.json")
    raw.update(status=status, completed_at=None, lease_id=str(uuid4()), attempt=1)
    assert ResultV2.model_validate(raw).completed_at is None
    raw["completed_at"] = raw["sent_at"]
    with pytest.raises(ValueError):
        ResultV2.model_validate(raw)


def test_result_receipt_exact_digest_and_tamper_detection():
    raw = fixture("proposed_v2_inform.json")
    offered = fixture("proposed_v2_result.json")
    offered.update(lease_id=str(uuid4()), attempt=1)
    raw["results"] = [offered]
    raw["sent_at"] = offered["sent_at"]
    inform = InformV2.model_validate(raw)
    parsed = inform.results[0]
    expected = sha256(
        json.dumps(
            parsed.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    assert result_sha256(parsed) == expected
    response = fixture("proposed_v2_response.json")
    response.update(
        sent_at=raw["sent_at"],
        accepted_results=[
            {
                "request_id": offered["request_id"],
                "execution_id": offered["execution_id"],
                "acceptance_id": str(uuid4()),
                "result_sha256": expected,
            }
        ],
    )
    ResponseV2.model_validate(response).check_inform(inform)
    response["accepted_results"][0]["result_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        ResponseV2.model_validate(response).check_inform(inform)
    receipt = response["accepted_results"][0]
    receipt.pop("acceptance_id")
    with pytest.raises(ValueError):
        ResultAcceptanceV2.model_validate(receipt)
    offered["lease_id"] = None
    with pytest.raises(ValueError):
        ResultV2.model_validate(offered)
