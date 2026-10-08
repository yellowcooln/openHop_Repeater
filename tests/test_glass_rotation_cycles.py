"""Integrated synthetic-issuer source tests, not HTTPS or broker evidence."""

# ruff: noqa: F811 - imported pytest fixtures
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from repeater.glass import enrollment as e
from repeater.glass import rotation_completion as c
from repeater.glass import rotation_reports as q
from repeater.glass import rotation_state as r
from repeater.glass import rotation_transport as t
from tests.test_glass_rotation_completion import accepted, complete, pure_completion  # noqa: F401
from tests.test_glass_rotation_handler import make_handler
from tests.test_glass_rotation_reports import (  # noqa: F401
    acknowledge,
    args,
    bundle,
    enroll_fixture,
    installation,
    installed,
    queue,
    snapshot,
    state,
)


def issue(issuer, current, payload):
    response = issuer(current["base_url"] + "/renew", payload)
    leaf = x509.load_pem_x509_certificate(response["client_cert"].encode())
    return dict(
        response,
        request_id=payload["request_id"],
        state="issued",
        fingerprint_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
    )


def test_pure_successor_phase_binds_predecessor(pure_completion, enroll_fixture):
    completed, old, context, binding = pure_completion
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    response = issue(e.post_verified_json, old, pending)
    new = r._build_renewal_candidate(old, response, pending)
    journal = dict(
        context,
        version=1,
        request_id=pending["request_id"],
        credential_file=binding["credential_file"],
        previous_bundle=old,
        previous_sha256=r._bundle_digest(old),
        candidate_sha256=r._bundle_digest(new),
    )
    assert (
        r._cycle_phase(old, pending, completed, journal, binding["credential_file"]) == "previous"
    )
    assert (
        r._cycle_phase(new, pending, completed, journal, binding["credential_file"]) == "installed"
    )
    damaged = dict(completed, pending_sha256="0" * 64)
    with pytest.raises(e.EnrollmentError):
        r._cycle_phase(new, pending, damaged, journal, binding["credential_file"])
    # Once new completion is published, remaining matched state is authorized
    # by its saved digest, not by a predecessor receipt that no longer exists.
    new_binding = r._cycle_binding(new, binding["credential_file"])
    report = q._report(
        {
            "device_id": new["device_id"],
            "request_id": pending["request_id"],
            "cert_serial": new["cert_serial"],
            "fingerprint_sha256": new["fingerprint_sha256"],
            "boot_id": "00000000-0000-4000-8000-000000000001",
            "connected": True,
        },
        new,
    )
    from tests.test_glass_rotation_reports import ack

    new_receipt = dict(
        context,
        version=1,
        credential_file=binding["credential_file"],
        request_id=pending["request_id"],
        cert_serial=new["cert_serial"],
        fingerprint_sha256=new["fingerprint_sha256"],
        candidate_sha256=r._bundle_digest(new),
        pending_sha256=c._digest(pending, r._LIMIT),
        install_journal=journal,
        accepted_record=dict(new_binding, report=report, ack=ack(report)),
    )
    assert (
        r._cycle_phase(new, pending, new_receipt, journal, binding["credential_file"])
        == "completed"
    )
    assert r._cycle_phase(new, None, new_receipt, None, binding["credential_file"]) == "completed"
    altered = dict(pending, previous_completed_sha256="0" * 64)
    with pytest.raises(e.EnrollmentError):
        r._cycle_phase(new, altered, new_receipt, journal, binding["credential_file"])


def test_history_expiry_is_not_current_authority(pure_completion, enroll_fixture, monkeypatch):
    completed, old, context, binding = pure_completion
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    enroll_fixture[1].update(lifetime_days=14, serial=3)
    response = issue(e.post_verified_json, old, pending)
    new = r._build_renewal_candidate(old, response, pending)
    journal = dict(
        context,
        version=1,
        request_id=pending["request_id"],
        credential_file=binding["credential_file"],
        previous_bundle=old,
        previous_sha256=r._bundle_digest(old),
        candidate_sha256=r._bundle_digest(new),
    )
    clock = Mock()
    clock.now.return_value = x509.load_pem_x509_certificate(
        old["client_cert"].encode()
    ).not_valid_after_utc + timedelta(seconds=1)
    monkeypatch.setattr(e, "datetime", clock)
    clock.fromisoformat.side_effect = datetime.fromisoformat
    assert (
        r._cycle_phase(new, pending, completed, journal, binding["credential_file"]) == "installed"
    )
    with pytest.raises(e.EnrollmentError):
        r._cycle_phase(old, pending, completed, journal, binding["credential_file"])
    with pytest.raises(e.EnrollmentError):
        e.load_credentials(
            enroll_fixture[0]["credential_file"],
            base_url=old["base_url"],
            device_id=old["device_id"],
        )
    corrupted = dict(old, private_key=pending["private_key"])
    broken = dict(journal, previous_bundle=corrupted, previous_sha256=r._bundle_digest(corrupted))
    with pytest.raises(e.EnrollmentError):
        r._cycle_phase(new, pending, completed, broken, binding["credential_file"])


@pytest.mark.parametrize("bad", ["expired", "bad_signature", "mismatch"])
def test_successor_replacement_crypto_remains_strict(pure_completion, enroll_fixture, bad):
    completed, old, context, _ = pure_completion
    pending = r._new_pending(context, previous_completed_sha256=c._digest(completed, c._LIMIT))
    enroll_fixture[1][bad] = True
    response = issue(e.post_verified_json, old, pending)
    with pytest.raises((e.EnrollmentError, InvalidSignature)):
        r._build_renewal_candidate(old, response, pending)


def test_handler_two_complete_cycles(bundle, enroll_fixture, monkeypatch):
    import repeater.data_acquisition.glass_handler as h
    from tests.test_glass_rotation_reports import ack

    options = enroll_fixture[0]
    issuer = e.post_verified_json
    requests = []
    clients = []
    issued = {}
    lost = {"renew": True, "report": True}

    def client():
        value = Mock()
        clients.append(value)
        return value

    def post(url, payload, **kwargs):
        if url.endswith("/report"):
            if lost["report"]:
                lost["report"] = False
                raise TimeoutError("synthetic lost report response")
            return ack(payload)
        requests.append(dict(payload))
        current = json.loads(options["credential_file"].read_bytes())
        if payload["request_id"] not in issued:
            enroll_fixture[1]["serial"] = len(issued) + 3
            issued[payload["request_id"]] = issue(issuer, current, payload)
        if lost["renew"]:
            lost["renew"] = False
            raise TimeoutError("synthetic lost renewal response")
        return issued[payload["request_id"]]

    monkeypatch.setattr(h, "mqtt", Mock(Client=client))
    monkeypatch.setattr(t, "post_verified_json", post)
    monkeypatch.setattr(e, "post_verified_json", post)
    # Eligibility alone is controlled; crypto clocks and all keys/signatures are real.
    clock = Mock()
    clock.now.return_value = x509.load_pem_x509_certificate(
        bundle["client_cert"].encode()
    ).not_valid_after_utc
    monkeypatch.setattr(h, "datetime", clock)
    handler = make_handler(options, True)
    handler._sync_mqtt_publisher()
    keys = [bundle["private_key"]]
    for cycle in range(2):
        old_client = handler._mqtt_client
        asyncio.run(handler._maintain_operational_certificate())
        if cycle == 0:
            assert handler._mqtt_client is old_client
            pending_path = options["credential_file"].parent / "rotation-state" / "pending.json"
            saved = pending_path.read_bytes()
            asyncio.run(handler._maintain_operational_certificate())
            assert pending_path.read_bytes() == saved
        new_client = handler._mqtt_client
        assert new_client is not old_client
        assert not handler._mqtt_ready
        handler._on_mqtt_connect(old_client, None, None, 0)
        assert not handler._mqtt_ready
        handler._on_mqtt_connect(new_client, None, None, 0)
        asyncio.run(handler._flush_operational_certificate_report())
        if cycle == 0:
            outbox = options["credential_file"].parent / "rotation-state" / "report-outbox.json"
            assert outbox.exists()
            assert pending_path.exists()
            asyncio.run(handler._flush_operational_certificate_report())
        current = json.loads(options["credential_file"].read_bytes())
        keys.append(current["private_key"])
        store = options["credential_file"].parent
        assert c.load_completed(
            current, store_dir=store, credential_file=options["credential_file"]
        )
        assert not (store / "rotation-state" / "pending.json").exists()
        assert not (store / "rotation-state" / "install.json").exists()
    assert len(set(keys)) == 3
    assert len({p["request_id"] for p in requests}) == 2
    assert requests[0] == requests[1]
    handler._close_mqtt_publisher()


@pytest.mark.parametrize("missing_accepted", [False, True])
def test_lost_successor_response_new_boot_defers_old_report(
    accepted, enroll_fixture, monkeypatch, missing_accepted
):
    import repeater.data_acquisition.glass_handler as h
    from tests.test_glass_rotation_reports import ack

    complete(accepted)
    old, store, target = accepted
    old_receipt = state(accepted, "completed.json").read_bytes()
    if missing_accepted:
        state(accepted, "report-accepted.json").unlink()
    latest = json.loads(old_receipt)["accepted_record"]["report"]
    issuer = e.post_verified_json
    active = {"request_id": old["rotation_request_id"], "cert_serial": old["cert_serial"]}
    issued = {}
    requests, reports, rejected, queued = [], [], [], []
    original_queue = q.queue_report

    def observe_queue(*a, **kwargs):
        report = original_queue(*a, **kwargs)
        queued.append(dict(report))
        return report

    def post(url, payload, **kwargs):
        if url.endswith("/report"):
            reports.append(dict(payload))
            if any(payload[key] != active[key] for key in active):
                rejected.append(dict(payload))
                raise e.EnrollmentError("synthetic HTTP 409 stale rotation")
            return ack(payload)
        requests.append(dict(payload))
        request = payload["request_id"]
        if request not in issued:
            enroll_fixture[1]["serial"] = 3
            issued[request] = issue(issuer, old, payload)
            active.update(request_id=request, cert_serial=issued[request]["cert_serial"])
            # The server has committed NEW before the client loses its response.
            raise TimeoutError("synthetic lost renewal response")
        return issued[request]

    monkeypatch.setattr(q, "queue_report", observe_queue)
    monkeypatch.setattr(h, "mqtt", Mock(Client=lambda: Mock()))
    monkeypatch.setattr(t, "post_verified_json", post)
    monkeypatch.setattr(e, "post_verified_json", post)
    clock = Mock()
    clock.now.return_value = x509.load_pem_x509_certificate(
        old["client_cert"].encode()
    ).not_valid_after_utc
    monkeypatch.setattr(h, "datetime", clock)
    handler = make_handler(enroll_fixture[0], True)
    try:
        assert handler._boot_id != latest["boot_id"]
        handler._sync_mqtt_publisher()
        old_client = handler._mqtt_client
        handler._on_mqtt_connect(old_client, None, None, 0)
        assert handler._mqtt_ready
        asyncio.run(handler._maintain_operational_certificate())
        assert handler._mqtt_client is old_client
        assert json.loads(target.read_bytes()) == old
        pending_raw = state(accepted, "pending.json").read_bytes()
        assert json.loads(pending_raw)["version"] == 2
        assert active["request_id"] != old["rotation_request_id"]
        # Same successful-inform cycle flushes after failed maintenance. Before
        # the fix this produces OLD/boot-B, receives 409, and blocks every retry.
        asyncio.run(handler._flush_operational_certificate_report())
        assert handler._mqtt_ready  # OLD telemetry readiness is not invalidated.
        assert state(accepted, "pending.json").read_bytes() == pending_raw
        assert state(accepted, "completed.json").read_bytes() == old_receipt
        blocked = state(accepted, "report-outbox.json").exists()
        asyncio.run(handler._maintain_operational_certificate())
        if blocked:
            assert rejected and rejected[0]["request_id"] == old["rotation_request_id"]
            assert state(accepted, "report-outbox.json").exists()
            assert json.loads(target.read_bytes()) == old
            assert handler._mqtt_client is old_client
        assert not blocked, (
            "lost NEW response queued an unacknowledgeable OLD-boot report and stranded cutover"
        )
        assert reports == []
        assert queued == [latest]
        assert requests[0] == requests[1]
        assert state(accepted, "pending.json").read_bytes() == pending_raw
        new = json.loads(target.read_bytes())
        assert new["rotation_request_id"] == active["request_id"]
        assert new["private_key"] != old["private_key"]
        new_client = handler._mqtt_client
        assert new_client is not old_client and not handler._mqtt_ready
        assert state(accepted, "completed.json").read_bytes() == old_receipt
        assert not state(accepted, "report-accepted.json").exists()
        asyncio.run(handler._flush_operational_certificate_report())
        handler._on_mqtt_connect(old_client, None, None, 0)
        asyncio.run(handler._flush_operational_certificate_report())
        assert reports == [] and not handler._mqtt_ready
        handler._on_mqtt_connect(new_client, None, None, 0)
        asyncio.run(handler._flush_operational_certificate_report())
        assert len(reports) == 1 and rejected == []
        report = reports[0]
        assert report["request_id"] == new["rotation_request_id"]
        assert report["cert_serial"] == new["cert_serial"]
        assert report["fingerprint_sha256"] == new["fingerprint_sha256"]
        assert report["boot_id"] == handler._boot_id
        case = (new, store, target)
        receipt = c.load_completed(new, **args(case))
        assert receipt is not None
        assert receipt["request_id"] == active["request_id"]
        assert not state(case, "pending.json").exists()
        assert not state(case, "install.json").exists()
        assert not state(case, "report-outbox.json").exists()
        assert json.loads(state(case, "report-accepted.json").read_bytes())["report"] == report
    finally:
        handler._close_mqtt_publisher()


def test_successor_deferral_returns_latest_real_acceptance(accepted):
    from tests.test_glass_rotation_reports import BOOT, NEXT_BOOT

    complete(accepted)
    latest = queue(accepted, NEXT_BOOT)
    acknowledge(accepted, latest)
    r.prepare_rotation(accepted[0], **args(accepted))
    before = snapshot(accepted)
    embedded = json.loads(before["completed.json"])["accepted_record"]["report"]
    assert embedded["boot_id"] == BOOT != latest["boot_id"]
    assert queue(accepted, "00000000-0000-4000-8000-000000000003") == latest
    assert q.load_report(accepted[0], **args(accepted)) is None
    assert snapshot(accepted) == before


@pytest.mark.parametrize("bad", ["boot", "serial", "fingerprint", "pending_marker", "caller"])
def test_successor_deferral_still_validates_all_authority(accepted, bad):
    complete(accepted)
    r.prepare_rotation(accepted[0], **args(accepted))
    callback = {}
    case = accepted
    if bad == "pending_marker":
        path = state(accepted, "pending.json")
        pending = json.loads(path.read_bytes())
        pending["previous_completed_sha256"] = "0" * 64
        path.write_text(json.dumps(pending))
    elif bad == "caller":
        case = (dict(accepted[0], pubkey="foreign-caller"), accepted[1], accepted[2])
    else:
        callback = {
            "boot": {"boot": "invalid"},
            "serial": {"connected_serial": "ff"},
            "fingerprint": {"connected_fingerprint": "0" * 64},
        }[bad]
    before = snapshot(accepted)
    with pytest.raises(e.EnrollmentError):
        queue(case, **callback)
    assert snapshot(accepted) == before
    assert not state(accepted, "report-outbox.json").exists()


def test_successor_install_retry_outbox_and_completion(accepted, monkeypatch):
    from tests.test_glass_rotation_reports import NEXT_BOOT

    complete(accepted)
    old, store, target = accepted
    issuer = e.post_verified_json
    # Retain the existing-outbox gate coverage independently of fresh-report
    # deferral: restore a real previously published, exactly acknowledged record
    # as accepted-but-not-cleaned crash state after preparing the successor.
    report = queue(accepted, NEXT_BOOT)
    outbox_raw = state(accepted, "report-outbox.json").read_bytes()
    acknowledge(accepted, report)
    payload = r.prepare_rotation(old, **args(accepted))
    response = issue(issuer, old, payload)
    state(accepted, "report-outbox.json").write_bytes(outbox_raw)
    state(accepted, "report-outbox.json").chmod(0o600)
    before = snapshot(accepted)
    assert queue(accepted) == report
    assert q.load_report(old, **args(accepted)) == report
    assert snapshot(accepted) == before
    with pytest.raises(e.EnrollmentError):
        r.install_renewal_candidate(old, response, **args(accepted))
    assert snapshot(accepted) == before
    acknowledge(accepted, report)
    r.install_renewal_candidate(old, response, **args(accepted))
    new = json.loads(target.read_bytes())
    case = (new, store, target)
    assert not state(case, "report-accepted.json").exists()
    monkeypatch.setattr(
        t,
        "post_verified_json",
        lambda *a, **k: pytest.fail("installed retry must not renew over HTTPS"),
    )
    retry = t.renew_credentials(
        credential_file=target,
        base_url=new["base_url"],
        device_id=new["device_id"],
        store_dir=store,
    )
    assert retry["request_id"] == payload["request_id"]
    acknowledge(case, queue(case))
    retained = state(case, "report-accepted.json").read_bytes()
    r.install_renewal_candidate(new, response, **args(case))
    assert state(case, "report-accepted.json").read_bytes() == retained
    complete(case)
    assert c.load_completed(new, **args(case))["request_id"] == payload["request_id"]
    assert r.prepare_rotation(new, **args(case))["request_id"] != payload["request_id"]


@pytest.mark.parametrize("fault", ["old_accepted_unlink", "cutover", "completed_publication"])
def test_successor_crash_retries_preserve_exact_keys(accepted, monkeypatch, fault):
    from tests.test_glass_rotation_reports import NEXT_BOOT

    complete(accepted)
    old, store, target = accepted
    payload = r.prepare_rotation(old, **args(accepted))
    response = issue(e.post_verified_json, old, payload)
    pending_raw = state(accepted, "pending.json").read_bytes()
    old_receipt = state(accepted, "completed.json").read_bytes()
    if fault != "completed_publication":
        original = r._unlink if fault == "old_accepted_unlink" else r._replace

        def fail(*a, **k):
            if fault == "old_accepted_unlink" or a[1] == target.name:
                raise OSError("synthetic crash")
            return original(*a, **k)

        with monkeypatch.context() as patch:
            patch.setattr(r, "_unlink" if fault == "old_accepted_unlink" else "_replace", fail)
            with pytest.raises(e.EnrollmentError):
                r.install_renewal_candidate(old, response, **args(accepted))
        assert json.loads(target.read_bytes()) == old
        assert state(accepted, "pending.json").read_bytes() == pending_raw
        assert state(accepted, "completed.json").read_bytes() == old_receipt
        # Even removed old public acceptance can report from durable embedded proof.
        acknowledge(accepted, queue(accepted, NEXT_BOOT))
    r.install_renewal_candidate(old, response, **args(accepted))
    case = (json.loads(target.read_bytes()), store, target)
    acknowledge(case, queue(case))
    if fault == "completed_publication":
        original = c._replace

        def fail(*a, **k):
            original(*a, **k)
            raise OSError("synthetic post-publication crash")

        with monkeypatch.context() as patch:
            patch.setattr(c, "_replace", fail)
            with pytest.raises(e.EnrollmentError):
                complete(case)
        assert state(case, "completed.json").read_bytes() != old_receipt
        assert state(case, "pending.json").read_bytes() == pending_raw
    complete(case)
    assert case[0]["rotation_request_id"] == payload["request_id"]
    assert not state(case, "pending.json").exists()
    assert not state(case, "install.json").exists()
    assert c.load_completed(case[0], **args(case))["request_id"] == payload["request_id"]
