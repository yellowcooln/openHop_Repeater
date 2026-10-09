"""Owned v2 consumption tests with transport/credential seams, not TLS proof."""

import asyncio
import copy
import json
import threading
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from repeater.data_acquisition.glass_handler import GlassHandler
from repeater.glass.contracts import InformV2
from repeater.glass.job_store import JobStore, ledger_context
from tests import test_glass_job_store as job_store_tests
from tests.test_glass_job_store import acceptance, delivery

# Re-export the shared pytest fixture without an unused import shadowed by parameters.
private_store = job_store_tests.private_store


def handler(private_store, monkeypatch):
    credentials = {
        "device_id": "00000000-0000-4000-8000-000000000001",
        "base_url": "https://glass.test",
        "operational_token": "A" * 43,
        "pubkey": "0x" + "11" * 32,
    }
    daemon = SimpleNamespace(
        local_identity=SimpleNamespace(get_public_key=lambda: bytes.fromhex("11" * 32)),
        get_stats=lambda: {"uptime_seconds": 10, "rx_count": 1, "private_key": "must-not-export"},
        send_advert=Mock(side_effect=AssertionError("RF unavailable")),
    )
    value = GlassHandler({"glass": {"enabled": False}}, daemon_instance=daemon)
    value.config = {
        "repeater": {"node_name": "synthetic-node", "mode": "monitor", "secret": "must-not-export"},
        "glass": {
            "enabled": True,
            "base_url": credentials["base_url"],
            "device_id": credentials["device_id"],
            "operational_credential_file": str(private_store / "credentials.json"),
            "cert_store_dir": str(private_store),
            "ca_cert_path": "/explicit/https-ca.pem",
            "verify_tls": True,
        },
    }
    value.enabled = True
    value._operational_credentials = credentials
    value.base_url = credentials["base_url"]
    value.operational_credential_file = str(private_store / "credentials.json")
    value.cert_store_dir = str(private_store)
    value.ca_cert_path = "/explicit/https-ca.pem"
    monkeypatch.setattr(value, "_reload_runtime_settings", lambda: None)
    from repeater.glass import enrollment

    monkeypatch.setattr(enrollment, "load_credentials", lambda *a, **k: dict(credentials))

    async def noop():
        pass

    monkeypatch.setattr(value, "_maintain_operational_certificate", noop)
    monkeypatch.setattr(value, "_flush_operational_certificate_report", noop)
    return value


def ledger(value):
    return JobStore(
        ledger_context(value._operational_credentials, value.operational_credential_file),
        value.cert_store_dir,
    )


def response(payload, *, queries=None, jobs=None, acks=None):
    return {
        "type": "response",
        "version": 2,
        "device_id": payload["device_id"],
        "boot_id": payload["boot_id"],
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "interval_seconds": 30,
        "accepted_results": acks or [],
        "queries": queries or [],
        "jobs": jobs or [],
    }


def test_actual_owned_handler_durable_consumption_and_exact_ack(private_store, monkeypatch):
    value = handler(private_store, monkeypatch)
    query, job = delivery(False), delivery(True)
    sent = []

    def post(url, payload, credentials, ca, timeout):
        assert url == "https://glass.test/inform/v2"
        assert credentials["operational_token"] == "A" * 43
        assert ca == "/explicit/https-ca.pem" and timeout == 10
        assert payload["capabilities"] == {"diagnostic.read": 1}
        assert payload["inventory"]["radios"] == []
        assert "must-not-export" not in json.dumps(payload)
        InformV2.model_validate(payload)
        sent.append(copy.deepcopy(payload))
        return response(payload, queries=[query], jobs=[job])

    monkeypatch.setattr(value, "_post_job_json", post)
    asyncio.run(value._inform_once())
    pending = ledger(value).pending_results()
    assert {r["status"] for r in pending} == {"succeeded", "unsupported"}
    assert value.daemon_instance.send_advert.call_count == 0
    asyncio.run(value._inform_once())
    assert ledger(value).pending_results() == pending
    assert sent[1]["results"] == pending
    # A response without explicit receipts does NOT clear the durable outbox.
    monkeypatch.setattr(
        value,
        "_post_job_json",
        lambda url, payload, *args: response(
            payload, acks=[acceptance(r) for r in payload["results"]]
        ),
    )
    asyncio.run(value._inform_once())
    assert ledger(value).pending_results() == []


@pytest.mark.parametrize("damage", ["boot", "digest", "lease", "request", "extra"])
def test_full_response_validation_before_any_ack_or_delivery(private_store, monkeypatch, damage):
    value = handler(private_store, monkeypatch)
    prior = ledger(value).execute(
        delivery(False), value._boot_id, lambda _: {"status": "succeeded"}, {"diagnostic.read": 1}
    )
    new = delivery(False)

    def post(url, payload, *args):
        result = response(payload, acks=[acceptance(prior)], queries=[new])
        if damage == "boot":
            result["boot_id"] = str(uuid4())
        elif damage == "digest":
            result["accepted_results"][0]["result_sha256"] = "0" * 64
        elif damage == "lease":
            result["queries"][0].pop("lease_id")
        elif damage == "request":
            result["queries"][0]["device_id"] = str(uuid4())
        else:
            result["arbitrary_root_payload"] = {"set_mode": "forward"}
        return result

    monkeypatch.setattr(value, "_post_job_json", post)
    with pytest.raises(ValueError):
        asyncio.run(value._inform_once())
    assert ledger(value).pending_results() == [prior]
    with ledger(value)._locked() as (db, _):
        assert db.execute("SELECT count(*) FROM records").fetchone()[0] == 1


@pytest.mark.parametrize("disposition", ["accepted", "superseded"])
def test_stale409_archives_only_exact_durable_result(private_store, monkeypatch, disposition):
    value = handler(private_store, monkeypatch)
    request = delivery(True)
    result = ledger(value).execute(
        request, value._boot_id, lambda _: {"status": "unknown"}, {"set_mode": 1}
    )
    calls = []

    def post(url, payload, *args):
        calls.append(url)
        if url.endswith("/inform/v2"):
            return None
        assert payload == result
        return dict(acceptance(result), disposition=disposition)

    monkeypatch.setattr(value, "_post_job_json", post)
    with pytest.raises(ValueError):
        asyncio.run(value._inform_once())  # strict stale inform still fails
    assert calls == [
        "https://glass.test/inform/v2",
        "https://glass.test/device/commands/results/reconcile",
    ]
    assert ledger(value).pending_results() == []
    renewed = dict(request, lease_id=str(uuid4()), attempt=2)
    assert (
        ledger(value).execute(
            renewed,
            value._boot_id,
            lambda _: pytest.fail("archived unknown effect replay"),
            {"set_mode": 1},
        )
        == result
    )
    assert ledger(value).pending_results() == []


def test_repeated_cancellation_owns_worker_and_lock(private_store, monkeypatch):
    value = handler(private_store, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    new = delivery(False)

    def post(url, payload, *args):
        entered.set()
        assert release.wait(10)
        return response(payload, queries=[new])

    monkeypatch.setattr(value, "_post_job_json", post)

    async def run():
        task = asyncio.create_task(value._inform_once())
        while not entered.is_set():
            await asyncio.sleep(0.005)
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.01)
        assert value._job_lock.locked() and not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not value._job_lock.locked()

    asyncio.run(run())
    assert ledger(value).pending_results() == []
    assert not value._runtime_settings_valid


def test_config_change_and_generation_change_reject_delivery(private_store, monkeypatch):
    value = handler(private_store, monkeypatch)
    new = delivery(False)

    def post(url, payload, *args):
        value.config["glass"]["base_url"] = "https://other.test"
        return response(payload, queries=[new])

    monkeypatch.setattr(value, "_post_job_json", post)
    with pytest.raises(ValueError):
        asyncio.run(value._inform_once())
    assert ledger(value).pending_results() == []


def test_cancellation_after_start_persists_real_outcome(private_store, monkeypatch):
    value = handler(private_store, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    new = delivery(False)
    monkeypatch.setattr(
        value, "_post_job_json", lambda url, payload, *args: response(payload, queries=[new])
    )
    calls = 0
    diagnostic = value._diagnostic_v2

    def observed():
        nonlocal calls
        calls += 1
        if calls == 2:  # first call builds telemetry; second is admitted executor
            entered.set()
            assert release.wait(10)
        return diagnostic()

    monkeypatch.setattr(value, "_diagnostic_v2", observed)

    async def run():
        task = asyncio.create_task(value._inform_once())
        while not entered.is_set():
            await asyncio.sleep(0.005)
        task.cancel()
        await asyncio.sleep(0.01)
        assert value._job_lock.locked() and not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    results = ledger(value).pending_results()
    assert len(results) == 1 and results[0]["status"] == "succeeded"
    assert results[0]["request_id"] == new["request_id"]
    assert calls == 2  # admitted callback wasn't rolled back, orphaned or retried


def test_transport_strict_https_ca_token_duplicate_json_and_409(monkeypatch):
    from repeater.data_acquisition import glass_handler as module
    from repeater.glass.enrollment import EnrollmentError

    captures = []
    monkeypatch.setattr(
        module.ssl, "create_default_context", lambda **kw: captures.append(kw) or object()
    )
    monkeypatch.setattr(module.request, "HTTPSHandler", lambda **kw: kw)

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == 262145
            return b'{"type":"response","type":"response"}'

    def opener(*args):
        def open(req, **options):
            assert req.full_url == "https://glass.test/inform/v2"
            assert req.get_header("Authorization") == "Bearer " + "A" * 43
            return Reply()

        return SimpleNamespace(open=open)

    monkeypatch.setattr(module.request, "build_opener", opener)
    with pytest.raises(EnrollmentError):
        GlassHandler._post_job_json(
            "https://glass.test/inform/v2",
            {},
            {"operational_token": "A" * 43},
            "/explicit/ca.pem",
            10,
        )
    assert captures == [{"cafile": "/explicit/ca.pem"}]
    with pytest.raises(EnrollmentError):
        GlassHandler._post_job_json(
            "http://glass.test/inform/v2", {}, {"operational_token": "A" * 43}, None, 10
        )


@pytest.mark.parametrize(
    "reply",
    [
        {
            "type": "command",
            "command_id": "legacy",
            "action": "set_mode",
            "params": {"mode": "forward"},
        },
        {"type": "command", "command_id": "legacy", "action": "send_advert", "params": {}},
        {"type": "command", "command_id": "legacy", "action": "restart", "params": {}},
        {"type": "config_update", "config": {"repeater": {"mode": "forward"}}},
        {"type": "cert_renewal", "client_cert": "untrusted", "client_key": "untrusted"},
    ],
)
def test_unenrolled_discovery_ignores_every_mutating_response(monkeypatch, reply):
    from unittest.mock import AsyncMock

    from repeater.data_acquisition import glass_handler as module

    daemon = SimpleNamespace(get_stats=lambda: {"uptime_seconds": 1}, send_advert=Mock())
    manager = SimpleNamespace(save_config=Mock(), update_config=Mock())
    value = GlassHandler(
        {"glass": {"enabled": True}, "repeater": {"mode": "monitor"}},
        daemon_instance=daemon,
        config_manager=manager,
    )
    before = copy.deepcopy(value.config)
    payload = {"type": "inform", "observations": {"uptime_seconds": 1}}
    build = AsyncMock(return_value=payload)
    post = AsyncMock(return_value=dict(reply, interval=1))
    monkeypatch.setattr(value, "_build_inform_payload", build)
    monkeypatch.setattr(value, "_post_inform", post)
    command = AsyncMock(side_effect=AssertionError("unenrolled command"))
    config = Mock(side_effect=AssertionError("unenrolled config"))
    cert = Mock(side_effect=AssertionError("unenrolled certificate"))
    restart = Mock(side_effect=AssertionError("unenrolled restart"))
    monkeypatch.setattr(value, "_handle_command_response", command)
    monkeypatch.setattr(value, "_apply_config_update", config)
    monkeypatch.setattr(value, "_apply_cert_renewal", cert)
    monkeypatch.setattr(module, "restart_service", restart)
    assert asyncio.run(value._inform_once()) == value._clamp_interval(1)
    build.assert_awaited_once()
    post.assert_awaited_once_with(payload)
    assert value.config == before
    command.assert_not_awaited()
    for mock in (
        config,
        cert,
        restart,
        daemon.send_advert,
        manager.save_config,
        manager.update_config,
    ):
        mock.assert_not_called()


def test_enrolled_v2_failure_never_falls_back_to_legacy_discovery(private_store, monkeypatch):
    from unittest.mock import AsyncMock

    value = handler(private_store, monkeypatch)
    legacy = AsyncMock(side_effect=AssertionError("legacy authentication fallback"))
    monkeypatch.setattr(value, "_post_inform", legacy)
    monkeypatch.setattr(value, "_post_job_json", lambda *args: None)
    with pytest.raises(ValueError):
        asyncio.run(value._inform_once())
    legacy.assert_not_awaited()
