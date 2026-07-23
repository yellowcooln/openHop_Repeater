import threading

from repeater.web.auth.oidc_store import OIDCExchangeRecord, OIDCFlowRecord, OneTimeOIDCStore


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def flow(state="state-1"):
    return OIDCFlowRecord(
        state=state,
        nonce="nonce",
        code_verifier="verifier",
        return_to="/",
        client_id="client",
        expires_at=0,
    )


def exchange(code="exchange-1"):
    return OIDCExchangeRecord(
        code=code,
        client_id="client",
        identity={"sub": "alice"},
        expires_at=0,
    )


def test_flow_create_consume_replay_and_expiry():
    clock = FakeClock()
    store = OneTimeOIDCStore(ttl_seconds=10, max_entries=3, time_fn=clock)
    record = store.create_flow(lambda: "state-1", flow())

    assert record.expires_at == 1010.0
    assert store.consume_flow("state-1") == record
    assert store.consume_flow("state-1") is None

    store.create_flow(lambda: "state-2", flow("state-2"))
    clock.now += 11
    assert store.consume_flow("state-2") is None


def test_exchange_create_consume_replay_client_match_and_expiry():
    clock = FakeClock()
    store = OneTimeOIDCStore(ttl_seconds=5, max_entries=3, time_fn=clock)
    record = store.create_exchange(lambda: "code-1", exchange("code-1"))

    assert store.consume_exchange("code-1", "other") is None
    assert store.consume_exchange("code-1", "client") == record
    assert store.consume_exchange("code-1", "client") is None

    store.create_exchange(lambda: "code-2", exchange("code-2"))
    clock.now += 6
    assert store.consume_exchange("code-2", "client") is None


def test_max_entries_rejects_new_records_after_cleanup():
    clock = FakeClock()
    store = OneTimeOIDCStore(ttl_seconds=60, max_entries=2, time_fn=clock)

    store.create_flow(lambda: "s1", flow("s1"))
    store.create_flow(lambda: "s2", flow("s2"))

    assert store.create_flow(lambda: "s3", flow("s3")) is None


def test_concurrent_consume_only_succeeds_once():
    store = OneTimeOIDCStore(ttl_seconds=60, max_entries=2)
    store.create_flow(lambda: "state-1", flow())
    results = []

    def consume():
        results.append(store.consume_flow("state-1"))

    threads = [threading.Thread(target=consume) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(result is not None for result in results) == 1
