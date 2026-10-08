"""Parent acceptance probes complementing the implementer's pending-CSR suite."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

from tests.test_glass_rotation_state import bundle, enroll_fixture  # noqa: F401


def test_simultaneous_fresh_processes_share_one_request(bundle, tmp_path):  # noqa: F811
    code = (
        "import json,sys; from repeater.glass.rotation_state import prepare_rotation; "
        "print(json.dumps(prepare_rotation(json.loads(sys.stdin.read()),store_dir=sys.argv[1])))"
    )
    children = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(8)
    ]

    # Feed all workers concurrently, unlike sequential communicate() calls.
    def communicate(child):
        output, error = child.communicate(json.dumps(bundle), timeout=60)
        assert child.returncode == 0, error
        return json.loads(output)

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(communicate, children))
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    assert all(result == results[0] for result in results)
    state = json.loads((tmp_path / "rotation-state" / "pending.json").read_text())
    assert state["request_id"] == results[0]["request_id"]
    assert state["csr_pem"] == results[0]["csr_pem"]
