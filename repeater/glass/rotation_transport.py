"""One-cycle verified HTTPS renewal with durable, node-owned CSR retries.

Installation is not a broker connection, report, acknowledgment or retirement.
"""

import fcntl
import os

from repeater.glass import mqtt_credentials as m
from repeater.glass import rotation_state as r
from repeater.glass.enrollment import EnrollmentError, load_credentials, post_verified_json


def rotation_pending(store_dir):
    """Read-only secure existence probe; never provision or repair state."""
    descriptors = []
    try:
        store = m._open_directory(store_dir)
        descriptors.append(store)
        directory = os.open("rotation-state", m._DIR_FLAGS, dir_fd=store)
        descriptors.append(directory)
        r._check_private(directory, directory=True)
        lock = os.open(".lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        descriptors.append(lock)
        r._check_private(lock)
        fcntl.flock(lock, fcntl.LOCK_SH)
        r._check_private(directory, directory=True)
        r._check_private(lock)
        try:
            r._read_private_json(directory, "pending.json", 32768)
        except FileNotFoundError:
            return False
        return True
    except FileNotFoundError:
        # A missing lock in an existing state directory is not absent state.
        if len(descriptors) >= 2:
            raise EnrollmentError("Unable to inspect private Glass rotation state") from None
        return False
    except Exception:  # noqa: BLE001 - never expose private state or paths
        raise EnrollmentError("Unable to inspect private Glass rotation state") from None
    finally:
        failed = False
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except Exception:  # noqa: BLE001 - close remaining descriptors
                failed = True
        if failed:
            raise EnrollmentError("Unable to inspect private Glass rotation state") from None


def renew_credentials(
    *, credential_file, base_url, device_id, store_dir, https_ca_file=None, timeout=10
):
    """Return only the public bundle-installed receipt; retain pending on error."""
    try:
        current = load_credentials(credential_file, base_url=base_url, device_id=device_id)
        payload = r.prepare_rotation(current, store_dir=store_dir)
        if current.get("rotation_request_id") == payload["request_id"]:
            response = {
                field: current[field]
                for field in (
                    "device_id",
                    "client_cert",
                    "ca_cert",
                    "cert_serial",
                    "expires_at",
                    "fingerprint_sha256",
                )
            }
            response.update(request_id=payload["request_id"], state="issued")
        else:
            response = post_verified_json(
                current["base_url"] + "/device/certificates/renew",
                payload,
                token=current["operational_token"],
                timeout=timeout,
                https_ca_file=https_ca_file,
                max_request=16384,
            )
        return r.install_renewal_candidate(
            current,
            response,
            store_dir=store_dir,
            credential_file=credential_file,
        )
    except Exception:  # noqa: BLE001 - transport/crypto errors may contain secrets
        raise EnrollmentError("Unable to renew private Glass operational credentials") from None
