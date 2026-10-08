"""Durable completion receipts and matched key/journal retirement.

Acceptance is a node assertion, not broker proof. The retained previous bundle
is secret historical backup material, never runtime authority or rollback.
Handler reconciliation uses this core without provisioning or expired-current recovery.
"""

import fcntl
import hashlib
import os
import re
import secrets
from contextlib import contextmanager
from datetime import datetime

from repeater.glass import mqtt_credentials as m
from repeater.glass import rotation_reports as q
from repeater.glass import rotation_state as r
from repeater.glass.enrollment import EnrollmentError

_COMPLETED = "completed.json"
_LIMIT = 131072
_FIELDS = {
    "version",
    "base_url",
    "device_id",
    "generation_sha256",
    "credential_file",
    "request_id",
    "cert_serial",
    "fingerprint_sha256",
    "candidate_sha256",
    "pending_sha256",
    "install_journal",
    "accepted_record",
}
_PUBLIC = ("device_id", "request_id", "cert_serial", "fingerprint_sha256", "expires_at")
_fsync = os.fsync
_replace = os.replace
_unlink = os.unlink
_read_private_json = r._read_private_json
_write_staged = r._write_staged


def _digest(value, limit):
    return hashlib.sha256(r._canonical_json(value, limit)).hexdigest()


def _equal(left, right, limit):
    return r._canonical_json(left, limit) == r._canonical_json(right, limit)


def _optional(directory, name, limit):
    try:
        return _read_private_json(directory, name, limit)[0]
    except FileNotFoundError:
        return None


def _no_outbox(directory):
    try:
        os.stat(q._OUTBOX, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise EnrollmentError("Outstanding report prevents completion")


def _response(current):
    value = {
        k: current[k]
        for k in (
            "device_id",
            "client_cert",
            "ca_cert",
            "cert_serial",
            "expires_at",
            "fingerprint_sha256",
        )
    }
    value.update(request_id=current["rotation_request_id"], state="issued")
    value = r._renewal_response(value)
    q._uuid(value["request_id"])
    from cryptography.hazmat.primitives import hashes

    leaf = r._single_certificate(current["client_cert"])
    if leaf.fingerprint(hashes.SHA256()).hex() != value["fingerprint_sha256"]:
        raise EnrollmentError("Current fingerprint mismatch")
    if format(leaf.serial_number, "x") != value["cert_serial"]:
        raise EnrollmentError("Noncanonical current serial")
    return value


@contextmanager
def _authority(credentials, store_dir, credential_file, *, require_rotation=True):
    fds = []
    try:
        path = os.fspath(credential_file)
        if type(path) is not str or not os.path.isabs(path) or ".." in path.split("/"):
            raise EnrollmentError("Invalid completion filename")
        parent, name = os.path.split(path)
        if (
            not name
            or name in {".lock", "pending.json", "install.json", _COMPLETED, q._OUTBOX, q._ACCEPTED}
            or name.startswith(".stage-")
        ):
            raise EnrollmentError("Reserved completion filename")
        store = m._open_directory(store_dir)
        fds.append(store)
        directory = os.open("rotation-state", m._DIR_FLAGS, dir_fd=store)
        fds.append(directory)
        r._check_private(directory, directory=True)
        lock = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        fds.append(lock)
        r._check_private(lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        r._check_private(directory, directory=True)
        r._check_private(lock)
        parent_fd = m._open_directory(parent)
        fds.append(parent_fd)
        a, b = os.fstat(parent_fd), os.fstat(directory)
        if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
            raise EnrollmentError("Credential target cannot be rotation state")
        current, snapshot = _read_private_json(parent_fd, name, r._BUNDLE_LIMIT)
        context = r._context(current)
        if r._context(credentials) != context or not r._same_bundle(current, credentials):
            raise EnrollmentError("Installed credential mismatch")
        if require_rotation:
            _response(current)
        binding = {
            "version": 1,
            "base_url": context["base_url"],
            "generation_sha256": context["generation_sha256"],
            "credential_file": path,
            "candidate_sha256": r._bundle_digest(current),
        }
        yield directory, parent_fd, name, current, snapshot, context, binding
    finally:
        failed = False
        for fd in reversed(fds):
            try:
                os.close(fd)
            except Exception:  # noqa: BLE001 - release every descriptor
                failed = True
        if failed:
            raise EnrollmentError("Unable to release private completion descriptors") from None


def _accepted(value, current, binding):
    if (
        not isinstance(value, dict)
        or set(value) != q._RECORD_FIELDS | {"ack"}
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise EnrollmentError("Invalid accepted completion assertion")
    for k in binding.keys() - {"version"}:
        if type(value[k]) is not str or value[k] != binding[k]:
            raise EnrollmentError("Foreign accepted completion assertion")
    q._report(value["report"], current)
    q._ack(value["ack"], value["report"])
    r._canonical_json(value, 8192)
    return value


def _historical_journal(journal, current, context, binding):
    # Unlike c3 creation authority, this retained receipt does not require the
    # old leaf still to be valid. Current _context is never relaxed.
    if (
        not isinstance(journal, dict)
        or set(journal) != r._INSTALL_FIELDS
        or type(journal["version"]) is not int
        or journal["version"] != 1
    ):
        raise EnrollmentError("Invalid historical journal")
    for k in r._INSTALL_FIELDS - {"version", "previous_bundle"}:
        if type(journal[k]) is not str:
            raise EnrollmentError("Invalid historical journal types")
    expected = dict(
        context,
        credential_file=binding["credential_file"],
        request_id=current["rotation_request_id"],
        candidate_sha256=binding["candidate_sha256"],
    )
    if any(journal[k] != v for k, v in expected.items()):
        raise EnrollmentError("Historical journal binding mismatch")
    for k in ("previous_sha256", "candidate_sha256", "generation_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", journal[k]):
            raise EnrollmentError("Invalid historical digest")
    previous = journal["previous_bundle"]
    if not isinstance(previous, dict) or r._bundle_digest(previous) != journal["previous_sha256"]:
        raise EnrollmentError("Historical backup digest mismatch")
    if r._context_snapshot(previous, historical=True) != context:
        raise EnrollmentError("Historical backup certificate mismatch")
    r._single_certificate(previous["client_cert"])
    for k in ("base_url", "device_id", "operational_token", "pubkey"):
        if type(previous[k]) is not str or previous[k] != current[k]:
            raise EnrollmentError("Historical backup context mismatch")
    for k, bound in (
        ("private_key", 14000),
        ("client_cert", 14000),
        ("ca_cert", 14000),
        ("cert_serial", 40),
        ("expires_at", 64),
    ):
        if type(previous[k]) is not str or not 1 <= len(previous[k]) <= bound:
            raise EnrollmentError("Invalid historical backup scalar")
        previous[k].encode("ascii")
    serial = previous["cert_serial"]
    if not re.fullmatch(r"[0-9a-f]{1,40}", serial) or int(serial, 16) <= 0:
        raise EnrollmentError("Invalid historical serial")
    if format(int(serial, 16), "x") != serial:
        raise EnrollmentError("Noncanonical historical serial")
    expiry = datetime.fromisoformat(previous["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry.utcoffset() is None:
        raise EnrollmentError("Invalid historical expiry")
    from cryptography.hazmat.primitives import serialization

    old_ca = r._single_certificate(previous["ca_cert"])
    ca = r._single_certificate(current["ca_cert"])
    if old_ca.public_bytes(serialization.Encoding.DER) != ca.public_bytes(
        serialization.Encoding.DER
    ):
        raise EnrollmentError("Historical pinned CA mismatch")
    r._canonical_json(journal, r._JOURNAL_LIMIT)


def _validate(value, current, context, binding):
    if (
        not isinstance(value, dict)
        or set(value) != _FIELDS
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise EnrollmentError("Invalid completion fields")
    for k in _FIELDS - {"version", "install_journal", "accepted_record"}:
        if type(value[k]) is not str:
            raise EnrollmentError("Invalid completion types")
    expected = dict(
        context,
        credential_file=binding["credential_file"],
        request_id=current["rotation_request_id"],
        cert_serial=current["cert_serial"],
        fingerprint_sha256=current["fingerprint_sha256"],
        candidate_sha256=binding["candidate_sha256"],
    )
    if any(value[k] != v for k, v in expected.items()):
        raise EnrollmentError("Foreign completion binding")
    for k in ("generation_sha256", "candidate_sha256", "pending_sha256", "fingerprint_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", value[k]):
            raise EnrollmentError("Invalid completion digest")
    _historical_journal(value["install_journal"], current, context, binding)
    _accepted(value["accepted_record"], current, binding)
    r._canonical_json(value, _LIMIT)
    return value


def _remaining(
    directory, value, current, context, binding, allow_outbox=False, allow_successor_pending=False
):
    # Only validated completed-current report callers may admit a linked next
    # request. Completion's default must never retire the next private key.
    if not allow_outbox:
        _no_outbox(directory)
    pending = r._read_pending(directory, context)
    successor = pending is not None and pending["request_id"] != value["request_id"]
    if successor:
        if not allow_successor_pending:
            raise EnrollmentError("Foreign remaining pending request")
        r._validate_successor_pending(pending, current, value, context, binding)
    elif pending is not None and (
        pending["private_key"] != current["private_key"]
        or _digest(pending, r._LIMIT) != value["pending_sha256"]
    ):
        raise EnrollmentError("Foreign remaining pending request")
    journal = _optional(directory, "install.json", r._JOURNAL_LIMIT)
    r._cycle_phase(current, pending, value, journal, binding["credential_file"])
    accepted = _optional(directory, q._ACCEPTED, 8192)
    if accepted is not None:
        _accepted(accepted, current, binding)
    return pending, journal


def _create(directory, current, context, binding):
    _no_outbox(directory)
    pending = r._read_pending(directory, context)
    if pending is None:
        raise EnrollmentError("Missing pending completion authority")
    journal = _read_private_json(directory, "install.json", r._JOURNAL_LIMIT)[0]
    previous = r._validate_install_journal(journal, context, pending, binding["credential_file"])
    candidate = r._build_renewal_candidate(previous, _response(current), pending)
    if (
        not r._same_bundle(candidate, current)
        or journal["candidate_sha256"] != binding["candidate_sha256"]
    ):
        raise EnrollmentError("Completion candidate mismatch")
    accepted = _read_private_json(directory, q._ACCEPTED, 8192)[0]
    _accepted(accepted, current, binding)
    value = dict(
        context,
        version=1,
        credential_file=binding["credential_file"],
        request_id=current["rotation_request_id"],
        cert_serial=current["cert_serial"],
        fingerprint_sha256=current["fingerprint_sha256"],
        candidate_sha256=binding["candidate_sha256"],
        pending_sha256=_digest(pending, r._LIMIT),
        install_journal=journal,
        accepted_record=accepted,
    )
    return _validate(value, current, context, binding)


def _publish(directory, value, current, context, binding, parent, name, snapshot):
    stages = []
    stage = ".stage-" + secrets.token_hex(16)
    try:
        _write_staged(
            directory,
            stage,
            r._canonical_json(value, _LIMIT),
            on_create=lambda: stages.append(stage),
        )
        checked = _read_private_json(directory, stage, _LIMIT)[0]
        _validate(checked, current, context, binding)
        if not _equal(checked, value, _LIMIT):
            raise EnrollmentError("Completion stage mismatch")
        reread, raw = _read_private_json(parent, name, r._BUNDLE_LIMIT)
        if raw != snapshot or not r._same_bundle(reread, current):
            raise EnrollmentError("Current completion bundle changed during staging")
        _replace(stage, _COMPLETED, src_dir_fd=directory, dst_dir_fd=directory)
        stages.remove(stage)  # Publication must never be rolled back.
        _fsync(directory)
        checked = _read_private_json(directory, _COMPLETED, _LIMIT)[0]
        _validate(checked, current, context, binding)
        if not _equal(checked, value, _LIMIT):
            raise EnrollmentError("Completion publication mismatch")
    finally:
        for owned in stages:
            try:
                _unlink(owned, dir_fd=directory)
            except FileNotFoundError:
                pass


def _public(current):
    return {
        k: current["rotation_request_id"] if k == "request_id" else current[k] for k in _PUBLIC
    } | {"state": "rotation_completed"}


def complete_rotation(credentials, *, store_dir, credential_file, commit_guard=None):
    """Admit one exact historical completion, then retire only matched state.

    The trusted guard runs once after validation and the current snapshot check,
    before any durable mutation, including retry fsync. Once admitted the exact
    transaction finishes even if a future handler cancels later. Never pass a
    guard through from configuration or wire input.
    """
    try:
        with _authority(credentials, store_dir, credential_file) as authority:
            directory, parent, name, current, snapshot, context, binding = authority
            value = _optional(directory, _COMPLETED, _LIMIT)
            pending = r._read_pending(directory, context)
            journal = _optional(directory, "install.json", r._JOURNAL_LIMIT)
            phase = r._cycle_phase(current, pending, value, journal, binding["credential_file"])
            creating = phase == "installed"
            if creating:
                value = _create(directory, current, context, binding)
            else:
                if phase != "completed":
                    raise EnrollmentError("Successor rotation is not complete")
                _validate(value, current, context, binding)
            _remaining(directory, value, current, context, binding)
            reread, raw = _read_private_json(parent, name, r._BUNDLE_LIMIT)
            if raw != snapshot or not r._same_bundle(reread, current):
                raise EnrollmentError("Current completion bundle changed")
            if commit_guard is not None:
                commit_guard()  # COMPLETION COMMIT ADMISSION
            if creating:
                _publish(directory, value, current, context, binding, parent, name, snapshot)
            else:
                _fsync(directory)
            pending, journal = _remaining(directory, value, current, context, binding)
            if pending is not None:
                _unlink("pending.json", dir_fd=directory)
            _fsync(directory)
            # Revalidate any surviving journal before its own deletion.
            _, journal = _remaining(directory, value, current, context, binding)
            if journal is not None:
                _unlink("install.json", dir_fd=directory)
            _fsync(directory)
            checked = _read_private_json(directory, _COMPLETED, _LIMIT)[0]
            _validate(checked, current, context, binding)
            if not _equal(checked, value, _LIMIT):
                raise EnrollmentError("Completion final readback mismatch")
            if any(
                item is not None
                for item in _remaining(directory, checked, current, context, binding)
            ):
                raise EnrollmentError("Completion retirement incomplete")
            return _public(current)
    except Exception:  # noqa: BLE001 - never expose secret-bearing errors
        raise EnrollmentError("Unable to complete durable private Glass rotation") from None


def reconcile_rotation(credentials, *, store_dir, credential_file, commit_guard=None):
    """Finish an exactly acknowledged current cycle; never retire a successor.

    The second lock acquisition in complete_rotation revalidates everything.
    A cooperating successor appearing between reads is rejected, not removed.
    """
    try:
        with _authority(
            credentials, store_dir, credential_file, require_rotation=False
        ) as authority:
            directory, _, _, current, _, context, binding = authority
            value = _optional(directory, _COMPLETED, _LIMIT)
            pending = r._read_pending(directory, context)
            journal = _optional(directory, "install.json", r._JOURNAL_LIMIT)
            phase = r._cycle_phase(current, pending, value, journal, binding["credential_file"])
            if phase == "previous":
                return False
            if _optional(directory, q._OUTBOX, 4096) is not None:
                return False
            accepted = _optional(directory, q._ACCEPTED, 8192)
            if phase == "installed" and accepted is None:
                return False
            if accepted is not None:
                _accepted(accepted, current, binding)
        complete_rotation(
            credentials,
            store_dir=store_dir,
            credential_file=credential_file,
            commit_guard=commit_guard,
        )
        return True
    except Exception:  # noqa: BLE001 - protect private state
        raise EnrollmentError("Unable to reconcile private Glass rotation completion") from None


def load_completed(credentials, *, store_dir, credential_file):
    """Read completion/current/remaining authority; never write or retire state."""
    try:
        with _authority(credentials, store_dir, credential_file) as authority:
            directory, _, _, current, _, context, binding = authority
            value = _optional(directory, _COMPLETED, _LIMIT)
            if value is None:
                return None
            pending = r._read_pending(directory, context)
            journal = _optional(directory, "install.json", r._JOURNAL_LIMIT)
            phase = r._cycle_phase(current, pending, value, journal, binding["credential_file"])
            if phase == "installed":
                return None
            _remaining(directory, value, current, context, binding)
            return _public(current)
    except Exception:  # noqa: BLE001 - never expose secret-bearing errors
        raise EnrollmentError("Unable to load durable private Glass rotation completion") from None
