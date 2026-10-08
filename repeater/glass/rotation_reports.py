"""Offline durable public reports, not MQTT callback or broker proof.

Only trusted internal callers may supply connection metadata. No transport,
handler activation, request retirement, or expired-certificate recovery.
"""

import fcntl
import os
import re
import secrets
import uuid
from contextlib import contextmanager

from repeater.glass import mqtt_credentials as m
from repeater.glass import rotation_state as r
from repeater.glass.enrollment import EnrollmentError

_OUTBOX = "report-outbox.json"
_ACCEPTED = "report-accepted.json"
_REPORT_FIELDS = {
    "device_id",
    "request_id",
    "cert_serial",
    "fingerprint_sha256",
    "boot_id",
    "connected",
}
_ACK_FIELDS = {"device_id", "request_id", "cert_serial", "accepted", "state"}
_RECORD_FIELDS = {
    "version",
    "base_url",
    "generation_sha256",
    "credential_file",
    "candidate_sha256",
    "report",
}
_fsync = os.fsync
_replace = os.replace
_unlink = os.unlink
_read_private_json = r._read_private_json
_write_staged = r._write_staged


def _uuid(value):
    if type(value) is not str or len(value) != 36 or str(uuid.UUID(value)) != value:
        raise EnrollmentError("Invalid report UUID")


def _report(value, current):
    if not isinstance(value, dict) or set(value) != _REPORT_FIELDS:
        raise EnrollmentError("Invalid public report fields")
    if any(type(value[k]) is not str for k in _REPORT_FIELDS - {"connected"}):
        raise EnrollmentError("Invalid public report types")
    if value["connected"] is not True:
        raise EnrollmentError("Invalid connection assertion")
    for k in ("device_id", "request_id", "boot_id"):
        _uuid(value[k])
    if not re.fullmatch(r"[0-9a-f]{1,40}", value["cert_serial"]) or not int(
        value["cert_serial"], 16
    ):
        raise EnrollmentError("Invalid report serial")
    if not re.fullmatch(r"[0-9a-f]{64}", value["fingerprint_sha256"]):
        raise EnrollmentError("Invalid report fingerprint")
    expected = {
        "device_id": current["device_id"],
        "request_id": current["rotation_request_id"],
        "cert_serial": current["cert_serial"],
        "fingerprint_sha256": current["fingerprint_sha256"],
    }
    if any(value[k] != v for k, v in expected.items()):
        raise EnrollmentError("Report does not bind installed certificate")
    return dict(value)


def _ack(value, report):
    if not isinstance(value, dict) or set(value) != _ACK_FIELDS:
        raise EnrollmentError("Invalid report acknowledgment fields")
    if any(type(value[k]) is not str for k in _ACK_FIELDS - {"accepted"}):
        raise EnrollmentError("Invalid report acknowledgment types")
    if value["accepted"] is not True or value["state"] != "node_reported":
        raise EnrollmentError("Report was not accepted")
    if any(value[k] != report[k] for k in ("device_id", "request_id", "cert_serial")):
        raise EnrollmentError("Foreign report acknowledgment")
    return dict(value)


def _same(a, b):
    return r._canonical_json(a, 8192) == r._canonical_json(b, 8192)


@contextmanager
def _authority(credentials, store_dir, credential_file):
    fds = []
    try:
        path = os.fspath(credential_file)
        if type(path) is not str or not os.path.isabs(path) or ".." in path.split("/"):
            raise EnrollmentError("Invalid report credential filename")
        parent, name = os.path.split(path)
        if (
            not name
            or name in {".lock", "pending.json", "install.json", _OUTBOX, _ACCEPTED}
            or name.startswith(".stage-")
        ):
            raise EnrollmentError("Reserved report credential filename")
        context = r._context(credentials)
        r._canonical_json(credentials, r._BUNDLE_LIMIT)
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
        current, _ = _read_private_json(parent_fd, name, r._BUNDLE_LIMIT)
        if r._context(current) != context or not r._same_bundle(current, credentials):
            raise EnrollmentError("Installed credential mismatch")
        _uuid(current["rotation_request_id"])
        state = r._read_pending(directory, context)
        if state is None:
            raise EnrollmentError("Missing pending request")
        journal, _ = _read_private_json(directory, "install.json", r._JOURNAL_LIMIT)
        previous = r._validate_install_journal(journal, context, state, path)
        response = {
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
        response.update(request_id=current["rotation_request_id"], state="issued")
        candidate = r._build_renewal_candidate(previous, r._renewal_response(response), state)
        digest = r._bundle_digest(current)
        if not r._same_bundle(candidate, current) or journal["candidate_sha256"] != digest:
            raise EnrollmentError("Installed candidate authority mismatch")
        binding = {
            "version": 1,
            "base_url": context["base_url"],
            "generation_sha256": context["generation_sha256"],
            "credential_file": path,
            "candidate_sha256": digest,
        }
        yield directory, current, binding
    finally:
        failed = False
        for fd in reversed(fds):
            try:
                os.close(fd)
            except Exception:  # noqa: BLE001 - Release remaining descriptors after any cleanup failure.
                failed = True
        if failed:
            raise EnrollmentError("Unable to release private report descriptors") from None


def _record(directory, name, current, binding):
    limit = 8192 if name == _ACCEPTED else 4096
    try:
        value, raw = _read_private_json(directory, name, limit)
    except FileNotFoundError:
        return None, None
    fields = _RECORD_FIELDS | ({"ack"} if name == _ACCEPTED else set())
    if set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise EnrollmentError("Invalid report record fields")
    if any(type(value[k]) is not str or value[k] != binding[k] for k in binding if k != "version"):
        raise EnrollmentError("Foreign report record binding")
    _report(value["report"], current)
    if name == _ACCEPTED:
        _ack(value["ack"], value["report"])
    r._canonical_json(value, limit)
    return value, raw


def _publish(directory, name, value, current, binding):
    limit = 8192 if name == _ACCEPTED else 4096
    data = r._canonical_json(value, limit)
    stages = []
    stage = ".stage-" + secrets.token_hex(16)
    try:
        _write_staged(directory, stage, data, on_create=lambda: stages.append(stage))
        checked, _ = _read_private_json(directory, stage, limit)
        if not _same(checked, value):
            raise EnrollmentError("Report stage readback mismatch")
        _replace(stage, name, src_dir_fd=directory, dst_dir_fd=directory)
        stages.remove(stage)
        _fsync(directory)
        checked, _ = _record(directory, name, current, binding)
        if checked is None or not _same(checked, value):
            raise EnrollmentError("Report publication readback mismatch")
    finally:
        for owned in stages:
            try:
                _unlink(owned, dir_fd=directory)
            except FileNotFoundError:
                pass


def queue_report(
    credentials, *, store_dir, credential_file, boot_id, connected_serial, connected_fingerprint
):
    """Persist a public assertion from a future trusted current-client callback.

    A pending older boot assertion is retained until its exact acknowledgment.
    This API cannot establish that a successful callback actually occurred.
    """
    try:
        with _authority(credentials, store_dir, credential_file) as (directory, current, binding):
            proposed = _report(
                {
                    "device_id": current["device_id"],
                    "request_id": current["rotation_request_id"],
                    "cert_serial": connected_serial,
                    "fingerprint_sha256": connected_fingerprint,
                    "boot_id": boot_id,
                    "connected": True,
                },
                current,
            )
            outbox, _ = _record(directory, _OUTBOX, current, binding)
            accepted, _ = _record(directory, _ACCEPTED, current, binding)
            if outbox is not None:
                _fsync(directory)
                return dict(outbox["report"])
            if accepted is not None and accepted["report"]["boot_id"] == boot_id:
                _fsync(directory)
                return dict(accepted["report"])
            value = dict(binding, report=proposed)
            _publish(directory, _OUTBOX, value, current, binding)
            return proposed
    except Exception:  # noqa: BLE001 - Expose only a safe public error, never private failure details.
        raise EnrollmentError("Unable to queue durable public Glass certificate report") from None


def load_report(credentials, *, store_dir, credential_file):
    """Read validated existing report state without creating or deleting entries."""
    try:
        with _authority(credentials, store_dir, credential_file) as (directory, current, binding):
            outbox, _ = _record(directory, _OUTBOX, current, binding)
            _record(directory, _ACCEPTED, current, binding)
            return None if outbox is None else dict(outbox["report"])
    except Exception:  # noqa: BLE001 - Expose only a safe public error, never private failure details.
        raise EnrollmentError("Unable to load public Glass certificate report") from None


def acknowledge_report(
    credentials, report, response, *, store_dir, credential_file, commit_guard=None
):
    """Durably accept exactly the in-flight saved report, then remove its outbox.

    The optional trusted internal guard runs exactly once under the durable lock,
    after full authority/report/response validation and before any mutation (even
    an idempotent receipt fsync). Raising aborts without writes. Returning admits
    this exact historical acknowledgment: later cancellation does not roll back
    its transaction. Never accept a guard from user-controlled input.
    """
    try:
        with _authority(credentials, store_dir, credential_file) as (directory, current, binding):
            expected = _report(report, current)
            ack = _ack(response, expected)
            outbox, raw = _record(directory, _OUTBOX, current, binding)
            accepted, _ = _record(directory, _ACCEPTED, current, binding)
            receipt = dict(binding, report=expected, ack=ack)
            reuse_accepted = accepted is not None and _same(accepted, receipt)
            if outbox is None:
                if not reuse_accepted:
                    raise EnrollmentError("Missing exact report acknowledgment authority")
            elif not _same(outbox["report"], expected):
                raise EnrollmentError("Stale in-flight report")
            # ACK COMMIT ADMISSION: all authority and exact-input checks precede
            # this fence, including lock waits and crypto. Nothing durable has
            # changed yet. Once admitted, finish this historical transaction.
            if commit_guard is not None:
                commit_guard()
            if outbox is not None:
                if not reuse_accepted:
                    _publish(directory, _ACCEPTED, dict(outbox, ack=ack), current, binding)
                else:
                    _fsync(directory)
                    checked, _ = _record(directory, _ACCEPTED, current, binding)
                    if checked is None or not _same(checked, receipt):
                        raise EnrollmentError("Accepted report readback mismatch")
                checked, reread = _record(directory, _OUTBOX, current, binding)
                if checked is None or reread != raw or not _same(checked, outbox):
                    raise EnrollmentError("Outbox changed before removal")
                _unlink(_OUTBOX, dir_fd=directory)
            _fsync(directory)
            checked, _ = _record(directory, _ACCEPTED, current, binding)
            if checked is None or not _same(checked, receipt):
                raise EnrollmentError("Accepted report final readback mismatch")
            return ack
    except Exception:  # noqa: BLE001 - Expose only a safe public error, never private failure details.
        raise EnrollmentError(
            "Unable to acknowledge durable public Glass certificate report"
        ) from None
