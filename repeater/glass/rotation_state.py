"""Inactive, offline durable pending CSR preparation (not certificate rotation).

One runtime UID is trusted. Existing state is never repaired or regenerated;
explicit future recovery is required for a different enrollment generation.
"""

import fcntl
import hashlib
import json
import os
import re
import secrets
import uuid

from repeater.glass import mqtt_credentials as m
from repeater.glass.enrollment import (
    EnrollmentError,
    _device_id,
    _secret,
    _validate_certificate,
    validate_https_url,
)

_LIMIT = 32768
_FIELDS = {
    "version",
    "base_url",
    "device_id",
    "generation_sha256",
    "request_id",
    "private_key",
    "csr_pem",
}
_fsync = os.fsync
_replace = os.replace


def _check_private(fd, *, directory=False):
    m._check_private(fd, directory=directory)
    if os.fstat(fd).st_uid != os.geteuid():
        raise EnrollmentError("Rotation state requires runtime ownership")


def _context(credentials):
    # Validate the already-loaded bundle before any filesystem operation. This
    # intentionally rejects expired leaves; there is no implicit recovery loader.
    if not isinstance(credentials, dict):
        raise EnrollmentError("Invalid enrollment bundle")
    bundle = dict(credentials)
    _device_id(bundle["device_id"])
    if not isinstance(bundle["base_url"], str):
        raise EnrollmentError("Invalid enrollment origin")
    origin = validate_https_url(bundle["base_url"])
    if origin != bundle["base_url"]:
        raise EnrollmentError("Noncanonical enrollment origin")
    _secret(bundle["operational_token"])
    _validate_certificate(bundle)
    return {
        "base_url": origin,
        "device_id": bundle["device_id"],
        "generation_sha256": hashlib.sha256(
            bundle["operational_token"].encode("ascii")
        ).hexdigest(),
    }


def _validate_pending(value, context):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise EnrollmentError("Invalid pending CSR fields")
    if type(value["version"]) is not int or value["version"] != 1:
        raise EnrollmentError("Invalid pending CSR version")
    if any(type(value[field]) is not str for field in _FIELDS - {"version"}):
        raise EnrollmentError("Invalid pending CSR types")
    if not re.fullmatch("[0-9a-f]{64}", value["generation_sha256"]):
        raise EnrollmentError("Invalid pending generation")
    if any(value[field] != context[field] for field in context):
        raise EnrollmentError("Pending CSR enrollment mismatch")
    _device_id(value["device_id"])
    if str(uuid.UUID(value["request_id"])) != value["request_id"]:
        raise EnrollmentError("Invalid pending request identity")
    key_pem = value["private_key"].encode("ascii")
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise EnrollmentError("Invalid pending private key")
    # Require a single canonical PKCS8 PEM, not a parser-tolerated suffix or
    # legacy PKCS1 encoding. Likewise reject trailing CSR material.
    if (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        != key_pem
    ):
        raise EnrollmentError("Invalid pending key encoding")
    csr_pem = value["csr_pem"].encode("ascii")
    csr = x509.load_pem_x509_csr(csr_pem)
    if csr.public_bytes(serialization.Encoding.PEM) != csr_pem:
        raise EnrollmentError("Invalid pending CSR encoding")
    if not csr.is_signature_valid or not isinstance(csr.signature_hash_algorithm, hashes.SHA256):
        raise EnrollmentError("Invalid pending CSR signature")
    if csr.subject != x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "device:" + value["device_id"])]
    ):
        raise EnrollmentError("Invalid pending CSR identity")

    def public_bytes(public):
        return public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    if public_bytes(key.public_key()) != public_bytes(csr.public_key()):
        raise EnrollmentError("Pending CSR key mismatch")
    return value


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EnrollmentError("Duplicate pending CSR fields")
        result[key] = value
    return result


def _read_pending(directory_fd, context):
    try:
        fd = os.open(
            "pending.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
        )
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        _check_private(stream.fileno())
        data = stream.read(_LIMIT + 1)
    if len(data) > _LIMIT:
        raise EnrollmentError("Pending CSR too large")
    return _validate_pending(json.loads(data, object_pairs_hook=_unique_pairs), context)


def _new_pending(context):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device:" + context["device_id"])])
        )
        .sign(key, hashes.SHA256())
    )
    return dict(
        context,
        version=1,
        request_id=str(uuid.uuid4()),
        private_key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def _write_staged(directory_fd, name, data):
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd
    )
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        m._strip_acls(stream.fileno())
        _check_private(stream.fileno())
        if stream.write(data) != len(data):
            raise EnrollmentError("Incomplete pending CSR write")
        stream.flush()
        _fsync(stream.fileno())


def prepare_rotation(credentials, *, store_dir):
    """Return only device_id/request_id/csr_pem after durable private readback.

    The provisioned store must exist with mqtt_credentials' strict ancestry.
    State binds to exact origin, immutable device ID and SHA256 ASCII token,
    not certificate serial. Retrying reuses the exact persisted request/key.
    No network, credential installation, report, handler or MQTT activation.
    """
    store_fd = directory_fd = lock_fd = None
    staged = None
    try:
        context = _context(credentials)
        store_fd = m._open_directory(store_dir)
        try:
            os.mkdir("rotation-state", 0o700, dir_fd=store_fd)
            created = True
        except FileExistsError:
            created = False
        directory_fd = os.open("rotation-state", m._DIR_FLAGS, dir_fd=store_fd)
        if created:
            os.fchmod(directory_fd, 0o700)
            m._strip_acls(directory_fd)
        _check_private(directory_fd, directory=True)
        # O_NONBLOCK avoids waiting forever on a preexisting FIFO. Never unlink
        # the fixed lock inode: flock must serialize both threads and processes.
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            lock_fd = os.open(".lock", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
            new_lock = True
        except FileExistsError:
            lock_fd = os.open(".lock", flags, dir_fd=directory_fd)
            new_lock = False
        if new_lock:
            os.fchmod(lock_fd, 0o600)
            m._strip_acls(lock_fd)
        _check_private(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _check_private(directory_fd, directory=True)
        _check_private(lock_fd)
        _fsync(lock_fd)
        _fsync(store_fd)
        state = _read_pending(directory_fd, context)
        if state is None:
            state = _validate_pending(_new_pending(context), context)
            data = json.dumps(state, separators=(",", ":")).encode("utf-8")
            if len(data) > _LIMIT:
                raise EnrollmentError("Pending CSR too large")
            staged = ".stage-" + secrets.token_hex(16)
            _write_staged(directory_fd, staged, data)
            _replace(staged, "pending.json", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            staged = None  # Never fake rollback after publication.
            _fsync(directory_fd)
            verified = _read_pending(directory_fd, context)
            if verified != state:
                raise EnrollmentError("Pending CSR readback mismatch")
            if verified is None:
                raise EnrollmentError("Pending CSR disappeared during readback")
            state = verified
        else:
            # A retry after a post-replace fsync failure must reuse and make the
            # published entry durable, not generate another key.
            _fsync(directory_fd)
        return {field: state[field] for field in ("device_id", "request_id", "csr_pem")}
    except Exception:  # noqa: BLE001 - never expose credential-bearing library errors
        raise EnrollmentError("Unable to prepare durable private Glass rotation request") from None
    finally:
        try:
            if staged is not None and directory_fd is not None:
                try:
                    os.unlink(staged, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        except Exception:  # noqa: BLE001 - cleanup errors must also be sanitized
            raise EnrollmentError("Unable to clean private Glass rotation staging") from None
        finally:
            for fd in (lock_fd, directory_fd, store_fd):
                if fd is not None:
                    os.close(fd)
