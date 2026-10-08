"""Inactive offline CSR preparation, candidate validation and bundle installation.

One runtime UID is trusted. Existing state is never repaired or regenerated;
explicit future recovery is required for a different enrollment generation.
No handler activation, transport, acknowledgment or request retirement here.
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
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
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


def _write_staged(directory_fd, name, data, *, on_create=None):
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd
    )
    try:
        if on_create is not None:
            on_create()  # Record ownership only after exclusive creation succeeded.
        stream = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
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


_RENEWAL_FIELDS = {
    "device_id",
    "request_id",
    "client_cert",
    "ca_cert",
    "cert_serial",
    "expires_at",
    "fingerprint_sha256",
    "state",
}


def _renewal_response(response):
    from datetime import datetime

    if not isinstance(response, dict) or set(response) != _RENEWAL_FIELDS:
        raise EnrollmentError("Invalid renewal response fields")
    value = dict(response)
    if any(type(item) is not str for item in value.values()):
        raise EnrollmentError("Invalid renewal response types")
    # Bound individual scalars before serializing or parsing untrusted material.
    if len(value["device_id"]) != 36 or len(value["request_id"]) != 36:
        raise EnrollmentError("Invalid renewal identity")
    if value["state"] != "issued":
        raise EnrollmentError("Renewal certificate is not issued")
    if not re.fullmatch(r"[0-9a-f]{1,40}", value["cert_serial"]) or not int(
        value["cert_serial"], 16
    ):
        raise EnrollmentError("Invalid renewal serial")
    if not re.fullmatch(r"[0-9a-f]{64}", value["fingerprint_sha256"]):
        raise EnrollmentError("Invalid renewal fingerprint")
    for field in ("client_cert", "ca_cert"):
        if not 1 <= len(value[field]) <= 14000:
            raise EnrollmentError("Invalid renewal certificate size")
        value[field].encode("ascii")
    if not 1 <= len(value["expires_at"]) <= 64:
        raise EnrollmentError("Invalid renewal expiry size")
    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry.utcoffset() is None:
        raise EnrollmentError("Renewal expiry must be timezone aware")
    if len(json.dumps(value, separators=(",", ":")).encode("utf-8")) > 65536:
        raise EnrollmentError("Renewal response too large")
    return value


def _single_certificate(pem):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    raw = pem.encode("ascii")
    certificate = x509.load_pem_x509_certificate(raw)
    # PEM parsers can accept extra certificates, prefixes and trailing garbage.
    if certificate.public_bytes(serialization.Encoding.PEM) != raw:
        raise EnrollmentError("Invalid renewal certificate encoding")
    return certificate


def _build_renewal_candidate(current, value, state):
    """Pure c2 certificate builder; filesystem callers hold the rotation lock."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    if any(value[field] != state[field] for field in ("device_id", "request_id")):
        raise EnrollmentError("Renewal pending identity mismatch")
    leaf = _single_certificate(value["client_cert"])
    ca = _single_certificate(value["ca_cert"])
    pinned_ca = x509.load_pem_x509_certificate(current["ca_cert"].encode("ascii"))
    if ca.public_bytes(serialization.Encoding.DER) != pinned_ca.public_bytes(
        serialization.Encoding.DER
    ):
        raise EnrollmentError("Renewal issuing CA mismatch")
    candidate = {
        "base_url": current["base_url"],
        "device_id": current["device_id"],
        "pubkey": current["pubkey"],
        "operational_token": current["operational_token"],
        "private_key": state["private_key"],
        "client_cert": value["client_cert"],
        "ca_cert": value["ca_cert"],
        "cert_serial": value["cert_serial"],
        "expires_at": value["expires_at"],
        "rotation_request_id": state["request_id"],
        "fingerprint_sha256": value["fingerprint_sha256"],
    }
    _validate_certificate(candidate)
    if leaf.fingerprint(hashes.SHA256()).hex() != value["fingerprint_sha256"]:
        raise EnrollmentError("Renewal leaf fingerprint mismatch")
    return candidate


def validate_renewal_candidate(credentials, response, *, store_dir):
    """Return a secret-bearing replacement bundle, without installing it.

    Only an existing private pending request under its existing fixed lock is
    authoritative. No state creation, network, deletion, activation or writes;
    the current enrollment must still be valid (no expired-current recovery).
    The issuing CA is pinned by DER; returned CA material is never HTTPS trust.
    """
    store_fd = directory_fd = lock_fd = None
    try:
        if not isinstance(credentials, dict):
            raise EnrollmentError("Invalid enrollment bundle")
        current = dict(credentials)
        context = _context(current)
        value = _renewal_response(response)
        store_fd = m._open_directory(store_dir)
        directory_fd = os.open("rotation-state", m._DIR_FLAGS, dir_fd=store_fd)
        _check_private(directory_fd, directory=True)
        lock_fd = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        _check_private(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _check_private(directory_fd, directory=True)
        _check_private(lock_fd)
        state = _read_pending(directory_fd, context)
        if state is None:
            raise EnrollmentError("Missing pending renewal request")
        return _build_renewal_candidate(current, value, state)
    except Exception:  # noqa: BLE001 - never expose credential-bearing library errors
        raise EnrollmentError("Unable to validate private Glass renewal candidate") from None
    finally:
        cleanup_failed = False
        for fd in (lock_fd, directory_fd, store_fd):
            if fd is not None:
                try:
                    os.close(fd)  # Closing the fixed lock releases flock.
                except Exception:  # noqa: BLE001 - still close the other descriptors
                    cleanup_failed = True
        if cleanup_failed:
            raise EnrollmentError("Unable to clean private Glass renewal validation") from None


_BUNDLE_LIMIT = 65536
_JOURNAL_LIMIT = 131072
_INSTALL_FIELDS = {
    "version",
    "base_url",
    "device_id",
    "generation_sha256",
    "request_id",
    "credential_file",
    "previous_bundle",
    "previous_sha256",
    "candidate_sha256",
}


def _canonical_json(value, limit):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > limit:
        raise EnrollmentError("Private rotation record too large")
    return data


def _bundle_digest(bundle):
    return hashlib.sha256(_canonical_json(bundle, _BUNDLE_LIMIT)).hexdigest()


def _same_bundle(left, right):
    # Python dict equality equates True with 1; full JSON identity must not.
    return _canonical_json(left, _BUNDLE_LIMIT) == _canonical_json(right, _BUNDLE_LIMIT)


def _read_private_json(directory_fd, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        _check_private(stream.fileno())
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise EnrollmentError("Private rotation record too large")
    value = json.loads(data, object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict):
        raise EnrollmentError("Invalid private rotation record")
    return value, data


def _validate_install_journal(journal, context, state, path):
    if not isinstance(journal, dict) or set(journal) != _INSTALL_FIELDS:
        raise EnrollmentError("Invalid installation journal fields")
    if type(journal["version"]) is not int or journal["version"] != 1:
        raise EnrollmentError("Invalid installation journal version")
    if any(
        type(journal[field]) is not str
        for field in _INSTALL_FIELDS - {"version", "previous_bundle"}
    ):
        raise EnrollmentError("Invalid installation journal types")
    if any(journal[field] != context[field] for field in context):
        raise EnrollmentError("Installation journal context mismatch")
    if journal["request_id"] != state["request_id"] or journal["credential_file"] != path:
        raise EnrollmentError("Installation journal binding mismatch")
    for field in ("previous_sha256", "candidate_sha256", "generation_sha256"):
        if not re.fullmatch("[0-9a-f]{64}", journal[field]):
            raise EnrollmentError("Invalid installation journal digest")
    previous = journal["previous_bundle"]
    if _context(previous) != context or _bundle_digest(previous) != journal["previous_sha256"]:
        raise EnrollmentError("Installation journal backup mismatch")
    _canonical_json(journal, _JOURNAL_LIMIT)
    return previous


def _stage_install(directory_fd, data, stages):
    name = ".stage-" + secrets.token_hex(16)
    _write_staged(directory_fd, name, data, on_create=lambda: stages.append((directory_fd, name)))
    return name


def install_renewal_candidate(credentials, response, *, store_dir, credential_file):
    """Install an inactive offline bundle and return a public durability receipt.

    The explicit existing filename is trusted internal caller authority, never
    HTTP passthrough. Retains one bounded secret backup journal and pending CSR;
    no MQTT activation, acknowledgment, retirement, network or expired recovery.
    """
    store_fd = directory_fd = lock_fd = parent_fd = None
    stages = []
    try:
        # Preserve the absolute lexical filename as the journal authority binding.
        path = os.fspath(credential_file)
        if not isinstance(path, str) or not os.path.isabs(path) or ".." in path.split("/"):
            raise EnrollmentError("Invalid installation filename")
        parent, name = os.path.split(path)
        if (
            not name
            or name in {".lock", "pending.json", "install.json"}
            or name.startswith(".stage-")
        ):
            raise EnrollmentError("Reserved installation filename")
        store_fd = m._open_directory(store_dir)
        directory_fd = os.open("rotation-state", m._DIR_FLAGS, dir_fd=store_fd)
        _check_private(directory_fd, directory=True)
        lock_fd = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        _check_private(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _check_private(directory_fd, directory=True)
        _check_private(lock_fd)
        # All candidate/current/pending/journal crypto checks share this lock.
        context = _context(credentials)
        caller = dict(credentials)
        _canonical_json(caller, _BUNDLE_LIMIT)
        value = _renewal_response(response)
        state = _read_pending(directory_fd, context)
        if state is None:
            raise EnrollmentError("Missing pending renewal request")
        parent_fd = m._open_directory(parent)
        parent_info, state_info = os.fstat(parent_fd), os.fstat(directory_fd)
        if (parent_info.st_dev, parent_info.st_ino) == (state_info.st_dev, state_info.st_ino):
            raise EnrollmentError("Installation target cannot be rotation state")
        current, snapshot = _read_private_json(parent_fd, name, _BUNDLE_LIMIT)
        if _context(current) != context:
            raise EnrollmentError("Current installation context mismatch")
        try:
            journal, _ = _read_private_json(directory_fd, "install.json", _JOURNAL_LIMIT)
        except FileNotFoundError:
            journal = None
        if journal is None:
            if not _same_bundle(current, caller):
                raise EnrollmentError("Current installation bundle mismatch")
            previous = current
        else:
            previous = _validate_install_journal(journal, context, state, path)
        candidate = _build_renewal_candidate(previous, value, state)
        candidate_data = _canonical_json(candidate, _BUNDLE_LIMIT)
        candidate_digest = _bundle_digest(candidate)
        if journal is not None:
            if journal["candidate_sha256"] != candidate_digest:
                raise EnrollmentError("Installation candidate digest mismatch")
            accepted = {_bundle_digest(previous), candidate_digest}
            if _bundle_digest(caller) not in accepted or _bundle_digest(current) not in accepted:
                raise EnrollmentError("Foreign installation bundle")
        else:
            journal = dict(
                context,
                version=1,
                request_id=state["request_id"],
                credential_file=path,
                previous_bundle=previous,
                previous_sha256=_bundle_digest(previous),
                candidate_sha256=candidate_digest,
            )
            _validate_install_journal(journal, context, state, path)
            staged = _stage_install(directory_fd, _canonical_json(journal, _JOURNAL_LIMIT), stages)
            _replace(staged, "install.json", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            stages.remove((directory_fd, staged))  # Never rollback published state.
        # Also resolves a previous postpublication directory-fsync uncertainty.
        _fsync(directory_fd)
        verified, _ = _read_private_json(directory_fd, "install.json", _JOURNAL_LIMIT)
        _validate_install_journal(verified, context, state, path)
        if _canonical_json(verified, _JOURNAL_LIMIT) != _canonical_json(journal, _JOURNAL_LIMIT):
            raise EnrollmentError("Installation journal readback mismatch")
        if not _same_bundle(current, candidate):
            staged = _stage_install(parent_fd, candidate_data, stages)
            checked, _ = _read_private_json(parent_fd, staged, _BUNDLE_LIMIT)
            if _context(checked) != context or not _same_bundle(checked, candidate):
                raise EnrollmentError("Staged installation readback mismatch")
            # Cooperating-writer guard, not a merge promise for administrators.
            reread, raw = _read_private_json(parent_fd, name, _BUNDLE_LIMIT)
            if not _same_bundle(reread, current) or raw != snapshot:
                raise EnrollmentError("Current installation changed during staging")
            _replace(staged, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            stages.remove((parent_fd, staged))
        # Candidate retries are durable read-only retries, never another rewrite.
        _fsync(parent_fd)
        installed, _ = _read_private_json(parent_fd, name, _BUNDLE_LIMIT)
        if _context(installed) != context or not _same_bundle(installed, candidate):
            raise EnrollmentError("Installed bundle readback mismatch")
        return {
            "device_id": state["device_id"],
            "request_id": state["request_id"],
            "cert_serial": candidate["cert_serial"],
            "fingerprint_sha256": candidate["fingerprint_sha256"],
            "expires_at": candidate["expires_at"],
            "state": "bundle_installed",
        }
    except Exception:  # noqa: BLE001 - suppress all secret-bearing library errors
        raise EnrollmentError("Unable to install durable private Glass renewal bundle") from None
    finally:
        cleanup_failed = False
        for fd, name in stages:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
            except Exception:  # noqa: BLE001 - release every descriptor regardless
                cleanup_failed = True
        for fd in (parent_fd, lock_fd, directory_fd, store_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:  # noqa: BLE001 - never leak secret-bearing errors
                    cleanup_failed = True
        if cleanup_failed:
            raise EnrollmentError("Unable to clean private Glass renewal installation") from None
