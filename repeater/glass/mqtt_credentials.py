"""Validate node-owned enrollment material and publish immutable private TLS files.

No rotation API, HTTPS trust changes, or MQTT installation acknowledgement here.
The caller activates returned filenames and waits for a successful connection.
"""

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from repeater.glass.enrollment import EnrollmentError, _validate_certificate, load_credentials

_FILES = {"ca_cert": "ca.pem", "client_cert": "client.pem", "private_key": "client.key"}
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_fsync = os.fsync
_rename = os.rename


@dataclass(frozen=True)
class MqttCredentials:
    ca_cert_path: str
    client_cert_path: str
    client_key_path: str
    fingerprint: str
    cert_serial: str
    expires_at: str


def _check_private(fd, *, directory=False):
    info = os.fstat(fd)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise EnrollmentError("MQTT credentials require private modes")
    if info.st_uid not in (0, os.geteuid()):
        raise EnrollmentError("MQTT credentials require trusted ownership")
    if any(name.startswith("system.posix_acl_") for name in os.listxattr(fd)):
        raise EnrollmentError("MQTT credential ACLs are forbidden")


def _check_ancestor(fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
        raise EnrollmentError("MQTT ancestry requires trusted ownership")
    # Conservative even for masked named writers: do not trust access ACLs.
    # Default ACLs do not grant access to this directory; newly created private
    # children have their inherited ACLs removed before publication.
    if "system.posix_acl_access" in os.listxattr(fd):
        raise EnrollmentError("MQTT ancestry access ACLs are forbidden")
    if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise EnrollmentError("MQTT ancestry must not be writable by other users")
    # A root/runtime-owned sticky directory protects our root/runtime-owned
    # next component from unlink/rename by other writers (e.g. /tmp).


def _open_directory(path):
    # Do not resolve first: symlinks and symlink/.. spellings must not disappear.
    if ".." in Path(path).parts:
        raise EnrollmentError("MQTT ancestry cannot contain parent traversal")
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, _DIR_FLAGS)
    try:
        _check_ancestor(fd)
        for part in path.parts[1:]:
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            _check_ancestor(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _strip_acls(fd):
    for name in os.listxattr(fd):
        if name.startswith("system.posix_acl_"):
            os.removexattr(fd, name)


def _write_private(directory_fd, name, value):
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd
    )
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        _strip_acls(stream.fileno())
        _check_private(stream.fileno())
        stream.write(value.encode("utf-8"))
        stream.flush()
        _fsync(stream.fileno())


def _readback(directory_fd, bundle):
    _check_private(directory_fd, directory=True)
    if set(os.listdir(directory_fd)) != set(_FILES.values()):
        raise EnrollmentError("Incomplete MQTT credential directory")
    verified = dict(bundle)
    for field, name in _FILES.items():
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(fd, "rb") as stream:
            _check_private(stream.fileno())
            data = stream.read(65537)
        if len(data) > 65536 or data != bundle[field].encode("utf-8"):
            raise EnrollmentError("MQTT credential readback mismatch")
        verified[field] = data.decode("utf-8")
    _validate_certificate(verified)


def materialize_credentials(credential_file, *, base_url, device_id, store_dir):
    """Return validated TLS paths only after full readback + atomic directory rename.

    The provisioned store directory must already exist. Its mqtt-credentials
    child and fingerprint directories are private, owned and ACL-free. Existing
    fingerprint directories are verified, never repaired or overwritten. Failed
    staging leaves every previously published directory untouched.
    """
    root_fd = store_fd = staged_fd = None
    staged = None
    try:
        bundle = load_credentials(credential_file, base_url=base_url, device_id=device_id)
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_pem_x509_certificate(bundle["client_cert"].encode())
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        root_path = Path(os.path.abspath(store_dir)) / "mqtt-credentials"
        store_fd = _open_directory(store_dir)
        try:
            os.mkdir("mqtt-credentials", 0o700, dir_fd=store_fd)
            created = True
        except FileExistsError:
            created = False
        root_fd = os.open("mqtt-credentials", _DIR_FLAGS, dir_fd=store_fd)
        if created:
            os.fchmod(root_fd, 0o700)
            _strip_acls(root_fd)
            _fsync(root_fd)
            _fsync(store_fd)
        _check_private(root_fd, directory=True)
        try:
            existing_fd = os.open(fingerprint, _DIR_FLAGS, dir_fd=root_fd)
        except FileNotFoundError:
            existing_fd = None
        if existing_fd is not None:
            try:
                _readback(existing_fd, bundle)
            finally:
                os.close(existing_fd)
        else:
            staged = ".stage-" + secrets.token_hex(16)
            os.mkdir(staged, 0o700, dir_fd=root_fd)
            staged_fd = os.open(staged, _DIR_FLAGS, dir_fd=root_fd)
            os.fchmod(staged_fd, 0o700)
            _strip_acls(staged_fd)
            for field, name in _FILES.items():
                _write_private(staged_fd, name, bundle[field])
            _readback(staged_fd, bundle)
            _fsync(staged_fd)
            _rename(staged, fingerprint, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            staged = None
            _fsync(root_fd)
        directory = root_path / fingerprint
        return MqttCredentials(
            ca_cert_path=str(directory / _FILES["ca_cert"]),
            client_cert_path=str(directory / _FILES["client_cert"]),
            client_key_path=str(directory / _FILES["private_key"]),
            fingerprint=fingerprint,
            cert_serial=format(cert.serial_number, "x"),
            expires_at=cert.not_valid_after_utc.isoformat(),
        )
    except Exception:  # noqa: BLE001 - suppress credential-bearing library errors
        raise EnrollmentError("Unable to materialize verified private MQTT credentials") from None
    finally:
        if staged is not None and staged_fd is not None:
            for name in os.listdir(staged_fd):
                os.unlink(name, dir_fd=staged_fd)
            os.rmdir(staged, dir_fd=root_fd)
        for fd in (staged_fd, root_fd, store_fd):
            if fd is not None:
                os.close(fd)
