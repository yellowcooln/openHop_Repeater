"""Explicit administrator-initiated enrollment. Never invoked by discovery.

TLS trust must already be provisioned (system roots or an explicit HTTPS CA
file). Returned device CA is certificate metadata, NOT new HTTPS trust.
All credentials share one atomic private bundle; no enrollment token survives.
The returned non-secret settings must be persisted by the administrator through
ConfigManager before the handler uses this bundle. HTTP authentication is bearer,
not mTLS; MQTT certificate activation and rotation are separate workflows.
"""

import json
import math
import os
import re
import secrets
import ssl
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib import request
from urllib.parse import urlsplit


class EnrollmentError(ValueError):
    """Safe error text: never includes a response body or credential."""


def validate_https_url(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EnrollmentError("Verified HTTPS endpoint required")
    return url.rstrip("/")


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EnrollmentError("Glass redirects are forbidden")


def post_verified_json(
    url, payload, *, timeout=10, https_ca_file=None, token=None, max_request=16384
):
    """Bounded HTTPS without redirects or credential-bearing error messages."""
    validate_https_url(url)
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise EnrollmentError("Timeout must be between zero and 60 seconds")
    body = json.dumps(payload, separators=(",", ":")).encode()
    if len(body) > max_request:
        raise EnrollmentError("Glass request too large")
    try:
        context = ssl.create_default_context(cafile=https_ca_file)
        headers = {"Content-Type": "application/json", "User-Agent": "openHop-Repeater/enrollment"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = request.Request(url, data=body, headers=headers, method="POST")
        opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())
        with opener.open(req, timeout=timeout) as response:
            data = response.read(65537)
        if len(data) > 65536:
            raise EnrollmentError("Glass response too large")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise EnrollmentError("Invalid Glass response")
        return result
    except Exception:  # noqa: BLE001 - never expose credential-bearing library errors
        raise EnrollmentError("Verified Glass request failed") from None


def _device_id(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
    ):
        raise EnrollmentError("Invalid stable device identity")


def _secret(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", value):
        raise EnrollmentError("Invalid device secret")


def _validate_certificate(bundle):
    # Lazy imports preserve observation-only mode in old installations.
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = serialization.load_pem_private_key(bundle["private_key"].encode(), password=None)
    cert = x509.load_pem_x509_certificate(bundle["client_cert"].encode())
    ca = x509.load_pem_x509_certificate(bundle["ca_cert"].encode())
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise EnrollmentError("Invalid node private key")

    def public_bytes(public_key):
        return public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    if public_bytes(key.public_key()) != public_bytes(cert.public_key()):
        raise EnrollmentError("Issued certificate key mismatch")
    now = datetime.now(timezone.utc)
    for item in (ca, cert):
        if not item.not_valid_before_utc <= now < item.not_valid_after_utc:
            raise EnrollmentError("Certificate outside validity period")
    device_id = bundle["device_id"]
    if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) != [
        x509.NameAttribute(NameOID.COMMON_NAME, "device:" + device_id)
    ]:
        raise EnrollmentError("Issued certificate identity mismatch")
    if cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier) != [
        "urn:openhop:device:" + device_id
    ]:
        raise EnrollmentError("Issued certificate SAN mismatch")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise EnrollmentError("Device certificate must not be a CA")
    if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise EnrollmentError("Invalid issuing CA")
    if (
        ExtendedKeyUsageOID.CLIENT_AUTH
        not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    ):
        raise EnrollmentError("Device certificate lacks client authentication")
    if cert.issuer != ca.subject:
        raise EnrollmentError("Certificate issuer mismatch")
    ca_key = ca.public_key()
    if isinstance(ca_key, rsa.RSAPublicKey):
        ca_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
            cert.signature_hash_algorithm,
        )
    elif isinstance(ca_key, ec.EllipticCurvePublicKey):
        ca_key.verify(
            cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
        )
    else:
        raise EnrollmentError("Unsupported issuing CA key")
    expiry = datetime.fromisoformat(bundle["expires_at"].replace("Z", "+00:00"))
    if expiry != cert.not_valid_after_utc or bundle["cert_serial"] != format(
        cert.serial_number, "x"
    ):
        raise EnrollmentError("Certificate metadata mismatch")


def _save_bundle(path, bundle):
    path = Path(path)
    # Admin provisions parent directory; never create surprising storage paths.
    staged = None
    try:
        fd, staged = tempfile.mkstemp(prefix=".glass-credentials-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            # Directory default ACLs must not grant named users access.
            for attribute in os.listxattr(stream.fileno()):
                os.removexattr(stream.fileno(), attribute)
            json.dump(bundle, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
        staged = None
    except Exception:  # noqa: BLE001 - never expose credential-bearing library errors
        raise EnrollmentError("Unable to persist private Glass credentials") from None
    finally:
        if staged is not None:
            os.unlink(staged)


def load_credentials(path, *, base_url, device_id):
    """Fail closed on stale, wrong-origin, invalid, or non-private credentials."""
    _device_id(device_id)
    base_url = validate_https_url(base_url)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
            ):
                raise EnrollmentError("Credential file must be owned by runtime user and mode 0600")
            if "system.posix_acl_access" in os.listxattr(stream.fileno()):
                raise EnrollmentError("Credential ACL is not permitted")
            data = stream.read(65537)
        if len(data) > 65536:
            raise EnrollmentError("Credential file too large")
        bundle = json.loads(data)
        if bundle["device_id"] != device_id or bundle["base_url"] != base_url:
            raise EnrollmentError("Credential identity or endpoint mismatch")
        _secret(bundle["operational_token"])
        _validate_certificate(bundle)
        return bundle
    except Exception:  # noqa: BLE001 - never expose credential-bearing library errors
        raise EnrollmentError("Invalid or inaccessible private Glass credentials") from None


def enroll_device(
    *,
    base_url,
    device_id,
    node_name,
    pubkey,
    enrollment_token,
    credential_file,
    https_ca_file=None,
    timeout=10,
):
    """Explicit opt-in helper. Returns only non-secret ConfigManager settings.

    No retries: a lost response requires fresh administrator approval. No handler
    config mutation occurs on network/validation/persistence failure.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    base_url = validate_https_url(base_url)
    _device_id(device_id)
    _secret(enrollment_token)
    if not isinstance(node_name, str) or not 1 <= len(node_name) <= 128:
        raise EnrollmentError("Invalid node name")
    if not isinstance(pubkey, str) or not 1 <= len(pubkey) <= 130:
        raise EnrollmentError("Invalid approved public identity")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device:" + device_id)]))
        .sign(key, hashes.SHA256())
    )
    operational_token = secrets.token_urlsafe(32)
    response = post_verified_json(
        base_url + "/enroll",
        {
            "device_id": device_id,
            "node_name": node_name,
            "pubkey": pubkey,
            "enrollment_token": enrollment_token,
            "operational_token": operational_token,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        },
        https_ca_file=https_ca_file,
        timeout=timeout,
    )
    try:
        if set(response) != {"device_id", "client_cert", "ca_cert", "cert_serial", "expires_at"}:
            raise EnrollmentError("Unexpected enrollment response fields")
        if response["device_id"] != device_id:
            raise EnrollmentError("Enrollment identity mismatch")
        bundle = dict(
            response,
            base_url=base_url,
            operational_token=operational_token,
            pubkey=pubkey,
            private_key=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        )
        _validate_certificate(bundle)
    except Exception:  # noqa: BLE001 - never expose credential-bearing library errors
        raise EnrollmentError("Invalid issued device certificate") from None
    _save_bundle(credential_file, bundle)
    return {"device_id": device_id, "operational_credential_file": str(credential_file)}
