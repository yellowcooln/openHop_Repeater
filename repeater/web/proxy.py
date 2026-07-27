from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class ProxyConfigError(ValueError):
    """Raised when the trusted reverse-proxy configuration is invalid."""


@dataclass(frozen=True)
class ProxyRequestContext:
    client_ip: str
    scheme: str
    host: str
    origin: str
    forwarded: bool


class TrustedProxyPolicy:
    """Resolve client and origin metadata without trusting arbitrary peers."""

    def __init__(
        self,
        *,
        trusted_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (),
        external_url: str | None = None,
        redirect_to_https: bool = False,
    ) -> None:
        self.trusted_networks = trusted_networks
        self.external_url = external_url
        self.redirect_to_https = redirect_to_https

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> TrustedProxyPolicy:
        http = config.get("http", {}) if isinstance(config, dict) else {}
        if not isinstance(http, dict):
            raise ProxyConfigError("http must be a mapping")

        raw_proxies = http.get("trusted_proxies", [])
        if not isinstance(raw_proxies, list):
            raise ProxyConfigError("http.trusted_proxies must be a list of IP addresses or CIDRs")
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for value in raw_proxies:
            if not isinstance(value, str) or not value.strip():
                raise ProxyConfigError("http.trusted_proxies entries must be IP addresses or CIDRs")
            try:
                networks.append(ipaddress.ip_network(value.strip(), strict=True))
            except ValueError as exc:
                raise ProxyConfigError(
                    "http.trusted_proxies entries must be valid IP addresses or CIDRs"
                ) from exc

        external_url = None
        raw_external_url = http.get("external_url")
        if raw_external_url not in (None, ""):
            if not isinstance(raw_external_url, str):
                raise ProxyConfigError("http.external_url must be a string URL")
            external_url = normalize_external_url(raw_external_url, name="http.external_url")

        raw_redirect = http.get("redirect_to_https", False)
        if not isinstance(raw_redirect, bool):
            raise ProxyConfigError("http.redirect_to_https must be true or false")
        if raw_redirect and not external_url:
            raise ProxyConfigError("http.redirect_to_https requires http.external_url")
        if (
            raw_redirect
            and external_url is not None
            and not external_url.startswith("https://")
        ):
            raise ProxyConfigError("http.redirect_to_https requires an HTTPS http.external_url")

        return cls(
            trusted_networks=tuple(networks),
            external_url=external_url,
            redirect_to_https=raw_redirect,
        )

    def is_trusted(self, address: str) -> bool:
        normalized = _normalize_ip(address)
        if normalized is None:
            return False
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:
            return False
        return any(parsed.version == network.version and parsed in network for network in self.trusted_networks)

    def resolve_request(
        self,
        *,
        remote_ip: str,
        headers: Mapping[str, str],
        direct_scheme: str,
        direct_host: str,
    ) -> ProxyRequestContext:
        remote = _normalize_ip(remote_ip) or "unknown"
        scheme = direct_scheme.lower() if direct_scheme.lower() in {"http", "https"} else "http"
        host = _normalize_host(direct_host) or "localhost"
        forwarded = False

        if self.is_trusted(remote):
            xff = _header(headers, "X-Forwarded-For")
            client_ip, valid_chain, boundary_index, chain_length = self._resolve_client_ip(
                remote, xff
            )
            if valid_chain:
                proto = _aligned_forwarded_value(
                    _header(headers, "X-Forwarded-Proto"),
                    boundary_index=boundary_index,
                    chain_length=chain_length,
                ).lower()
                forwarded_host = _aligned_forwarded_value(
                    _header(headers, "X-Forwarded-Host"),
                    boundary_index=boundary_index,
                    chain_length=chain_length,
                )
                if proto in {"http", "https"}:
                    scheme = proto
                    forwarded = True
                normalized_host = _normalize_host(forwarded_host)
                if normalized_host:
                    host = normalized_host
                    forwarded = True
                if xff:
                    forwarded = True
            else:
                client_ip = remote
        else:
            client_ip = remote

        return ProxyRequestContext(
            client_ip=client_ip,
            scheme=scheme,
            host=host,
            origin=f"{scheme}://{host}",
            forwarded=forwarded,
        )

    def _resolve_client_ip(
        self, remote_ip: str, xff: str
    ) -> tuple[str, bool, int | None, int]:
        if not xff:
            return remote_ip, True, None, 0
        raw_addresses = [item.strip() for item in xff.split(",")]
        if not raw_addresses or any(not item for item in raw_addresses):
            return remote_ip, False, None, 0
        addresses = [_normalize_ip(item) for item in raw_addresses]
        if any(address is None for address in addresses):
            return remote_ip, False, None, 0

        current = remote_ip
        boundary_index = None
        for index in range(len(addresses) - 1, -1, -1):
            if not self.is_trusted(current):
                break
            current = addresses[index] or remote_ip
            boundary_index = index
        return current, True, boundary_index, len(addresses)

    def redirect_url(
        self,
        context: ProxyRequestContext,
        path: str,
        query_string: str,
    ) -> str | None:
        if not self.redirect_to_https or context.scheme == "https":
            return None
        if self.external_url is None:
            return None
        safe_path = path if _safe_local_path(path) else "/"
        safe_query = query_string if _safe_query(query_string) else ""
        target = f"{self.external_url}{safe_path}"
        return f"{target}?{safe_query}" if safe_query else target


def normalize_external_url(value: str, *, name: str = "external_url") -> str:
    raw = value.strip()
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError as exc:
        raise ProxyConfigError(f"{name} must be a valid absolute URL origin") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or _normalize_host(parsed.netloc) is None
    ):
        raise ProxyConfigError(f"{name} must be an absolute URL origin without path or credentials")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise ProxyConfigError(f"{name} must use HTTPS except for loopback development URLs")
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    port = parsed.port
    if (scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    netloc = f"{rendered_host}:{port}" if port is not None else rendered_host
    return urlunsplit((scheme, netloc, "", "", "")).rstrip("/")


def _header(headers: Mapping[str, str], name: str) -> str:
    direct = headers.get(name)
    if direct is not None:
        return str(direct).strip()
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value).strip()
    return ""


def _aligned_forwarded_value(
    value: str, *, boundary_index: int | None, chain_length: int
) -> str:
    if not value:
        return ""
    parts = [item.strip() for item in value.split(",")]
    if any(not item for item in parts):
        return ""
    if len(parts) == 1:
        return parts[0]
    if boundary_index is not None and len(parts) == chain_length:
        return parts[boundary_index]
    return ""


def _normalize_ip(value: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(value.strip())
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except ValueError:
        return None


def _normalize_host(value: str) -> str | None:
    host = value.strip()
    if not host or any(ord(char) < 33 or ord(char) == 127 for char in host):
        return None
    if any(char in host for char in "/\\?#@"):
        return None
    try:
        parsed = urlsplit(f"//{host}")
        _ = parsed.port
    except ValueError:
        return None
    if not parsed.hostname or parsed.username or parsed.password:
        return None
    return host.lower()


def _safe_local_path(path: str) -> bool:
    return (
        bool(path)
        and path.startswith("/")
        and not path.startswith("//")
        and "\\" not in path
        and not any(char in path for char in "\r\n")
    )


def _safe_query(query: str) -> bool:
    return not any(char in query for char in "\r\n#")


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
