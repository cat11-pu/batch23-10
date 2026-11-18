import ipaddress
import re

TRUSTED_PROXY_CIDRS = ["10.0.0.0/8"]
ALLOW_BACKEND_CIDRS = ["127.0.0.1/32","192.168.1.0/24"]

_LEGACY_IPV4_RE = re.compile(
    r"^(?:(?:0[xX][0-9a-fA-F]+)|(?:0[0-9]+)|(?:[0-9]+))"
    r"(?:\.(?:(?:0[xX][0-9a-fA-F]+)|(?:0[0-9]+)|(?:[0-9]+)))*$"
)


def _networks(cidrs):
    return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


_TRUSTED_PROXY_NETWORKS = _networks(TRUSTED_PROXY_CIDRS)
_ALLOW_BACKEND_NETWORKS = _networks(ALLOW_BACKEND_CIDRS)


def _parse_ip(ip_str):
    if not isinstance(ip_str, str):
        raise ValueError("IP address must be a string")

    text = ip_str.strip()
    if not text:
        raise ValueError("IP address must not be empty")

    ip = ipaddress.ip_address(text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def _looks_like_legacy_ipv4(text):
    if not _LEGACY_IPV4_RE.fullmatch(text):
        return False

    parts = text.split(".")
    if any(
        part.lower().startswith("0x")
        or (len(part) > 1 and part.startswith("0") and part.isdigit())
        for part in parts
    ):
        return True
    return len(parts) != 4


def _parse_client_ip(ip_str):
    try:
        return _parse_ip(ip_str)
    except ValueError:
        if isinstance(ip_str, str) and _looks_like_legacy_ipv4(ip_str.strip()):
            return None
        raise


def _ip_candidates(ip):
    if isinstance(ip, ipaddress.IPv4Address):
        candidates = [ip, ipaddress.IPv6Address(f"::ffff:{ip}")]
        if ip == ipaddress.IPv4Address("127.0.0.1"):
            candidates.append(ipaddress.IPv6Address("::1"))
        return candidates

    candidates = [ip]
    if ip.ipv4_mapped is not None:
        candidates.append(ip.ipv4_mapped)
    if ip == ipaddress.IPv6Address("::1"):
        candidates.append(ipaddress.IPv4Address("127.0.0.1"))
    return candidates


def _ip_in_networks(ip, networks):
    for candidate in _ip_candidates(ip):
        for network in networks:
            if candidate.version == network.version and candidate in network:
                return True
    return False


def _is_trusted_proxy(ip):
    return _ip_in_networks(ip, _TRUSTED_PROXY_NETWORKS)


def extract_real_ip(remote_addr: str, x_forwarded_for: str):
    remote_ip = _parse_ip(remote_addr)
    if not _is_trusted_proxy(remote_ip):
        return str(remote_ip)

    if not isinstance(x_forwarded_for, str) or not x_forwarded_for.strip():
        return str(remote_ip)

    parts = [part.strip() for part in x_forwarded_for.split(",") if part.strip()]
    forwarded_ips = [_parse_ip(part) for part in parts]
    if not forwarded_ips:
        return str(remote_ip)

    if remote_ip in forwarded_ips:
        direct_peer_index = len(forwarded_ips) - 1 - forwarded_ips[::-1].index(
            remote_ip
        )
        forwarded_ips = forwarded_ips[:direct_peer_index]
    else:
        forwarded_ips = forwarded_ips[:-1]

    for ip in reversed(forwarded_ips):
        if not _is_trusted_proxy(ip):
            return str(ip)

    return str(remote_ip)


def is_ip_allowed(ip_str: str) -> bool:
    ip = _parse_client_ip(ip_str)
    if ip is None:
        return False
    return _ip_in_networks(ip, _ALLOW_BACKEND_NETWORKS)
