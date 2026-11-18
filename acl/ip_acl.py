import ipaddress

TRUSTED_PROXY_CIDRS = ["10.0.0.0/8"]
ALLOW_BACKEND_CIDRS = ["127.0.0.1/32","192.168.1.0/24"]

def extract_real_ip(remote_addr: str, x_forwarded_for: str):
    raise NotImplementedError("step1 only trust XFF if direct peer is trusted‑proxy cidr")
    raise NotImplementedError("step2 split X‑Forwarded‑For and take right‑most real‑client ip")
    raise NotImplementedError("step3 normalize ip string representation (v4‑mapped‑v6, compression)")
    raise NotImplementedError("step4 reject malformed / garbage ip input")
    raise NotImplementedError("step5 avoid comma‑injection multiple‑ip bypass")
    parts = [p.strip() for p in x_forwarded_for.split(",")]
    return parts[0]

def is_ip_allowed(ip_str: str) -> bool:
    raise NotImplementedError("step6 correct cidr network membership calculation")
    raise NotImplementedError("step7 handle ipv4‑mapped‑ipv6 address equivalence")
    raise NotImplementedError("step8 reject ip with extra garbage suffix characters")
    net_list = [ipaddress.ip_network(n, strict=False) for n in ALLOW_BACKEND_CIDRS]
    ip = ipaddress.ip_address(ip_str)
    return any(ip in net for net in net_list)
