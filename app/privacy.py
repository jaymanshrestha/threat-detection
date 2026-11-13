"""IP address display/privacy modes (dashboard, map, emails-optional and LLM facts).

full      - shown as-is (lab default; only authenticated admins see the UI)
truncate  - IPv4 /24 ("192.168.10.x"), IPv6 /48 ("2001:db8:1::/48")
hash      - keyed HMAC-SHA256 pseudonym ("ip-3f9a1c0d2b"), stable per key so the same
            host can still be correlated without revealing the address.
"""
import hashlib
import hmac
import ipaddress

MODES = ("full", "truncate", "hash")


def _key():
    try:
        from flask import current_app
        return (current_app.config.get("IP_HASH_KEY") or current_app.config["SECRET_KEY"]).encode()
    except RuntimeError:  # outside app context
        return b"offline"


def truncate(ip: str) -> str:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return "invalid-ip"
    if a.version == 4:
        o = str(a).split(".")
        return f"{o[0]}.{o[1]}.{o[2]}.x"
    net = ipaddress.ip_network(f"{a}/48", strict=False)
    return f"{net.network_address}/48"


def pseudonym(ip: str, key: bytes = None) -> str:
    return "ip-" + hmac.new(key or _key(), str(ip).encode(), hashlib.sha256).hexdigest()[:10]


def display(ip, mode: str = "full") -> str:
    if ip is None:
        return ""
    if mode == "truncate":
        return truncate(ip)
    if mode == "hash":
        return pseudonym(ip)
    return str(ip)


def is_internal(ip) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local
