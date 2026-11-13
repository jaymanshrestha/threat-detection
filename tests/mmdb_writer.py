"""Tiny MaxMind DB writer for tests (one IPv4 prefix -> one record). Spec: maxmind.github.io/MaxMind-DB"""
import ipaddress
import struct


def _enc(v):
    if isinstance(v, dict):
        out = bytes([(7 << 5) | len(v)])
        for k, x in v.items():
            out += _enc(k) + _enc(x)
        return out
    if isinstance(v, str):
        b = v.encode()
        assert len(b) < 29
        return bytes([(2 << 5) | len(b)]) + b
    if isinstance(v, float):
        return bytes([(3 << 5) | 8]) + struct.pack("!d", v)
    if isinstance(v, list):
        out = bytes([len(v), 11 - 7])  # extended type: array
        for x in v:
            out += _enc(x)
        return out
    if isinstance(v, int):
        b = v.to_bytes(8, "big").lstrip(b"\0")
        if v < 2 ** 16:
            return bytes([(5 << 5) | len(b)]) + b
        if v < 2 ** 32:
            return bytes([(6 << 5) | len(b)]) + b
        return bytes([len(b), 9 - 7]) + b  # uint64 (extended)
    raise TypeError(type(v))


def write_mmdb(path, prefix, record):
    net = ipaddress.ip_network(prefix)
    bits = net.prefixlen
    n = bits  # one node per prefix bit
    addr = int(net.network_address)
    data = _enc(record)
    tree = b""
    for depth in range(bits):
        bit = (addr >> (31 - depth)) & 1
        nxt = depth + 1 if depth + 1 < bits else n + 16  # last level -> data offset 0
        empty = n
        left, right = (nxt, empty) if bit == 0 else (empty, nxt)
        tree += left.to_bytes(3, "big") + right.to_bytes(3, "big")
    meta = {"node_count": n, "record_size": 24, "ip_version": 4, "database_type": "Test-City",
            "languages": ["en"], "binary_format_major_version": 2, "binary_format_minor_version": 0,
            "build_epoch": 1700000000, "description": {"en": "test db"}}
    with open(path, "wb") as fh:
        fh.write(tree + b"\0" * 16 + data + b"\xab\xcd\xefMaxMind.com" + _enc(meta))
