"""Offline IP geolocation for the threat map.

Uses the free DB-IP "IP to City Lite" database (CC BY 4.0, attribution required:
"IP Geolocation by DB-IP", https://db-ip.com). Download it with
``python scripts/download_geoip.py``. Reading uses the pure-Python ``maxminddb``
package if installed; otherwise a small built-in MMDB reader (below) is used, so
the map works on any Python version without compiled extensions.
Private / RFC1918 / loopback addresses are placed at SITE_LAT/SITE_LON and labelled internal.
"""
import ipaddress
import struct
import threading
from functools import lru_cache
from pathlib import Path

from .privacy import is_internal

ATTRIBUTION = 'IP Geolocation by <a href="https://db-ip.com" rel="noopener">DB-IP</a> (CC BY 4.0)'
_lock = threading.Lock()
_readers = {}


class MiniMMDBReader:
    """Minimal pure-Python MaxMind DB (v2) reader: enough for City lookups.
    Spec: https://maxmind.github.io/MaxMind-DB/"""
    META = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path):
        self.buf = Path(path).read_bytes()
        m = self.buf.rfind(self.META)
        if m < 0:
            raise ValueError("not a MaxMind DB file")
        self.meta, _ = self._decode(m + len(self.META), m + len(self.META))
        self.node_count = self.meta["node_count"]
        self.record_size = self.meta["record_size"]
        self.ip_version = self.meta["ip_version"]
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self.data_start = self.tree_size + 16
        self._ipv4_start = None

    def _read_node(self, n, bit):
        off = n * self.node_bytes
        b = self.buf
        rs = self.record_size
        if rs == 24:
            o = off + bit * 3
            return int.from_bytes(b[o:o + 3], "big")
        if rs == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | int.from_bytes(b[off:off + 3], "big")
            return ((b[off + 3] & 0x0F) << 24) | int.from_bytes(b[off + 4:off + 7], "big")
        if rs == 32:
            o = off + bit * 4
            return int.from_bytes(b[o:o + 4], "big")
        raise ValueError(f"unsupported record size {rs}")

    def _ipv4_root(self):
        if self._ipv4_start is None:
            n = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if n >= self.node_count:
                        break
                    n = self._read_node(n, 0)
            self._ipv4_start = n
        return self._ipv4_start

    def get(self, ip):
        a = ipaddress.ip_address(ip)
        packed = a.packed
        n = self._ipv4_root() if a.version == 4 else 0
        bits = len(packed) * 8
        for i in range(bits):
            if n >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            n = self._read_node(n, bit)
        if n == self.node_count:
            return None
        if n > self.node_count:
            off = n - self.node_count - 16 + self.data_start
            return self._decode(off, self.data_start)[0]
        return None

    def _decode(self, off, base):
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss = (ctrl >> 3) & 3
            v = ctrl & 7
            if ss == 0:
                p = (v << 8) | b[off]; off += 1
            elif ss == 1:
                p = ((v << 16) | int.from_bytes(b[off:off + 2], "big")) + 2048; off += 2
            elif ss == 2:
                p = ((v << 24) | int.from_bytes(b[off:off + 3], "big")) + 526336; off += 3
            else:
                p = int.from_bytes(b[off:off + 4], "big"); off += 4
            val, _ = self._decode(base + p, base)
            return val, off
        if typ == 0:  # extended
            typ = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size >= 29:
            if size == 29:
                size = 29 + b[off]; off += 1
            elif size == 30:
                size = 285 + int.from_bytes(b[off:off + 2], "big"); off += 2
            else:
                size = 65821 + int.from_bytes(b[off:off + 3], "big"); off += 3
        if typ == 2:  # utf8
            return b[off:off + size].decode("utf-8", "replace"), off + size
        if typ == 3:  # double
            return struct.unpack("!d", b[off:off + 8])[0], off + 8
        if typ == 4:  # bytes
            return bytes(b[off:off + size]), off + size
        if typ in (5, 6, 9, 10):  # uint16/32/64/128
            return int.from_bytes(b[off:off + size], "big") if size else 0, off + size
        if typ == 7:  # map
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[k] = v
            return out, off
        if typ == 8:  # int32
            v = int.from_bytes(b[off:off + size], "big", signed=False) if size else 0
            if size == 4 and v >= 2 ** 31:
                v -= 2 ** 32
            return v, off + size
        if typ == 11:  # array
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if typ == 14:  # boolean
            return bool(size), off
        if typ == 15:  # float
            return struct.unpack("!f", b[off:off + 4])[0], off + 4
        raise ValueError(f"unsupported MMDB type {typ}")


def reset_readers():
    with _lock:
        _readers.clear()
    _lookup_cached.cache_clear()


def open_reader(path):
    """Return a reader with .get(ip) or None if the DB is absent."""
    path = str(path)
    with _lock:
        if path in _readers:
            return _readers[path]
        r = None
        if Path(path).exists():
            try:
                import maxminddb
                r = maxminddb.open_database(path)
            except Exception:  # noqa: BLE001 - not installed, or its C extension rejects the file
                r = MiniMMDBReader(path)
        _readers[path] = r
        return r


def _name(d):
    if isinstance(d, dict):
        n = d.get("names") or {}
        return n.get("en") or next(iter(n.values()), None)
    return None


@lru_cache(maxsize=20000)
def _lookup_cached(path, ip):
    r = open_reader(path)
    if r is None:
        return None
    try:
        rec = r.get(ip)
    except (ValueError, TypeError):
        return None
    if not rec:
        return None
    loc = rec.get("location") or {}
    if "latitude" not in loc:
        return None
    return {"lat": round(float(loc["latitude"]), 4), "lon": round(float(loc["longitude"]), 4),
            "city": _name(rec.get("city")), "country": _name(rec.get("country")),
            "country_code": (rec.get("country") or {}).get("iso_code"), "internal": False}


def locate(ip, db_path, site):
    """site = dict(name, lat, lon). Returns dict or None (unknown location)."""
    if is_internal(ip):
        return {"lat": site["lat"], "lon": site["lon"], "city": "Internal network", "site": site["name"], "country": None,
                "country_code": None, "internal": True}
    return _lookup_cached(str(db_path), str(ip))
