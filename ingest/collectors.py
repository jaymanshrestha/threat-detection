"""Streaming collectors: syslog over UDP/TCP (RFC 5426 / RFC 6587) and NetFlow v5 over UDP.

Each listener runs in a daemon thread and appends raw lines/datagrams to a bounded
buffer; a flusher thread hands the buffer to ``handler(profile, payload_bytes)``
every ``flush_seconds`` so events are scored within ~1 s of arrival.
Bind to 127.0.0.1 by default; only expose on a LAN interface you control.
"""
import logging
import socket
import socketserver
import threading
import time

log = logging.getLogger("collectors")
MAX_LINE = 8192
MAX_BUFFER = 50_000  # lines / datagrams per profile between flushes; overflow is dropped and counted
MAX_TCP_CLIENTS = 32


class _Buffer:
    def __init__(self):
        self.lock = threading.Lock()
        self.items = {"syslog": [], "netflow_v5": []}
        self.dropped = {"syslog": 0, "netflow_v5": 0}
        self.received = {"syslog": 0, "netflow_v5": 0}

    def add(self, profile, item):
        with self.lock:
            self.received[profile] += 1
            if len(self.items[profile]) >= MAX_BUFFER:
                self.dropped[profile] += 1
                return
            self.items[profile].append(item)

    def take(self):
        with self.lock:
            out = {k: v for k, v in self.items.items() if v}
            self.items = {k: [] for k in self.items}
            return out


class CollectorService:
    def __init__(self, handler, bind="127.0.0.1", syslog_udp=5514, syslog_tcp=5514, netflow_udp=2055,
                 flush_seconds=1.0):
        self.handler, self.bind, self.flush_seconds = handler, bind, flush_seconds
        self.ports = {"syslog_udp": syslog_udp, "syslog_tcp": syslog_tcp, "netflow_udp": netflow_udp}
        self.buf = _Buffer()
        self.stop_event = threading.Event()
        self.threads, self.socks, self.bound = [], [], {}
        self._tcp_server = None
        self.flushes = 0
        self.errors = 0

    # ---------------------------------------------------------------- listeners
    def _udp(self, name, port, profile):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, port))
        s.settimeout(0.5)
        self.socks.append(s)
        self.bound[name] = s.getsockname()[1]

        def run():
            while not self.stop_event.is_set():
                try:
                    data, _addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if profile == "syslog":
                    for line in data.splitlines():
                        if line.strip():
                            self.buf.add("syslog", line[:MAX_LINE])
                else:
                    self.buf.add(profile, data)
        t = threading.Thread(target=run, name=f"collector-{name}", daemon=True)
        t.start()
        self.threads.append(t)

    def _tcp(self, port):
        svc = self
        active = threading.BoundedSemaphore(MAX_TCP_CLIENTS)

        class Handler(socketserver.StreamRequestHandler):
            timeout = 60

            def handle(self):
                if not active.acquire(blocking=False):
                    return
                try:
                    while not svc.stop_event.is_set():
                        line = self.rfile.readline(MAX_LINE)
                        if not line:
                            break
                        line = line.rstrip(b"\r\n")
                        # RFC 6587 octet counting: "<len> <msg>" - strip the length prefix
                        head, sep, rest = line.partition(b" ")
                        if sep and head.isdigit() and rest.startswith(b"<"):
                            line = rest
                        if line.strip():
                            svc.buf.add("syslog", line)
                except (OSError, ValueError):
                    pass
                finally:
                    active.release()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        srv = Server((self.bind, port), Handler)
        self._tcp_server = srv
        self.bound["syslog_tcp"] = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5}, name="collector-syslog-tcp",
                             daemon=True)
        t.start()
        self.threads.append(t)

    # ---------------------------------------------------------------- flushing
    def flush(self):
        batch = self.buf.take()
        for profile, items in batch.items():
            payload = b"\n".join(items) if profile == "syslog" else b"".join(items)
            try:
                self.handler(profile, payload)
            except Exception:  # noqa: BLE001 - never let one bad batch kill the collector
                self.errors += 1
                log.exception("collector flush failed for %s", profile)
        self.flushes += 1
        return batch

    def _flusher(self):
        while not self.stop_event.wait(self.flush_seconds):
            self.flush()

    def start(self):
        if self.ports["syslog_udp"] is not None:
            self._udp("syslog_udp", self.ports["syslog_udp"], "syslog")
        if self.ports["syslog_tcp"] is not None:
            self._tcp(self.ports["syslog_tcp"])
        if self.ports["netflow_udp"] is not None:
            self._udp("netflow_udp", self.ports["netflow_udp"], "netflow_v5")
        t = threading.Thread(target=self._flusher, name="collector-flush", daemon=True)
        t.start()
        self.threads.append(t)
        log.info("collectors listening on %s: %s", self.bind, self.bound)
        return self

    def stop(self):
        self.stop_event.set()
        if self._tcp_server:
            self._tcp_server.shutdown()
            self._tcp_server.server_close()
        for s in self.socks:
            s.close()
        self.flush()

    def stats(self):
        return {"bound": dict(self.bound), "received": dict(self.buf.received), "dropped": dict(self.buf.dropped),
                "flushes": self.flushes, "errors": self.errors}


def app_handler(app):
    """Handler that scores a batch through the app's pipeline (one ingestion job per flush)."""
    from app.pipeline import ingest_bytes

    def handle(profile, payload):
        with app.app_context():
            ingest_bytes(payload, f"stream-{profile}", source=f"stream:{profile}", profile=profile)
    return handle


def start_for_app(app):
    c = app.config
    svc = CollectorService(app_handler(app), bind=c["COLLECTOR_BIND"], syslog_udp=c["SYSLOG_UDP_PORT"],
                           syslog_tcp=c["SYSLOG_TCP_PORT"], netflow_udp=c["NETFLOW_UDP_PORT"],
                           flush_seconds=c["COLLECTOR_FLUSH_SECONDS"])
    try:
        svc.start()
    except OSError as e:
        app.logger.error("collectors not started (port in use?): %s", e)
        svc.stop()
        return None
    app.extensions["collectors"] = svc
    return svc


def wait_forever(svc, report_every=10.0):
    try:
        last = 0
        while True:
            time.sleep(1)
            if time.time() - last > report_every:
                log.info("collector stats: %s", svc.stats())
                last = time.time()
    except KeyboardInterrupt:
        svc.stop()
