"""Run the streaming collectors as a separate process (alternative to ENABLE_COLLECTORS=1).

    python scripts/collector.py                     # syslog UDP+TCP :5514, NetFlow v5 UDP :2055 on 127.0.0.1
    python scripts/collector.py --bind 0.0.0.0      # listen on all interfaces (lab LAN only!)

Events are scored as they arrive (batched every ~1 s) and stored in the same database the
dashboard uses, which pushes updates to open browsers via Server-Sent Events.
"""
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402
from ingest.collectors import CollectorService, app_handler, wait_forever  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default=None)
    ap.add_argument("--syslog-port", type=int, default=None, help="UDP and TCP syslog port (default 5514)")
    ap.add_argument("--netflow-port", type=int, default=None, help="NetFlow v5 UDP port (default 2055)")
    ap.add_argument("--flush", type=float, default=None, help="seconds between scoring batches (default 1)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app(START_SCHEDULER=False, ENABLE_COLLECTORS=False)
    c = app.config
    svc = CollectorService(app_handler(app), bind=a.bind or c["COLLECTOR_BIND"],
                           syslog_udp=a.syslog_port or c["SYSLOG_UDP_PORT"],
                           syslog_tcp=a.syslog_port or c["SYSLOG_TCP_PORT"],
                           netflow_udp=a.netflow_port or c["NETFLOW_UDP_PORT"],
                           flush_seconds=a.flush or c["COLLECTOR_FLUSH_SECONDS"]).start()
    print(f"Collectors running on {svc.bind}: {svc.bound}. Ctrl+C to stop.", flush=True)
    wait_forever(svc)


if __name__ == "__main__":
    main()
