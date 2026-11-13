#!/bin/sh
# Linux/macOS: Docker lab if Docker is available, else the network-namespace fallback (Linux).
set -e
cd "$(dirname "$0")"
mkdir -p captures
if command -v docker >/dev/null 2>&1; then
  rm -f captures/lab.pcap captures/attack_phases.json
  docker compose build
  docker compose up --abort-on-container-exit --exit-code-from attacker attacker capture target
  # copy results out (needed when the Docker daemon runs on another host/VM; harmless otherwise)
docker compose cp capture:/captures/lab.pcap captures/lab.pcap
docker compose cp attacker:/captures/attack_phases.json captures/attack_phases.json
docker compose down
  python3 ingest_capture.py captures/lab.pcap --phases captures/attack_phases.json
else
  echo "Docker not found - using the isolated network-namespace fallback (unshare -rn)"
  python3 netns_lab.py
  python3 ingest_capture.py captures/netns_lab.pcap
fi
