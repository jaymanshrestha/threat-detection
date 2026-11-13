# Attack lab - safety rules (read before running)

The lab produces real attack traffic (a port scan and a SYN flood). It is safe **only** because
it is confined to a virtual network that has no route to anything else.

## Rules

1. **Only attack the lab.** `attack.py` refuses any target outside `10.66.0.0/24`. Don't remove that check.
   Scanning or flooding networks you don't own is illegal in most countries (in Australia, for example,
   under the Criminal Code Act 1995 Part 10.7) and against university IT policy.
2. **Keep the network isolated.** `docker-compose.yml` sets `internal: true` on `labnet`, so containers can
   reach each other but not your LAN or the internet. Don't add `ports:`, `network_mode: host` or a second
   network to any service.
3. **Low rates only.** The flood is capped at 500 packets/s for 30 s (default 200 packets/s for 10 s). That is
   enough to trip the detectors without stressing your machine.
4. **Captures stay local.** Captures in `lab/captures/` contain only lab traffic. tcpdump uses a 160-byte snap
   length, so almost no payload is stored. Don't commit large captures.
5. **Tear down afterwards:** `docker compose down` (run_lab.ps1 does this for you).

## Running on Windows (Docker Desktop)

1. Install Docker Desktop and enable the WSL 2 backend. Use Linux containers (the default).
2. Open PowerShell in the project folder and run:
   ```powershell
   cd lab
   powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
   ```
   This builds three containers:
   - `target`: nginx on port 80 and OpenSSH on port 22. Password login is disabled.
   - `capture`: tcpdump, sharing the target's network interface.
   - `attacker`: Python plus nmap and hping3.

   The attacker then runs four phases: benign HTTP and SSH, `nmap -sT -p1-1024`, `hping3 -S` at 200 pps for
   10 s, and benign traffic again. Finally the script stops the lab and scores `captures\lab.pcap` with all
   three detectors.
3. Show the detections in the dashboard while the app is running:
   ```powershell
   python lab\ingest_capture.py lab\captures\lab.pcap --api http://127.0.0.1:5000
   ```
   You can also upload `lab.pcap` on **Data sources → Upload → pcap**.

## No Docker? (Linux only) - network-namespace fallback

`python lab/netns_lab.py` re-runs itself under `unshare -rn`, which creates a new, empty network namespace
and needs no root. Before doing anything it checks that the only interface is `lo`. It then:
- adds the lab addresses 10.66.0.10 and 10.66.0.66 to loopback;
- starts a small HTTP server and SSH-banner service on the target address;
- captures packets with an AF_PACKET socket;
- runs the same attack phases with the pure-Python scanner and raw-socket SYN sender.

Traffic physically cannot leave the namespace. The output is `lab/captures/netns_lab.pcap`, which you score
with `python lab/ingest_capture.py`.

## How ground truth is assigned

`attack.py` writes the start and end time of each phase to a JSON file. `ingest_capture.py` labels a flow
`scan` or `flood` if it involves the attacker's address and falls inside that phase's time window.
Everything else is labelled `benign`.
