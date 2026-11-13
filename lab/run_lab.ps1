<#  Run the isolated Docker attack lab on Windows (Docker Desktop, Linux containers).
    cd lab ; powershell -ExecutionPolicy Bypass -File .\run_lab.ps1
    Produces lab\captures\lab.pcap + attack_phases.json, then scores the capture. #>
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force captures | Out-Null
Remove-Item -ErrorAction SilentlyContinue captures\lab.pcap, captures\attack_phases.json
docker compose build
# attacker exits when done -> capture + target are stopped too
docker compose up --abort-on-container-exit --exit-code-from attacker attacker capture target
# copy results out (needed when the Docker daemon runs on another host/VM; harmless otherwise)
docker compose cp capture:/captures/lab.pcap captures/lab.pcap
docker compose cp attacker:/captures/attack_phases.json captures/attack_phases.json
docker compose down
python ingest_capture.py captures\lab.pcap --phases captures\attack_phases.json
Write-Host "To show the detections in the dashboard: python ingest_capture.py captures\lab.pcap --api http://127.0.0.1:5000"
