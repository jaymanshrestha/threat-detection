<#
  Windows helper (PowerShell). No venv activation needed - packages go to the user site-packages.
  Usage:   powershell -ExecutionPolicy Bypass -File .\run_windows.ps1 <command>
  Commands:
    setup      install requirements (+ optional extras that have wheels), download data, train, create admin
    install    python -m pip install --user -r requirements.txt  (then tries each optional package)
    data       download CIC-IDS2017 CSVs and the DB-IP GeoIP database
    train      train + evaluate Isolation Forest, rules and Random Forest
    admin      create an administrator (prompts for email/password)
    run        start the dashboard on http://127.0.0.1:5000 (with streaming collectors)
    collector  run the syslog/NetFlow collectors as a separate process
    demo       send demo syslog + NetFlow traffic to the collectors
    replay     replay Friday's attacks into the running app
    test       run the test suite
    lab        run the Docker attack lab and ingest the capture (Docker Desktop required)
#>
param([string]$cmd = "help")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = "python"

function Install {
  & $py -m pip install --user -r requirements.txt
  foreach ($p in @("shap", "maxminddb", "matplotlib", "pyarrow", "pillow")) {
    & $py -m pip install --user --only-binary=:all: $p
    if ($LASTEXITCODE -ne 0) { Write-Host "optional package $p not installed (no wheel for this Python) - fallback will be used" -ForegroundColor Yellow }
  }
  & $py -m pip install --user pytest
}

switch ($cmd) {
  "install"   { Install }
  "data"      { & $py scripts\download_dataset.py; & $py scripts\download_geoip.py }
  "train"     { & $py scripts\train_and_evaluate.py }
  "admin"     { & $py -m flask --app wsgi.py create-admin }
  "run"       { $env:ENABLE_COLLECTORS = "1"; & $py -m flask --app wsgi.py run --port 5000 }
  "collector" { & $py scripts\collector.py }
  "demo"      { & $py scripts\send_syslog.py --demo; & $py scripts\send_netflow.py }
  "replay"    { & $py scripts\replay.py --speed 60 }
  "test"      { & $py -m pytest -q }
  "lab"       { Push-Location lab; .\run_lab.ps1; Pop-Location }
  "setup"     { Install; & $py scripts\download_dataset.py; & $py scripts\download_geoip.py; & $py scripts\train_and_evaluate.py; & $py -m flask --app wsgi.py create-admin }
  default     { Get-Help $MyInvocation.MyCommand.Path -Detailed; Write-Host "commands: setup install data train admin run collector demo replay test lab" }
}
