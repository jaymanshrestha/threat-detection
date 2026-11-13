@echo off
REM One-shot setup for Windows cmd.exe (no venv activation needed).
cd /d %~dp0
python -m pip install --user -r requirements.txt || goto :err
for %%p in (shap maxminddb matplotlib pyarrow pillow) do (
  python -m pip install --user --only-binary=:all: %%p || echo optional package %%p skipped - fallback will be used
)
python -m pip install --user pytest
python scripts\download_dataset.py || goto :err
python scripts\download_geoip.py
python scripts\train_and_evaluate.py || goto :err
python -m flask --app wsgi.py create-admin
echo.
echo Done. Start the app with:  python -m flask --app wsgi.py run
goto :eof
:err
echo Setup failed - see the message above.
exit /b 1
