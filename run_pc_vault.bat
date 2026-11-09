@echo off
cd /d %~dp0
if not exist .venv\Scripts\python.exe py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
set PORT=8787
.venv\Scripts\python phone_plus.py
pause
