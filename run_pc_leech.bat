@echo off
cd /d %~dp0
py -m pip install -r requirements.txt
py pc_leech.py
pause
