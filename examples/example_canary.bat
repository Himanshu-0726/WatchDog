@echo off
REM WatchDog Example Canary File
REM This is an example of what a generated canary looks like.
REM
REM WARNING: This is a security canary file.
REM If you see this message, the canary has been triggered.
REM An alert has been sent to the system administrator.
REM
REM For authorized use only. See DISCLAIMER.md.

echo WatchDog - Access detected
timeout /t 2 /nobreak >nul
pythonw "C:\path\to\watchdog\sentinel.py"
