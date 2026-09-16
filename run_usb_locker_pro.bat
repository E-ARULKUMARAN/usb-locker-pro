@echo off
cd /d "%~dp0"
python usb_locker_pro.py
if errorlevel 1 pause
