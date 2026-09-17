@echo off
REM ============================================================
REM  Builds USBLockerPro.exe - a standalone Windows executable
REM  that does NOT need Python installed on the machine that
REM  runs it. Build this once on YOUR PC, then copy the .exe
REM  onto the pendrive itself and run it from there.
REM ============================================================
cd /d "%~dp0"

echo Installing build + app dependencies...
python -m pip install --upgrade pip
python -m pip install --upgrade pyinstaller
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo pip install failed - see the errors above. Fix those first,
    echo then run this script again.
    pause
    exit /b 1
)

echo.
echo Building USBLockerPro.exe ...
python -m PyInstaller --onefile --noconsole --name "USBLockerPro" --icon "assets\usblockerpro.ico" usb_locker_pro.py

if not exist "dist\USBLockerPro.exe" (
    echo.
    echo ============================================================
    echo BUILD FAILED - dist\USBLockerPro.exe was not created.
    echo Scroll up and read the error text above to see why.
    echo ============================================================
    pause
    exit /b 1
)

echo.
echo ============================================================
echo Done. Your portable app is at:  dist\USBLockerPro.exe
echo.
echo Copy dist\USBLockerPro.exe onto the root (or any folder) of
echo your USB drive. On any Windows PC, plug the drive in and
echo double-click USBLockerPro.exe directly from the drive -
echo no Python installation needed on that PC.
echo ============================================================
pause
