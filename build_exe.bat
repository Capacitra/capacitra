@echo off
setlocal enabledelayedexpansion
title Capacitra - Build .exe
color 0B

echo.
echo =============================================
echo   Capacitra - Storage capacity intelligence
echo   Windows .exe builder
echo =============================================
echo.

REM --- Find Python ---
set "PYEXE="
where python >nul 2>nul && set "PYEXE=python"
if "%PYEXE%"=="" (
    where py >nul 2>nul && set "PYEXE=py"
)
if "%PYEXE%"=="" (
    echo [X] Python not found on PATH.
    echo     Install it from https://www.python.org/downloads/
    echo     During install, tick "Add Python to PATH".
    pause
    exit /b 1
)
echo [1/4] Using Python: %PYEXE%
%PYEXE% --version
echo.

REM --- Ensure pip + pyinstaller + optional features ---
echo [2/4] Installing PyInstaller and feature dependencies...
echo       (reportlab = PDF export, openpyxl = Excel export,
echo        send2trash = safe trash on macOS/Linux builds)
%PYEXE% -m pip install --quiet --upgrade pip pyinstaller reportlab openpyxl send2trash
if errorlevel 1 (
    echo.
    echo [!] Some dependencies failed to install but we will keep going.
    echo     The .exe will still build, just without those optional features.
    echo.
)

REM --- Generate the .ico file with the Capacitra mark ---
echo.
echo [3/5] Generating capacitra.ico ...
%PYEXE% make_icon.py
if errorlevel 1 (
    echo [!] Icon generation failed. The .exe will still build but use
    echo     the default PyInstaller icon.
)

REM --- Build ---
echo.
echo [4/5] Building Capacitra.exe ...
echo       (first run takes a few minutes)
echo.
REM --noupx     : avoid UPX compression (UPX-packed binaries are AV bait)
REM --version-file : embed CompanyName/ProductName/Version so SmartScreen
REM                  and most AV products see a legitimate publisher
REM --manifest  : embed a UAC manifest declaring asInvoker (no admin),
REM               DPI awareness, long-path support, and Win10/11
REM               compatibility. Reduces AV false positives.
REM --exclude-module : strip dev-only modules that PyInstaller would
REM                    otherwise bundle, shrinking the .exe and reducing
REM                    AV false-positive surface
%PYEXE% -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --clean ^
    --noupx ^
    --strip ^
    --name Capacitra ^
    --icon capacitra.ico ^
    --version-file version_info.txt ^
    --manifest Capacitra.manifest ^
    --collect-all reportlab ^
    --collect-all openpyxl ^
    --exclude-module pytest ^
    --exclude-module setuptools ^
    --exclude-module pip ^
    --exclude-module wheel ^
    --exclude-module unittest ^
    --exclude-module pydoc ^
    --exclude-module tkinter.test ^
    --exclude-module test ^
    Capacitra.pyw

if errorlevel 1 (
    echo.
    echo [X] Build failed. Scroll up for PyInstaller error.
    pause
    exit /b 1
)

echo.
echo [5/5] Copying result ...
if exist dist\Capacitra.exe (
    copy /Y dist\Capacitra.exe Capacitra.exe >nul
)

echo.
echo =============================================
echo   DONE
echo =============================================
echo.
echo   Output: %CD%\Capacitra.exe
echo.
echo   You can delete the .\build folder and the
echo   .spec file - they are intermediate artefacts.
echo.
pause
endlocal
