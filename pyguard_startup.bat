@echo off
REM ========================================
REM PyGuard Tracker - Startup script
REM ========================================
REM Spúšťa PyGuard Tracker na pozadí pri štarte PC
REM 
REM Ako to nainštalovať:
REM 1. Skopíruj tento súbor (pyguard_startup.bat)
REM 2. Stlač Win+R a zadaj: shell:startup
REM 3. Skopíruj tu tento súbor
REM 4. Pri ďalšom štarte PC sa Tracker spustí automaticky
REM ========================================

setlocal enabledelayedexpansion

REM Získame cestu k priečinku kde leží tento BAT súbor
set "SCRIPT_DIR=%~dp0"

REM Zmeniť do tohto priečinka
cd /d "%SCRIPT_DIR%"

REM Skontrolovať či Python existuje
python --version >nul 2>&1
if errorlevel 1 (
    REM Python nie je nainštalovaný
    exit /b 1
)

REM Skontrolovať či tracker.py existuje
if not exist "tracker.py" (
    exit /b 1
)

REM Spustiť Tracker na pozadí bez viditeľného okna
REM pythonw.exe = Python bez konzoly
REM /B = bez nového okna
start "" pythonw.exe -c "import sys; sys.path.insert(0, r'%SCRIPT_DIR%'); from tracker import loop; loop()"

REM Alternatívny spôsob (s konzolou):
REM start /B python.exe "%SCRIPT_DIR%tracker.py"

exit /b 0

