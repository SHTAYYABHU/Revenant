@echo off
setlocal
rem Starts Revenant, creating a private Python environment on the first run.
rem Right click and choose Run as administrator when you need to read attached disks.
cd /d "%~dp0"
where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
if not exist ".venv\Scripts\python.exe" (
  echo Creating a virtual environment in .venv, this only happens once.
  %PY% -m venv .venv || goto :fail
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :fail
)
start "" ".venv\Scripts\pythonw.exe" -m revenant
exit /b 0
:fail
echo.
echo Setup failed. Install Python 3.10 or newer from python.org, tick "Add python.exe to PATH",
echo then run this file again.
pause
exit /b 1
