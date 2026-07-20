@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ========================================
echo  BeamNG Mod Scanner - Install
echo ========================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python was not found on PATH.
  echo Install Python 3.10+ from https://www.python.org/downloads/
  echo Make sure "Add python.exe to PATH" is checked during setup.
  echo.
  pause
  exit /b 1
)

echo Using:
python --version
echo.

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create .venv
    pause
    exit /b 1
  )
)

echo Upgrading pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 (
  echo [ERROR] Failed to upgrade pip
  pause
  exit /b 1
)

echo Installing BeamNG Mod Scanner...
".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 (
  echo [ERROR] Install failed
  pause
  exit /b 1
)

echo.
echo ========================================
echo  Install complete.
echo  Double-click run.bat to start the app.
echo ========================================
echo.
pause
endlocal
