@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment not found.
  echo Running install.bat first...
  echo.
  call "%~dp0install.bat"
  if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Install did not finish successfully.
    pause
    exit /b 1
  )
)

echo Starting Simple Mod Scanner...
".venv\Scripts\python.exe" -m simple_mod_scanner
if errorlevel 1 (
  echo.
  echo [ERROR] The app exited with an error.
  pause
  exit /b 1
)

endlocal
