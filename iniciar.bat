@echo off
setlocal EnableExtensions
title MatrixScan
cd /d "%~dp0"

rem ---------------------------------------------------------------
rem  MatrixScan - lanzador para Windows
rem  Pide permisos de administrador (Prefetch, Defender y procesos del
rem  sistema los necesitan). Si los rechazas, corre con analisis parcial.
rem  Para no pedirlos nunca:  iniciar.bat --sin-admin
rem ---------------------------------------------------------------

net session >nul 2>&1
if errorlevel 1 (
  if /i not "%~1"=="--sin-admin" (
    echo Solicitando permisos de administrador...
    powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
    if not errorlevel 1 exit /b 0
    echo Permiso rechazado: MatrixScan correra con analisis parcial.
  )
)

set "PY="
py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY (
  python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo.
  echo [X] No se encontro Python 3.9 o superior.
  echo     Instalalo con:   winget install Python.Python.3.12
  echo     o desde https://www.python.org/downloads/ marcando "Add python.exe to PATH".
  echo.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creando entorno virtual en .venv ...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo [X] No se pudo crear el entorno virtual.
    pause
    exit /b 1
  )
)

".venv\Scripts\python.exe" -c "import psutil" >nul 2>&1
if errorlevel 1 (
  echo Instalando dependencias, solo la primera vez...
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
  if errorlevel 1 (
    echo [X] Fallo la instalacion de dependencias. Revisa tu conexion a internet.
    pause
    exit /b 1
  )
)

".venv\Scripts\python.exe" -m matrixscan
if errorlevel 1 pause
