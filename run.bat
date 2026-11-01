@echo off
setlocal
set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

rem Prefer the Python runtime already used by this Codex desktop installation.
set "PYTHON_EXE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
set "PYTHON_ARGS=-E"
if exist "%PYTHON_EXE%" goto :run_server

rem Fall back to a Python 3 installation registered with the Windows launcher.
set "PYTHON_EXE=py"
set "PYTHON_ARGS=-3 -E"
where.exe py >nul 2>&1
if not errorlevel 1 (
  "%PYTHON_EXE%" %PYTHON_ARGS% --version >nul 2>&1
  if not errorlevel 1 goto :run_server
)

rem Last option: python.exe available on PATH.
set "PYTHON_EXE=python"
set "PYTHON_ARGS=-E"
where.exe python >nul 2>&1
if errorlevel 1 goto :python_missing
"%PYTHON_EXE%" %PYTHON_ARGS% --version >nul 2>&1
if errorlevel 1 goto :python_missing

:run_server
echo Using Python:
"%PYTHON_EXE%" %PYTHON_ARGS% --version
echo Starting Cloud IAM Risk Analyzer...
echo No pip packages or cloud credentials are required for the sample project.
echo Keep this window open. The server will print the dashboard URL.
echo.
"%PYTHON_EXE%" %PYTHON_ARGS% -u "%PROJECT_DIR%server.py"
echo.
echo Server stopped. Press any key to close this window.
pause >nul
endlocal
exit /b

:python_missing
echo Python 3 could not be started. Install Python 3, then try again.
pause
endlocal
exit /b 1
