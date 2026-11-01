@echo off
set "EDGE_EXE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not exist "%EDGE_EXE%" set "EDGE_EXE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if exist "%EDGE_EXE%" (
  start "" "%EDGE_EXE%" --new-window "http://127.0.0.1:8000/"
) else (
  start "" "http://127.0.0.1:8000/"
)
