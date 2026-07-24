@echo off
REM launch_toolkit.bat
REM Double-click this file to launch the Recon Toolkit GUI directly,
REM with no terminal window needed.

cd /d "%~dp0"

REM Use the venv's pythonw.exe (the "w" version runs with no console window)
if exist "venv\Scripts\pythonw.exe" (
    start "" "venv\Scripts\pythonw.exe" toolkit_gui.py
) else (
    REM Fallback to system Python if venv isn't found
    start "" pythonw toolkit_gui.py
)
