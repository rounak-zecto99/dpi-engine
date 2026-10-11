@echo off
cd /d "%~dp0"
if not exist target\dpi-engine-java.jar call build.bat
if errorlevel 1 exit /b 1
java -jar target\dpi-engine-java.jar %*
