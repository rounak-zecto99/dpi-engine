@echo off
setlocal
cd /d "%~dp0"
if exist target\classes rmdir /s /q target\classes
if not exist target mkdir target
mkdir target\classes
dir /s /b src\main\java\*.java > target\sources.txt
javac --release 17 -d target\classes @target\sources.txt
if errorlevel 1 exit /b 1
jar --create --file target\dpi-engine-java.jar --main-class Main -C target\classes .
if errorlevel 1 exit /b 1
echo Build successful: target\dpi-engine-java.jar
endlocal
