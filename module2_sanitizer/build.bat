@echo off
setlocal
cd /d "%~dp0"
set "OUTPUT=%~1"
if "%OUTPUT%"=="" set "OUTPUT=bitscan_sanitizer.exe"
gcc -std=c11 -Wall -Wextra -Wpedantic -Iinclude main.c src\os_classification.c src\Interrogator.c src\os_windows.c src\nist_clear.c src\verifier.c src\reporter.c -o "%OUTPUT%" -ladvapi32
if errorlevel 1 exit /b 1
echo Built %OUTPUT%
