@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo Building BitScan C++ Native Carving Core (x64)
echo =======================================================

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to initialize MSVC x64 build environment.
    exit /b 1
)

cd /d "%~dp0"

echo Compiling carver_native.dll with /O2 optimization...
cl.exe /O2 /Oi /Ot /EHsc /MD /LD /std:c++17 ^
    hasher.cpp validators.cpp filesystem_bitmap.cpp carver_native.cpp ^
    /link /OUT:carver_native.dll bcrypt.lib

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] carver_native.dll built successfully!
    del *.obj *.exp *.lib 2>nul
    exit /b 0
) else (
    echo [ERROR] Compilation failed.
    exit /b %ERRORLEVEL%
)
