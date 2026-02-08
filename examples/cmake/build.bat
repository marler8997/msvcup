@setlocal enabledelayedexpansion

@set REAL_ARCH=%PROCESSOR_ARCHITECTURE%
@echo %PROCESSOR_IDENTIFIER% | findstr /i "ARMv8" >nul
@if %errorlevel%==0 set REAL_ARCH=ARM64

@if %REAL_ARCH%==AMD64 (
    set MSVCUP_ARCH=x86_64
    set HOST_CPU=x64
    set CMAKE_ARCH=x86_64
) else if %REAL_ARCH%==ARM64 (
    set MSVCUP_ARCH=aarch64
    set HOST_CPU=arm64
    set CMAKE_ARCH=arm64
) else (
    echo error: unhandled PROCESSOR_ARCHITECTURE "%REAL_ARCH%"
)

@if "%~1"=="-h" (
    echo Usage: build [TARGET_CPU]
    echo        TARGET_CPU can be one of x64, arm64 or x86
    echo        TARGET_CPU defaults to HOST_CPU ^(%HOST_CPU%^)
    exit /b 1
)

@if "%~1"=="" (
    set TARGET_CPU=%HOST_CPU%
) else (
    set TARGET_CPU=%~1
)

@if not exist %~dp0msvcup.exe (
    echo msvcup.exe: installing...
    curl -L -o %~dp0msvcup.zip https://github.com/marler8997/msvcup/releases/download/v2026_02_07/msvcup-%MSVCUP_ARCH%-windows.zip
    tar -C%~dp0 -xf %~dp0msvcup.zip
    del %~dp0msvcup.zip
) else (
    echo msvcup.exe: already installed
)
@if not exist %~dp0msvcup.exe exit /b 1

set MSVC=msvc-14.44.17.14
set SDK=sdk-10.0.22621.7
set NINJA_PKG=ninja-1.13.2
set NINJA=C:\msvcup\%NINJA_PKG%\ninja.exe
set CMAKE_PKG=cmake-4.2.3
set CMAKE=C:\msvcup\%CMAKE_PKG%\bin\cmake.exe

%~dp0msvcup.exe install --lock-file %~dp0msvcup.lock --manifest-update-off %MSVC% %SDK% %NINJA_PKG% %CMAKE_PKG%
@if %errorlevel% neq 0 (exit /b %errorlevel%)

%~dp0msvcup.exe autoenv --target-cpu %TARGET_CPU% --out-dir %~dp0autoenv\%TARGET_CPU% %MSVC% %SDK%
@if %errorlevel% neq 0 (exit /b %errorlevel%)

@if not exist %~dp0out\%TARGET_CPU%\build.ninja (
    %CMAKE% -S %~dp0 -B %~dp0out/%TARGET_CPU% -DCMAKE_TOOLCHAIN_FILE=%~dp0/autoenv/%TARGET_CPU%/toolchain.cmake -GNinja -DCMAKE_MAKE_PROGRAM=%NINJA%
    @if %errorlevel% neq 0 (exit /b %errorlevel%)
)

%NINJA% -C %~dp0out\%TARGET_CPU%
