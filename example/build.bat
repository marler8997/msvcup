@setlocal

@if %PROCESSOR_ARCHITECTURE%==AMD64 (
    set MSVCUP_ARCH=x86_64
    set HOST_CPU=x64
) else if %PROCESSOR_ARCHITECTURE%==ARM64 (
    set MSVCUP_ARCH=aarch64
    set HOST_CPU=arm64
) else (
    echo error: unhandled PROCESSOR_ARCHITECTURE "%PROCESSOR_ARCHITECTURE%"
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
    curl -L -o %~dp0msvcup.zip https://github.com/marler8997/msvcup/releases/download/v2025_08_15/msvcup-%MSVCUP_ARCH%-windows.zip
    tar xf %~dp0msvcup.zip
    del %~dp0msvcup.zip
) else (
    echo msvcup.exe: already installed
)

set MSVC=msvc-14.44.17.14
set SDK=sdk-10.0.22621.7

%~dp0msvcup.exe install --lock-file %~dp0msvcup.lock --manifest-update-off %MSVC% %SDK%
@if %errorlevel% neq 0 (exit /b %errorlevel%)

@REM @if not exist %~dp0autoenv mkdir %~dp0autoenv
@REM @if not exist %~dp0autoenv\%TARGET_CPU% mkdir %~dp0autoenv\%TARGET_CPU%
%~dp0msvcup.exe autoenv --target-cpu %TARGET_CPU% --out-dir %~dp0autoenv\%TARGET_CPU% %MSVC% %SDK%
@if %errorlevel% neq 0 (exit /b %errorlevel%)

@if not exist %~dp0out mkdir %~dp0out
@if not exist %~dp0out\%TARGET_CPU% mkdir %~dp0out\%TARGET_CPU%
%~dp0autoenv\%TARGET_CPU%\cl /Fo%~dp0out\%TARGET_CPU%\ /Fe%~dp0\out\%TARGET_CPU%\hello.exe %~dp0hello.c
