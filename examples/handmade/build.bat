@setlocal

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
    curl -L -o %~dp0msvcup.zip https://github.com/marler8997/msvcup/releases/download/v2026_02_21/msvcup-%MSVCUP_ARCH%-windows.zip
    tar -C%~dp0 -xf %~dp0msvcup.zip
    del %~dp0msvcup.zip
) else (
    echo msvcup.exe: already installed
)
@if not exist %~dp0msvcup.exe exit /b 1

%~dp0msvcup.exe install %~dp0msvc --manifest-update-off autoenv msvc-14.44.17.14 sdk-10.0.22621.7
@if %errorlevel% neq 0 (exit /b %errorlevel%)

@if not exist %~dp0out mkdir %~dp0out
@if not exist %~dp0out\%TARGET_CPU% mkdir %~dp0out\%TARGET_CPU%
%~dp0msvc\autoenv\%TARGET_CPU%\cl /Fo%~dp0out\%TARGET_CPU%\ /Fe%~dp0out\%TARGET_CPU%\hello.exe %~dp0hello.c
