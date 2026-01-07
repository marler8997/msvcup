@setlocal enabledelayedexpansion

@if %PROCESSOR_ARCHITECTURE%==AMD64 (
    set MSVCUP_ARCH=x86_64
    set HOST_CPU=x64
    set CMAKE_ARCH=x86_64
) else if %PROCESSOR_ARCHITECTURE%==ARM64 (
    set MSVCUP_ARCH=aarch64
    set HOST_CPU=arm64
    set CMAKE_ARCH=arm64
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
@if not exist %~dp0msvcup.exe exit /b 1

set MSVC=msvc-14.44.17.14
set SDK=sdk-10.0.22621.7

%~dp0msvcup.exe install --lock-file %~dp0msvcup.lock --manifest-update-off %MSVC% %SDK%
@if %errorlevel% neq 0 (exit /b %errorlevel%)

%~dp0msvcup.exe autoenv --target-cpu %TARGET_CPU% --out-dir %~dp0autoenv\%TARGET_CPU% %MSVC% %SDK%
@if %errorlevel% neq 0 (exit /b %errorlevel%)


@set CMAKE_VERSION=4.2.1
@set CMAKE=%~dp0cmake-%CMAKE_VERSION%-windows-%CMAKE_ARCH%\bin\cmake.exe
@if not exist %CMAKE% (
    echo cmake: installing...
    curl -L -o cmake.zip https://github.com/Kitware/CMake/releases/download/v%CMAKE_VERSION%/cmake-%CMAKE_VERSION%-windows-%CMAKE_ARCH%.zip
    tar xf cmake.zip
    del cmake.zip
) else (
    echo cmake: already installed
)
@if not exist %CMAKE% exit /b 1


@if not exist %~dp0ninja.exe (
    echo ninja.exe: installing...
    curl -L -o ninja.zip https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip
    tar xf ninja.zip
    del ninja.zip
) else (
    echo ninja.exe: already installed
)
@if not exist %~dp0ninja.exe exit /b 1

@if not exist %~dp0out\%TARGET_CPU%\build.ninja (
    %CMAKE% -S %~dp0 -B %~dp0out/%TARGET_CPU% -DCMAKE_TOOLCHAIN_FILE=%~dp0/autoenv/%TARGET_CPU%/toolchain.cmake -GNinja -DCMAKE_MAKE_PROGRAM=%~dp0ninja.exe
    @if %errorlevel% neq 0 (exit /b %errorlevel%)
)

%~dp0ninja.exe -C %~dp0out\%TARGET_CPU%
