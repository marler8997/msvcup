# msvcup

A standalone tool for installing the MSVC toolchain and Windows SDK without Visual Studio.

## Why?

The Visual Studio Installer manages thousands of components, modifies the registry, and can take hours to configure. msvcup treats the toolchain as a versioned asset rather than global system state. The build environment is defined by code, not a GUI.

- **Fast**: Runs in milliseconds when already installed. Put it at the start of every build script.
- **Reproducible**: Lock file ensures everyone gets the same toolchain.
- **Hermetic**: Every package is installed to its own versioned directory. No registry modifications. No conflicts.
- **Cross-compilation**: Target x64, arm64, or x86 out of the box.
- **Minimal**: Download only what's needed to get a working native toolchain/SDK.

## Quick Start

- for CMake projects, see [example/cmake/build.bat](example/cmake/build.bat)
- for "handmade" style projects, see [example/handmade/build.bat](example/handmade/build.bat)

These examples contain batch scripts that download msvcup, install an MSVC/SDK, and then compile "hello.c".

After downloading msvcup, the example will install the toolchain and an SDK with a command like this:

```batch
> msvcup install --lock-file msvcup.lock msvc-14.44.17.14 sdk-10.0.22621.7
```

All packages are installed to `C:\msvcup` so this would create the following directories:

- `C:\msvcup\msvc-14.44.17.14` and
- `C:\msvcup\sdk-10.0.22621.7`

You can query the latest packages/versions using `msvcup list`.

## Visual Studio Command Prompts

Each package includes a vcvars script for each target architecture:

- `vcvars-x64.bat`
- `vcvars-arm64.bat`
- `vcvars-x86.bat`
- `vcvars-arm.bat`

These scripts add extra environment variables like a "Visual Studio Command Prompt" would.

msvcup can also create an "automatic environment" directory which enables using the toolchain/sdk outside a special command prompt, e.g.

```batch
> msvcup autoenv --target-cpu x64 --out-dir autoenv-x64 msvc-14.44.17.14 sdk-10.0.22621.7
```

This generates a directory with wrapper executables (`cl.exe`, `link.exe`, etc) that can be invoked in a normal command prompt along with toolchain files for CMake/Zig.

## Additional Features

- **Lock file**: All components and URLs are saved before install, enabling reproducible builds via source control.
- **Install metadata**: Every installed file is tracked in `<package>/install`. This allows msvcup to detect file conflicts and allows the user to query which component(s) installed which files.
- **Download cache**: Packages are cached in `C:\msvcup\cache`. Failed installs can be retried without network access.

## Acknowledgements

Special thanks to Mārtiņš Možeiko (@mmozeiko) for his original [Python MSVC installer](https://gist.github.com/mmozeiko/7f3162ec2988e81e56d5c4e22cde9977), which served as a vital reference for this project.
