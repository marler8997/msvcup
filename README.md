# msvcup

A standalone tool for installing the MSVC toolchain and Windows SDK without Visual Studio.

## Why?

The Visual Studio Installer manages thousands of components, modifies the registry, and can take hours to configure. msvcup treats the toolchain as a versioned asset rather than global system state. The build environment is defined by code, not a GUI.

- **Fast**: Runs in milliseconds when already installed. Put it at the start of every build script.
- **Reproducible**: Lock file ensures everyone gets the same toolchain.
- **Isolated**: Every package is installed to its own versioned directory. No registry modifications. No conflicts.
- **Cross-compilation**: Target x64, arm64, or x86 out of the box.
- **Minimal**: Download only what's needed to get a working native toolchain/SDK.

## Quick Start

- for CMake projects, see [examples/cmake/build.bat](examples/cmake/build.bat)
- for "handmade" style projects, see [examples/handmade/build.bat](examples/handmade/build.bat)

These examples contain batch scripts that download msvcup, install an MSVC/SDK, and then compile "hello.c". The cmake `build.bat` is also project agnostic, meaning it can be used to build most CMAKE projects with no changes.

After downloading msvcup, the example will install the toolchain and an SDK with a command like this:

```batch
> msvcup install msvc autoenv msvc-14.44.17.14 sdk-10.0.22621.7
```

That command would install the 3 packages "autoenv", "msvc-14.44.17.14" and "sdk-10.0.22621.7" to the "msvc" directory. It also creates a lock file named "msvc.lock" alongside that msvc directory. This lock file contains all the packages and payloads along with URL's and hashes for everything msvcup installs. This lock file is meant to be commited to source control and its content is a hashable representation of all the content msvcup installs along with the entirety of all info msvcup requires to download everything.

Use the `msvcup list` command to query the available packages/versions. Also note that msvcup caches everything it downloads into a global directory. Deleting the install directory and re-installing should require no network access.

## Visual Studio Command Prompts

The install directory will include the following 4 vcvars files:

- `vcvars-x64.bat`
- `vcvars-arm64.bat`
- `vcvars-x86.bat`
- `vcvars-arm.bat`

These scripts update the `INCLUDE`, `PATH` and `LIB` environment variables which is what transforms your shell into a "Visual Studio Command Prompt".

Note that if you include the "autoenv" package, your install directory will include `autoenv/$ARCH` subdirectories which enables using the toolchain/sdk outside a special command prompt.  It works by installing wrapper executables (`cl.exe`, `link.exe`, etc) that will initialize the environment variables before forwarding to the underlying executables, and also includes toolchain files for CMake/Zig.

## Additional Features

- **Install metadata**: Every installed file is tracked in `<package>/install`. This allows msvcup to detect file conflicts and allows the user to query which component(s) installed which files.
- **Download cache**: Packages are cached in `C:\msvcup\cache`. Failed installs can be retried without network access.

## Acknowledgements

Special thanks to Mārtiņš Možeiko (@mmozeiko) for his original [Python MSVC installer](https://gist.github.com/mmozeiko/7f3162ec2988e81e56d5c4e22cde9977), which served as a vital reference for this project.
