"""
Build the Tier 2 native libraries from source.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

    python build/native.py              # fetch, verify, build, install
    python build/native.py --check      # report what is installed now
    python build/native.py --clean      # discard build trees, keep sources

Tier 2 -- .rar, .cab, .cpio, .ar, .deb, .rpm, .lha, .arj, .warc, .Z --
comes from libarchive, which Compakt loads through ctypes from
``app/assets/native``. That directory is not in version control and the
libraries in it are not downloadable binaries: they are compiled here,
from source archives pinned by SHA-256.

WHY BUILD RATHER THAN DOWNLOAD
------------------------------
Compakt's entire claim is that your files never leave your machine, and
that anyone can check that claim. Shipping a prebuilt DLL from a random
host inside a security tool contradicts it: nobody -- including us --
could say what is in that binary. Building from checksummed upstream
source means the supply chain is stated, and a suspicious user can run
this script and compare.

WHY THESE DEPENDENCIES
----------------------
libarchive parses containers itself but hands compressed payloads to
libraries chosen at COMPILE time. That is not a detail; it decides which
formats actually work:

    zlib      .cab (MSZIP), and gzip payloads inside .deb and .rpm
    liblzma   xz payloads -- what nearly every modern .rpm and most
              .deb files use. Without it those containers open and
              then yield nothing.
    libzstd   zstd payloads, used by .deb since Ubuntu 21.10

An earlier build of this project linked zlib alone. It passed its tests,
reported eleven Tier 2 formats, and would have failed on the majority of
real Debian and RPM packages. ``core.decompressor.supported_formats``
now probes for exactly these libraries so the advertised list matches
what the build can finish.

NOT INCLUDED, DELIBERATELY
--------------------------
- **libxml2** (needed by .xar) pulls a large dependency for one rare
  format. .xar is reported as unsupported rather than half-built.
- **bzip2** has no upstream CMake build and its payloads inside Tier 2
  containers are now rare. Tier 1 reads .bz2 and .tar.bz2 through
  Python's own bz2 module regardless.

ON THE xz VERSION
-----------------
Pinned to 5.4.7, the last of the 5.4 series, rather than a 5.6 release.
CVE-2024-3094 -- the backdoor planted in xz 5.6.0 and 5.6.1 -- was
introduced through the release tarball's autotools scripts and targeted
Linux sshd, so a CMake build on Windows was never a path to it. 5.4.7
is nonetheless a branch that never contained the code at all, which is
a cheaper thing to reason about than a fix we would have to trust.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
THIRDPARTY = os.path.join(HERE, "thirdparty")
STAGE = os.path.join(THIRDPARTY, "stage")
NATIVE = os.path.join(REPO, "app", "assets", "native")


class Source:
    """One upstream tarball, pinned by digest."""

    def __init__(self, name: str, version: str, url: str, sha256: str,
                 archive: str, folder: str, provenance: str) -> None:
        self.name = name
        self.version = version
        self.url = url
        self.sha256 = sha256
        self.archive = archive
        self.folder = folder
        self.provenance = provenance

    @property
    def archive_path(self) -> str:
        return os.path.join(THIRDPARTY, self.archive)

    @property
    def source_dir(self) -> str:
        return os.path.join(THIRDPARTY, self.folder)


#: Every digest below was checked against a second, independent source
#: before being written here. A pin nobody verified is decoration.
SOURCES = [
    Source(
        "zlib", "1.3.1",
        "https://zlib.net/fossils/zlib-1.3.1.tar.gz",
        "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
        "zlib-1.3.1.tar.gz", "zlib-1.3.1",
        "matches the checksum published on zlib.net",
    ),
    Source(
        "xz", "5.4.7",
        "https://github.com/tukaani-project/xz/releases/download/"
        "v5.4.7/xz-5.4.7.tar.gz",
        "8db6664c48ca07908b92baedcfe7f3ba23f49ef2476864518ab5db6723836e71",
        "xz-5.4.7.tar.gz", "xz-5.4.7",
        "byte-identical when fetched from github.com and from the "
        "upstream's own tukaani.org -- two independent hosts",
    ),
    Source(
        "zstd", "1.5.6",
        "https://github.com/facebook/zstd/releases/download/"
        "v1.5.6/zstd-1.5.6.tar.gz",
        "8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1",
        "zstd-1.5.6.tar.gz", "zstd-1.5.6",
        "matches the zstd-1.5.6.tar.gz.sha256 asset published alongside "
        "the release, which also carries a PGP signature",
    ),
    Source(
        "libarchive", "3.8.9",
        "https://github.com/libarchive/libarchive/releases/download/"
        "v3.8.9/libarchive-3.8.9.zip",
        "7b20200203d08866b62373dd51417798427ec67852928d71f142bfe578e9ea75",
        "libarchive-3.8.9.zip", "libarchive-3.8.9",
        "matches the checksum published with the GitHub release",
    ),
]

#: CMake settings per project. libarchive is configured last and told to
#: require each codec explicitly: without these it quietly builds
#: whatever it happens to find, which is how a zlib-only library came to
#: be shipped as though it were complete.
CMAKE_ARGS = {
    "zlib": ["-DZLIB_BUILD_EXAMPLES=OFF"],
    "xz": [
        "-DBUILD_SHARED_LIBS=ON",
        "-DENABLE_NLS=OFF",
        "-DXZ_TOOL_XZ=OFF", "-DXZ_TOOL_XZDEC=OFF", "-DXZ_TOOL_LZMADEC=OFF",
        "-DXZ_TOOL_LZMAINFO=OFF", "-DXZ_TOOL_SCRIPTS=OFF",
    ],
    "zstd": [
        "-DZSTD_BUILD_SHARED=ON", "-DZSTD_BUILD_STATIC=OFF",
        "-DZSTD_BUILD_PROGRAMS=OFF", "-DZSTD_BUILD_TESTS=OFF",
        "-DZSTD_LEGACY_SUPPORT=OFF",
    ],
    "libarchive": [
        "-DBUILD_SHARED_LIBS=ON",
        "-DENABLE_ZLIB=ON", "-DENABLE_LZMA=ON", "-DENABLE_ZSTD=ON",
        "-DENABLE_BZip2=OFF", "-DENABLE_LIBXML2=OFF", "-DENABLE_EXPAT=OFF",
        "-DENABLE_LZ4=OFF", "-DENABLE_OPENSSL=OFF", "-DENABLE_LIBB2=OFF",
        # Command line tools and tests are not shipped; only the library.
        "-DENABLE_TAR=OFF", "-DENABLE_CPIO=OFF", "-DENABLE_CAT=OFF",
        "-DENABLE_UNZIP=OFF", "-DENABLE_TEST=OFF",
    ],
}

#: zstd keeps its CMake project in a subdirectory rather than at the root.
CMAKE_SUBDIR = {"zstd": "build/cmake"}

#: What each project must leave behind. Checked after the build, because
#: CMake reports success for a configuration that silently produced a
#: static library when a shared one was asked for.
EXPECTED_DLL = {
    "zlib": ("zlib1.dll", "zlib.dll"),
    "xz": ("liblzma.dll",),
    "zstd": ("libzstd.dll", "zstd.dll"),
    "libarchive": ("archive.dll",),
}


# --------------------------------------------------------------------------
# Toolchain
# --------------------------------------------------------------------------

def find_vcvars() -> str:
    """Locate vcvars64.bat, preferring whatever vswhere reports."""
    vswhere = os.path.join(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if os.path.exists(vswhere):
        try:
            out = subprocess.run(
                [vswhere, "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"],
                capture_output=True, text=True, check=False).stdout.strip()
            if out:
                candidate = os.path.join(
                    out, "VC", "Auxiliary", "Build", "vcvars64.bat")
                if os.path.exists(candidate):
                    return candidate
        except OSError:
            pass

    for root in (r"C:\Program Files\Microsoft Visual Studio",
                 r"C:\Program Files (x86)\Microsoft Visual Studio"):
        if not os.path.isdir(root):
            continue
        for base, _dirs, files in os.walk(root):
            if "vcvars64.bat" in files:
                return os.path.join(base, "vcvars64.bat")
    sys.exit("could not find vcvars64.bat -- install Visual Studio Build "
             "Tools with the C++ workload")


def find_cmake(vcvars: str) -> str:
    """Prefer a cmake on PATH; fall back to the one Visual Studio ships."""
    found = shutil.which("cmake")
    if found:
        return found
    vs_root = vcvars.split(os.sep + "VC" + os.sep)[0]
    bundled = os.path.join(
        vs_root, "Common7", "IDE", "CommonExtensions", "Microsoft",
        "CMake", "CMake", "bin", "cmake.exe")
    if os.path.exists(bundled):
        return bundled
    sys.exit("could not find cmake")


def msvc_run(vcvars: str, command: str, cwd: str,
             extra_include: str = "") -> None:
    """
    Run a command inside a configured MSVC environment.

    vcvars64.bat sets several dozen variables and cannot be sourced from
    Python, so the command has to be chained after it in one cmd.exe
    session. Passing that as an argument does not survive: every path
    involved contains spaces, and between Python's Windows argument
    quoting and cmd.exe's own rules the inner quotes arrive escaped and
    cmd reports the compiler path itself as an unrecognised command.

    Writing a batch file and running that has no quoting layer to lose.
    """
    os.makedirs(cwd, exist_ok=True)
    script = os.path.join(cwd, "_compakt_build.bat")
    with open(script, "w", encoding="ascii") as fh:
        fh.write("@echo off\n")
        fh.write(f'call "{vcvars}" >nul\n')
        fh.write("if errorlevel 1 exit /b 1\n")
        if extra_include:
            # rc.exe honours INCLUDE. Reaching it through the
            # environment rather than through -DCMAKE_RC_FLAGS avoids
            # threading a path that contains spaces through cmd, cmake
            # and nmake quoting in turn.
            fh.write(f'set "INCLUDE=%INCLUDE%;{extra_include}"\n')
        fh.write(f"{command}\n")
        fh.write("exit /b %errorlevel%\n")
    try:
        result = subprocess.run([script], cwd=cwd, shell=False)
    finally:
        if os.path.exists(script):
            os.remove(script)
    if result.returncode != 0:
        sys.exit(f"command failed ({result.returncode}): {command}")


# --------------------------------------------------------------------------
# Fetch and verify
# --------------------------------------------------------------------------

def digest_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def fetch(source: Source) -> None:
    """Download if absent, then verify. A mismatch is fatal, never a warning."""
    os.makedirs(THIRDPARTY, exist_ok=True)
    if not os.path.exists(source.archive_path):
        print(f"  downloading {source.archive} ...")
        with urllib.request.urlopen(source.url, timeout=180) as response:
            data = response.read()
        with open(source.archive_path, "wb") as fh:
            fh.write(data)

    actual = digest_of(source.archive_path)
    if actual != source.sha256:
        # Leave the file for inspection. Deleting it destroys the only
        # evidence of what arrived.
        sys.exit(
            f"CHECKSUM MISMATCH for {source.archive}\n"
            f"  expected {source.sha256}\n"
            f"  actual   {actual}\n"
            f"Refusing to build. The file is left in place so it can be "
            f"examined.")
    print(f"  {source.name}-{source.version} verified ({source.sha256[:16]}...)")


def unpack(source: Source) -> None:
    if os.path.isdir(source.source_dir):
        return
    print(f"  extracting {source.archive} ...")
    if source.archive.endswith(".zip"):
        with zipfile.ZipFile(source.archive_path) as zf:
            zf.extractall(THIRDPARTY)
    else:
        with tarfile.open(source.archive_path) as tf:
            tf.extractall(THIRDPARTY)
    if not os.path.isdir(source.source_dir):
        sys.exit(f"{source.archive} did not unpack to {source.folder}")


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def build(source: Source, vcvars: str, cmake: str) -> None:
    src = source.source_dir
    sub = CMAKE_SUBDIR.get(source.name)
    if sub:
        src = os.path.join(src, sub.replace("/", os.sep))
    work = os.path.join(THIRDPARTY, f"build-{source.name}")
    os.makedirs(work, exist_ok=True)

    args = [
        f'"{cmake}"', f'-S "{src}"', f'-B "{work}"',
        '-G "NMake Makefiles"',
        "-DCMAKE_BUILD_TYPE=Release",
        f'-DCMAKE_INSTALL_PREFIX="{STAGE}"',
        f'-DCMAKE_PREFIX_PATH="{STAGE}"',
    ] + CMAKE_ARGS.get(source.name, [])

    # zstd's DLL carries a version resource whose .rc includes zstd.h,
    # but its CMake build never puts lib/ on the resource compiler's
    # search path. Without this the build dies at 'cannot open include
    # file zstd.h' after compiling the entire library successfully.
    extra_include = (os.path.join(source.source_dir, "lib")
                     if source.name == "zstd" else "")

    print(f"\nbuilding {source.name} {source.version}")
    msvc_run(vcvars, " ".join(args), cwd=THIRDPARTY,
             extra_include=extra_include)
    msvc_run(vcvars, f'"{cmake}" --build "{work}" --config Release',
             cwd=THIRDPARTY, extra_include=extra_include)
    msvc_run(vcvars, f'"{cmake}" --install "{work}" --config Release',
             cwd=THIRDPARTY, extra_include=extra_include)

    names = EXPECTED_DLL[source.name]
    if not any(_locate(name) for name in names):
        sys.exit(
            f"{source.name} built but produced none of {names}. A shared "
            f"library was requested; check the CMake output above for a "
            f"silent fallback to a static build.")


def _locate(name: str) -> str | None:
    for base, _dirs, files in os.walk(STAGE):
        for candidate in files:
            if candidate.lower() == name.lower():
                return os.path.join(base, candidate)
    return None


def install() -> list[str]:
    """Copy the built DLLs to where core.decompressor looks for them."""
    os.makedirs(NATIVE, exist_ok=True)
    placed = []
    for names in EXPECTED_DLL.values():
        for name in names:
            found = _locate(name)
            if found:
                shutil.copy2(found, os.path.join(NATIVE, name))
                placed.append(name)
                break
    return placed


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def check() -> int:
    """Ask the built library what it can actually do."""
    sys.path.insert(0, REPO)
    for name in ("core.decompressor", "libarchive", "libarchive.ffi"):
        sys.modules.pop(name, None)

    from core.decompressor import supported_formats

    formats = supported_formats()
    if not formats["tier2"] and not formats["tier2_partial"]:
        print("libarchive did NOT load from app/assets/native")
        return 1

    print(f"linked against : {', '.join(formats['native']) or 'nothing'}")
    print(f"fully supported: {' '.join(formats['tier2'])}")
    for line in formats["tier2_partial"]:
        print(f"partial        : {line}")
    for line in formats["tier2_unavailable"]:
        print(f"unavailable    : {line}")
    return 0


def clean() -> None:
    for name in os.listdir(THIRDPARTY) if os.path.isdir(THIRDPARTY) else []:
        if name.startswith("build-") or name == "stage":
            shutil.rmtree(os.path.join(THIRDPARTY, name), ignore_errors=True)
            print(f"removed {name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="report what the installed library supports")
    ap.add_argument("--clean", action="store_true",
                    help="remove build trees, keep verified sources")
    args = ap.parse_args()

    if args.clean:
        clean()
        return 0
    if args.check:
        return check()

    if os.name != "nt":
        sys.exit("this script builds the Windows libraries; on Linux the "
                 "distribution packages of libarchive are used instead")

    vcvars = find_vcvars()
    cmake = find_cmake(vcvars)
    print(f"toolchain: {vcvars}")
    print(f"cmake:     {cmake}\n")

    print("verifying sources")
    for source in SOURCES:
        fetch(source)
        unpack(source)

    for source in SOURCES:
        build(source, vcvars, cmake)

    placed = install()
    print(f"\ninstalled to app/assets/native: {', '.join(placed)}")
    print()
    return check()


if __name__ == "__main__":
    sys.exit(main())
