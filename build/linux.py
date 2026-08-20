"""
Package the frozen Linux command line for distribution.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

    python build/linux.py            # tarball + .deb + checksums
    python build/linux.py --tar      # just the tarball
    python build/linux.py --deb      # just the .deb

Expects build/dist/linux/pakt to exist -- run `python build/build.py --cli`
first. Linux only; the Windows artifact is an Inno Setup installer built
from build/installer.iss.

WHY NO INSTALLER PROGRAM
------------------------
Linux has no equivalent of Inno Setup and wants none. Two artifacts
cover the ground:

    pakt-VERSION-linux-x86_64.tar.gz    extract, put it on PATH
    compakt_VERSION_amd64.deb           dpkg/apt, with clean removal

A `curl | sh` installer is deliberately not offered. Piping a remote
script into a shell is the practice this project's whole argument is
against, and recommending it would undercut the tool in front of the
audience most likely to notice.

WHY THE .deb DECLARES A DEPENDENCY
----------------------------------
The Windows build bundles libarchive as a DLL. Linux does not: the
distribution ships a better-maintained copy, and core.decompressor finds
it through libarchive-c's own search. That makes it a real dependency
rather than a bundled one, so it is declared -- otherwise Tier 2 formats
(.rar .cab .deb .rpm and the rest) vanish silently on a clean machine
while working perfectly on the build host.

Both the plain and the time_t-64 package names are accepted, because
Debian renamed it: libarchive13 on bookworm and jammy, libarchive13t64
on trixie and noble.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DIST = os.path.join(HERE, "dist", "linux")
FROZEN = os.path.join(DIST, "pakt")
OUT = os.path.join(HERE, "release")

#: Where the payload lands. A PyInstaller onedir tree is a binary plus
#: an _internal directory that must stay beside it, so it goes to /opt
#: whole and /usr/bin gets a symlink -- the layout every other onedir
#: application on the system already uses.
OPT_DIR = "/opt/compakt"
BIN_LINK = "/usr/bin/pakt"

MAINTAINER = "Rounak Miskin <rounakmiskin@gmail.com>"

DESCRIPTION = """\
 Compakt reads the bytes of every file before compressing it, routing
 each one by what it measurably contains rather than by its extension,
 and packs the result into the .pakt container with authenticated
 encryption and an index written at both ends.
 .
 It opens no network sockets, sends no telemetry and has no update
 checker. This package provides the pakt command line only; the desktop
 window is a Windows product.
"""


def version() -> str:
    """Read the version from the CLI, which is the single source of it."""
    path = os.path.join(REPO, "cli", "main.py")
    with open(path, encoding="utf-8") as handle:
        match = re.search(r'version="pakt ([0-9]+\.[0-9]+\.[0-9]+)"',
                          handle.read())
    if not match:
        sys.exit(f"no version string found in {path}")
    return match.group(1)


def require_frozen() -> None:
    if not os.path.isdir(FROZEN):
        sys.exit("build/dist/linux/pakt does not exist -- run "
                 "`python build/build.py --cli` first")
    if not os.path.exists(os.path.join(FROZEN, "pakt")):
        sys.exit(f"{FROZEN} exists but contains no `pakt` binary")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_tar(ver: str) -> str:
    """A plain tarball: extract it anywhere, run the binary inside."""
    name = f"pakt-{ver}-linux-x86_64"
    out = os.path.join(OUT, f"{name}.tar.gz")

    # Deterministic: fixed ownership, sorted order and a fixed mtime, so
    # the same input produces the same bytes. Compakt offers reproducible
    # archives; its own release artifacts should not be an exception.
    def reset(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = 0
        return info

    with tarfile.open(out, "w:gz") as tar:
        for root, dirs, files in os.walk(FROZEN):
            dirs.sort()
            for entry in sorted(files):
                full = os.path.join(root, entry)
                rel = os.path.relpath(full, FROZEN)
                tar.add(full, arcname=os.path.join(name, rel), filter=reset)
    return out


def build_deb(ver: str) -> str:
    """A .deb installing to /opt with a symlink on PATH."""
    if not shutil.which("dpkg-deb"):
        sys.exit("dpkg-deb not found -- install dpkg-dev")

    staging = os.path.join(OUT, f"deb-{ver}")
    shutil.rmtree(staging, ignore_errors=True)

    payload = os.path.join(staging, OPT_DIR.lstrip("/"))
    os.makedirs(payload, exist_ok=True)
    shutil.copytree(FROZEN, payload, dirs_exist_ok=True)
    os.chmod(os.path.join(payload, "pakt"), 0o755)

    link_dir = os.path.join(staging, os.path.dirname(BIN_LINK).lstrip("/"))
    os.makedirs(link_dir, exist_ok=True)
    os.symlink(os.path.join(OPT_DIR, "pakt"),
               os.path.join(staging, BIN_LINK.lstrip("/")))

    installed_kb = sum(
        os.path.getsize(os.path.join(root, f))
        for root, _, files in os.walk(payload) for f in files) // 1024

    debian = os.path.join(staging, "DEBIAN")
    os.makedirs(debian, exist_ok=True)
    with open(os.path.join(debian, "control"), "w",
              encoding="utf-8", newline="\n") as handle:
        handle.write(
            f"Package: compakt\n"
            f"Version: {ver}\n"
            f"Section: utils\n"
            f"Priority: optional\n"
            f"Architecture: amd64\n"
            f"Depends: libarchive13 | libarchive13t64\n"
            f"Installed-Size: {installed_kb}\n"
            f"Maintainer: {MAINTAINER}\n"
            f"Homepage: https://github.com/Kasanki-Labs/Compakt\n"
            f"Description: archiver that routes files by measuring them\n"
            f"{DESCRIPTION}")

    out = os.path.join(OUT, f"compakt_{ver}_amd64.deb")
    result = subprocess.run(
        ["dpkg-deb", "--root-owner-group", "--build", staging, out],
        capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"dpkg-deb failed:\n{result.stderr}")
    shutil.rmtree(staging, ignore_errors=True)
    return out


def checksums(paths: list[str]) -> str:
    """SHA-256 for every artifact, in the format sha256sum -c expects."""
    out = os.path.join(OUT, "SHA256SUMS")
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        for path in sorted(paths):
            handle.write(f"{sha256(path)}  {os.path.basename(path)}\n")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tar", action="store_true")
    ap.add_argument("--deb", action="store_true")
    args = ap.parse_args()

    if os.name == "nt":
        sys.exit("this packages the Linux build; on Windows the artifact "
                 "is an Inno Setup installer -- see build/installer.iss")

    require_frozen()
    ver = version()
    os.makedirs(OUT, exist_ok=True)
    both = not (args.tar or args.deb)

    made: list[str] = []
    if args.tar or both:
        made.append(build_tar(ver))
    if args.deb or both:
        made.append(build_deb(ver))

    sums = checksums(made)
    print(f"compakt {ver} -- Linux artifacts\n")
    for path in made:
        print(f"  {os.path.basename(path):<40} "
              f"{os.path.getsize(path) / 1048576:6.1f} MB")
    print(f"  {os.path.basename(sums):<40} {len(made)} checksums\n")
    print(f"written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
