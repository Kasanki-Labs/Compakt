"""
Freeze Compakt into distributable binaries.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Produces two executables, because they are genuinely different
programs sharing one library:

    Compakt.exe   windowed, no console  -- the desktop application
    pakt.exe      console                -- the command line

    python build/build.py               # build both
    python build/build.py --gui         # just the window
    python build/build.py --cli         # just the command line
    python build/build.py --clean       # remove build output

UPX IS NEVER ENABLED. Packed executables are the single largest
trigger for antivirus heuristics, because malware uses the same
packers. Compakt is already at elevated risk -- it reads and writes
files in bulk, ships cryptography, and carries a compiled native
module -- so the few megabytes UPX would save are not worth a false
positive on a security tool.

The engine is optional. If `core/compressor` is present, compiled or
not, it is bundled and the build is a full release; if it is absent the
binary still works using the open reference encoder, which is the whole
point of the public repository being self-sufficient.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DIST = os.path.join(HERE, "dist")
WORK = os.path.join(HERE, "work")

ICON = os.path.join(REPO, "app", "assets", "compakt.ico")

#: Data files that must travel with the binary.
ASSETS = [
    ("app/assets/compakt-sharp.json", "app/assets"),
    ("app/assets/compakt.ico", "app/assets"),
    ("app/assets/kasanki-mark.png", "app/assets"),
    ("app/assets/compakt-mark.png", "app/assets"),
]

#: Where the Tier 2 shared libraries live, relative to the repository.
#:
#: These are NOT optional decoration. core.decompressor finds libarchive
#: by looking for app/assets/native/ next to the executable, so a frozen
#: build that omits this directory silently drops every Tier 2 format --
#: .rar, .cab, .cpio, .ar, .deb, .rpm and the rest -- while the source
#: tree it was built from handles them perfectly. That divergence
#: between "works here" and "works for a user" is exactly the failure
#: worth wiring into the build rather than remembering to copy by hand.
#:
#: Every file in the directory is collected, not a fixed list: libarchive
#: is linked against its dependencies (zlib today, more later) and those
#: must sit beside it. ctypes loads a path containing a separator with
#: LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, so a dependency next to archive.dll
#: resolves; one left behind does not, and the failure appears only at
#: the moment a user opens a .cab.
NATIVE_DIR = os.path.join(REPO, "app", "assets", "native")

#: Imported lazily or through ctypes, so PyInstaller's static analysis
#: does not always find them.
HIDDEN = [
    "zstandard", "brotli", "py7zr", "pyzipper", "pycdlib",
    "cryptography.hazmat.primitives.kdf.argon2",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "bcj", "pyppmd", "inflate64", "Cryptodome",
]

#: Pulled in by the toolchain but never used at runtime. Excluding them
#: is worth several megabytes and removes code we would otherwise be
#: shipping without reason.
EXCLUDE = [
    "matplotlib", "numpy", "scipy", "pandas", "PyQt5", "PyQt6", "PySide2",
    "PySide6", "IPython", "jupyter", "pytest", "Cython",
]

#: NOT excluded, though it is tempting: PyInstaller's own setuptools
#: hook aliases `distutils`, and excluding either makes the build abort
#: with "Target module already imported as ExcludedModule". The few
#: megabytes are not worth a broken build.


def native_libraries() -> list[str]:
    """Every shared library in app/assets/native, in a stable order."""
    if not os.path.isdir(NATIVE_DIR):
        return []
    return sorted(
        os.path.join(NATIVE_DIR, name)
        for name in os.listdir(NATIVE_DIR)
        if name.lower().endswith((".dll", ".so", ".dylib"))
        or ".so." in name.lower())


def engine_present() -> str | None:
    for pattern in ("compressor*.pyd", "compressor*.so", "compressor.py"):
        found = glob.glob(os.path.join(REPO, "core", pattern))
        if found:
            return found[0]
    return None


def _common(name: str, entry: str, windowed: bool) -> list[str]:
    sep = ";" if os.name == "nt" else ":"
    argv = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", name,
        "--distpath", DIST,
        "--workpath", WORK,
        "--specpath", WORK,
        "--noupx",                       # see the module docstring
        "--onedir",
    ]
    if windowed:
        argv += ["--windowed"]           # suppresses the console window
    if os.path.exists(ICON):
        argv += ["--icon", ICON]
    for src, dest in ASSETS:
        full = os.path.join(REPO, src.replace("/", os.sep))
        if os.path.exists(full):
            argv += ["--add-data", f"{full}{sep}{dest}"]
    for full in native_libraries():
        argv += ["--add-binary", f"{full}{sep}app/assets/native"]
    for mod in HIDDEN:
        argv += ["--hidden-import", mod]
    for mod in EXCLUDE:
        argv += ["--exclude-module", mod]
    # GUI only. Linux installs no Tk stack at all (see requirements.txt),
    # so asking PyInstaller to collect tkinterdnd2 there aborts the build
    # for a package the console binary never imports.
    if windowed:
        argv += ["--collect-submodules", "tkinterdnd2"]
    argv.append(os.path.join(REPO, entry))
    return argv


def run(argv: list[str]) -> None:
    print("  " + " ".join(argv[:8]) + " ...")
    result = subprocess.run(argv, cwd=REPO)
    if result.returncode != 0:
        sys.exit(f"build failed with exit code {result.returncode}")


def build_gui() -> None:
    print("building Compakt.exe (windowed)")
    run(_common("Compakt", "compakt.py", windowed=True))


def build_cli() -> None:
    print("building pakt.exe (console)")
    run(_common("pakt", "pakt.py", windowed=False))


def report(built: tuple[str, ...] = ("Compakt", "pakt")) -> None:
    """
    Summarise what was produced.

    Only the targets built in THIS run are judged. Reporting on a
    leftover directory from an earlier build produces a warning about a
    bundle nobody just made, which reads as a failure of the run that
    did succeed.
    """
    expected = {os.path.basename(p) for p in native_libraries()}
    for name in built:
        folder = os.path.join(DIST, name)
        if not os.path.isdir(folder):
            continue
        total = sum(
            os.path.getsize(os.path.join(base, f))
            for base, _d, files in os.walk(folder) for f in files)
        exe = os.path.join(folder, f"{name}.exe")
        print(f"  {name:<9} {total / 1024 / 1024:>6.1f} MB"
              f"   exe present: {os.path.exists(exe)}")

        # PyInstaller silently ignores an --add-binary whose source has
        # gone missing, and the resulting binary looks entirely healthy
        # until someone drops a .cab on it. Check rather than trust.
        if not expected:
            continue
        landed = {
            f for base, _d, files in os.walk(folder) for f in files
            if os.path.basename(base).lower() == "native"
        }
        missing = expected - landed
        if missing:
            print(f"            WARNING: {', '.join(sorted(missing))} did "
                  f"not reach the bundle; tier 2 will be dead in it")
        else:
            print(f"            tier 2 natives bundled: "
                  f"{', '.join(sorted(landed))}")


def clean() -> None:
    for path in (DIST, WORK):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            print(f"removed {path}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gui", action="store_true")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--clean", action="store_true")
    args = ap.parse_args()

    if args.clean:
        clean()
        return 0

    engine = engine_present()
    if engine:
        kind = "compiled" if engine.endswith((".pyd", ".so")) else "SOURCE"
        print(f"routing engine: {os.path.basename(engine)} ({kind})")
        if kind == "SOURCE":
            print("  WARNING: bundling the engine as .py ships readable "
                  "source. Run compakt-engine/build_engine.py first.")
    else:
        print("routing engine: absent -- building with the reference "
              "encoder, which is a valid open-source build")

    native = native_libraries()
    if native:
        print(f"tier 2 natives: {', '.join(os.path.basename(p) for p in native)}")
    else:
        print("tier 2 natives: NONE -- this build will open Tier 1 formats "
              "only.\n  .rar .cab .cpio .ar .deb .rpm and the rest will be "
              "refused with\n  a message naming the missing library. Run "
              "build/native.py to build them.")

    # Linux ships the command line only. The window is a Windows product:
    # freezing customtkinter/tkinterdnd2 on Linux drags in X11, fontconfig
    # and a bundled Tcl/Tk for a binary nobody would run interactively on
    # a server, which is where the Linux build is going.
    gui_supported = os.name == "nt"
    if args.gui and not gui_supported:
        sys.exit("--gui is Windows-only; Linux builds the pakt command "
                 "line. Run without --gui, or with --cli.")

    both = not (args.gui or args.cli)
    if both and not gui_supported:
        print("platform: not Windows -- building the command line only")

    built: list[str] = []
    if (args.gui or both) and gui_supported:
        build_gui()
        built.append("Compakt")
    if args.cli or both:
        build_cli()
        built.append("pakt")

    print("\noutput:")
    report(tuple(built))
    return 0


if __name__ == "__main__":
    sys.exit(main())
