"""
Verify the build interpreter before it is trusted with a release.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Run by build/linux.Dockerfile at image build time, so a defective
interpreter fails the image rather than the release.

Every module checked here is an OPTIONAL CPython extension. When its
headers are absent at compile time, `configure` notes the fact, carries
on, and produces an interpreter quietly lacking that module. Nothing
fails. The gap only shows up later, as a format Compakt no longer
supports:

    _zstd     Python 3.14's stdlib compression.zstd. py7zr imports it,
              so without it py7zr will not import and .7z silently
              disappears from the supported list.
    _lzma     .xz, .tar.xz, and the payload of most modern .rpm files
    _bz2      .bz2 and .tar.bz2
    zlib      .gz, and the MSZIP payload inside .cab
    _ssl      the cryptography stack
    _ctypes   the libarchive binding, and with it all of Tier 2

A shared library is separately required: PyInstaller refuses to freeze
an interpreter built without --enable-shared.
"""

from __future__ import annotations

import importlib.util
import sys
import sysconfig

REQUIRED = ["_zstd", "_lzma", "_bz2", "zlib", "_ssl", "_ctypes"]


def main() -> int:
    print(f"interpreter: CPython {sys.version.split()[0]}")

    shared = bool(sysconfig.get_config_var("Py_ENABLE_SHARED"))
    print(f"  shared library     : {'yes' if shared else 'NO'}")

    missing = []
    for name in REQUIRED:
        present = importlib.util.find_spec(name) is not None
        print(f"  {name:<18} : {'present' if present else 'MISSING'}")
        if not present:
            missing.append(name)

    if not shared:
        print("\nFAIL: built without --enable-shared; PyInstaller cannot "
              "freeze this interpreter.")
        return 1

    if missing:
        print(f"\nFAIL: built without {missing}. Install the matching "
              f"-devel packages and rebuild.")
        return 1

    print("\nOK: interpreter is fit to build a release.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
