"""
Universal local extraction manager.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Reads every archive format Compakt supports and extracts it through one
shared safety policy (:mod:`core.safety`). Format is decided by reading
the bytes, not by trusting the extension — a `.zip` renamed to `.txt`
still opens, and a file claiming to be `.zip` that is not gets refused
rather than mangled.

Everything here runs IN-PROCESS. No handler shells out to an external
binary. That is a deliberate constraint, not an accident of
implementation: launching whatever `unrar.exe` happens to sit earliest
on PATH would be both a hole in the air-gapped guarantee and a genuine
hijack vector, since that binary would run with Compakt's privileges the
moment somebody drops a `.rar` on the window.

TIERS
-----
**Tier 1** needs no native binaries and always works::

    .pakt                                    ours
    .zip  (store/deflate/bzip2/lzma)         stdlib zipfile
    .zip  (ZipCrypto, WinZip AES-256)        pyzipper
    .7z   (incl. AES-256, encrypted headers) py7zr
    .tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst
    .gz, .bz2, .xz, .lzma, .zst, .br         single streams
    .iso                                     pycdlib

**Tier 2** needs a bundled ``libarchive`` shared library and adds
roughly forty more read-only formats: `.rar` (RAR4 and RAR5), `.cab`,
`.lha`, `.cpio`, `.ar`, `.deb`, `.rpm`, `.xar`, `.warc`, `.arj`, `.Z`.
When the library is absent, Tier 2 formats are detected and refused
with a message naming what is missing — never silently mis-handled.

Writing `.rar` is never offered. RARLAB licenses no compressor.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import posixpath
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from core.safety import (
    BombGuard,
    ExtractLimits,
    SecurityError,
    check_link_target,
    safe_target,
    sanitise_member_path,
)

__all__ = [
    "ArchiveEntry", "ArchiveInfo", "ExtractResult", "ExtractLimits",
    "SecurityError", "UnsupportedArchive", "identify", "list_entries",
    "extract", "supported_formats",
]

_READ_CHUNK = 1 << 20


class UnsupportedArchive(Exception):
    """The file is not an archive this build can open."""


# --------------------------------------------------------------------------
# Optional backends
# --------------------------------------------------------------------------

def _try(name: str):
    try:
        return __import__(name)
    except Exception:
        return None


_py7zr = _try("py7zr")
_pyzipper = _try("pyzipper")
_pycdlib = _try("pycdlib")
_zstd = _try("zstandard")
_brotli = _try("brotli")


def _bundled_libarchive() -> Optional[str]:
    """Locate the shared library shipped alongside the application."""
    import sys
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Only this platform's library. Accepting any of the three meant a
    # Linux build that had wrongly bundled the Windows DLL would find
    # `archive.dll`, point LIBARCHIVE at it, and lose every Tier 2 format
    # -- while the system libarchive sat there, loadable, unused. The
    # build no longer bundles foreign libraries; this is the second lock.
    if sys.platform == "win32":
        names = ("archive.dll",)
    elif sys.platform == "darwin":
        names = ("libarchive.dylib",)
    else:
        names = ("libarchive.so",)

    for name in names:
        candidate = os.path.join(base, "app", "assets", "native", name)
        if os.path.exists(candidate):
            return candidate
    return None


def _libarchive():
    """
    Load libarchive lazily, preferring the copy we ship.

    libarchive-c is a ctypes binding and reads the LIBARCHIVE
    environment variable to find the shared library. Left to itself it
    searches the system, finds nothing on a normal Windows machine, and
    fails only at the point of use -- importing the package succeeds
    either way, which is why the probe has to touch the FFI layer.

    An explicit LIBARCHIVE set by the user always wins: someone who has
    deliberately pointed at their own build should get it.
    """
    if not os.environ.get("LIBARCHIVE"):
        bundled = _bundled_libarchive()
        if bundled:
            os.environ["LIBARCHIVE"] = bundled
    try:
        import libarchive
        import libarchive.ffi                          # noqa: F401
        return libarchive
    except Exception:
        return None


# --------------------------------------------------------------------------
# Normalised entries
# --------------------------------------------------------------------------

@dataclass
class ArchiveEntry:
    """One member of an archive, in a form independent of its format."""

    path: str
    size: int = 0
    is_dir: bool = False
    is_symlink: bool = False
    compressed_size: int = 0
    mtime: Optional[float] = None
    mode: int = 0
    link_target: str = ""


@dataclass
class ArchiveInfo:
    format: str
    tier: int
    entry_count: Optional[int] = None
    encrypted: bool = False
    note: str = ""


@dataclass
class ExtractResult:
    destination: str
    format: str
    entries_written: int = 0
    bytes_written: int = 0
    skipped: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Identification -- by content, never by extension
# --------------------------------------------------------------------------

_SIGNATURES: tuple[tuple[int, bytes, str, int], ...] = (
    (0, b"PAKT\x1a\x0a", "pakt", 1),
    (0, b"PK\x03\x04", "zip", 1),
    (0, b"PK\x05\x06", "zip", 1),
    (0, b"PK\x07\x08", "zip", 1),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", 1),
    (0, b"\x1f\x8b", "gzip", 1),
    (0, b"BZh", "bzip2", 1),
    (0, b"\xfd7zXZ\x00", "xz", 1),
    (0, b"\x5d\x00\x00", "lzma", 1),
    (0, b"\x28\xb5\x2f\xfd", "zstd", 1),
    # --- tier 2, libarchive ---
    (0, b"Rar!\x1a\x07\x00", "rar", 2),
    (0, b"Rar!\x1a\x07\x01\x00", "rar", 2),
    (0, b"MSCF", "cab", 2),
    (0, b"!<arch>", "ar", 2),
    (0, b"\x1f\x9d", "compress", 2),
    (0, b"070701", "cpio", 2),
    (0, b"070707", "cpio", 2),
    (2, b"-lh", "lha", 2),
    (0, b"\x60\xea", "arj", 2),
    (0, b"xar!", "xar", 2),
    # .rpm and .warc were advertised as supported for some time while
    # having no entry here at all, so identify() rejected them before
    # any handler could run -- "not an archive format Compakt
    # recognises" for a file the bundled library reads perfectly.
    # A format missing from this table is unreachable no matter what
    # libarchive was compiled with.
    (0, b"\xed\xab\xee\xdb", "rpm", 2),
    (0, b"WARC/", "warc", 2),
)

#: Formats with no magic number at all, resolved by extension as a last
#: resort. Brotli genuinely has no signature; this is the one place an
#: extension is load-bearing, and it is stated rather than hidden.
_EXT_ONLY = {".br": ("brotli", 1)}


def identify(path: str | os.PathLike[str]) -> ArchiveInfo:
    """Determine an archive's format by reading its header."""
    path = os.fspath(path)
    try:
        with open(path, "rb") as fh:
            head = fh.read(66_000)
    except OSError as exc:
        raise UnsupportedArchive(
            f"cannot read {path}: {exc.strerror or exc}") from None

    for offset, sig, name, tier in _SIGNATURES:
        if head[offset:offset + len(sig)] == sig:
            return _refine(path, head, name, tier)

    # tar's magic sits deep inside the first header block.
    if len(head) >= 262 and head[257:262] in (b"ustar", b"ustar"):
        return ArchiveInfo("tar", 1)

    # ISO 9660 carries "CD001" at 0x8001, past a 32 KiB system area.
    try:
        with open(path, "rb") as fh:
            fh.seek(0x8001)
            if fh.read(5) == b"CD001":
                return ArchiveInfo("iso", 1)
    except OSError:
        pass

    ext = os.path.splitext(path)[1].lower()
    if ext in _EXT_ONLY:
        name, tier = _EXT_ONLY[ext]
        return ArchiveInfo(name, tier,
                           note="identified by extension; this format has "
                                "no magic number")

    raise UnsupportedArchive(
        f"{os.path.basename(path)} is not an archive format Compakt "
        f"recognises")


def _refine(path: str, head: bytes, name: str, tier: int) -> ArchiveInfo:
    """Distinguish compressed tars from plain single streams."""
    if name in ("gzip", "bzip2", "xz", "zstd"):
        if _is_tar_inside(path, name):
            return ArchiveInfo(f"tar.{name}", 1)
    if name == "zip":
        return ArchiveInfo("zip", 1, encrypted=_zip_is_encrypted(path))
    if name == "7z":
        return ArchiveInfo("7z", 1, encrypted=_sevenzip_is_encrypted(path))
    return ArchiveInfo(name, tier)


def _is_tar_inside(path: str, name: str) -> bool:
    """Peek one tar header block through the outer compressor."""
    openers = {
        "gzip": lambda: gzip.open(path, "rb"),
        "bzip2": lambda: bz2.open(path, "rb"),
        "xz": lambda: lzma.open(path, "rb"),
    }
    if name == "zstd":
        if _zstd is None:
            return False
        def _open():
            fh = open(path, "rb")
            return _zstd.ZstdDecompressor().stream_reader(fh)
        openers["zstd"] = _open
    try:
        with openers[name]() as stream:
            block = stream.read(512)
        return len(block) >= 262 and block[257:262] == b"ustar"
    except Exception:
        return False


def _zip_is_encrypted(path: str) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return any(i.flag_bits & 0x1 for i in zf.infolist())
    except Exception:
        return False


def _sevenzip_is_encrypted(path: str) -> bool:
    if _py7zr is None:
        return False
    try:
        return bool(_py7zr.is_7zfile(path)) and _py7zr.SevenZipFile(
            path, mode="r").needs_password()
    except Exception:
        return True                                   # encrypted headers


# --------------------------------------------------------------------------
# What Tier 2 can ACTUALLY do in this build
# --------------------------------------------------------------------------
#
# "libarchive loaded" and "this format decodes" are not the same claim.
# Roughly half of libarchive's readers hand their payload to an external
# compression library that is chosen at COMPILE time, so two builds of
# the identical version support different format sets. A build without
# liblzma reads the container of a modern .deb perfectly and then cannot
# decompress a single file inside it.
#
# Advertising the full list whenever the library loads was therefore a
# promise this code could not keep. libarchive will say what it was
# built with, so it is asked rather than assumed.

#: format -> (needs any one of, prefers any one of, note)
#:
#: ``needs`` empty means libarchive decodes it internally with no
#: external dependency. ``prefers`` names the filters that real-world
#: files of that format actually use today: missing them leaves the
#: format working on older payloads only, which is reported as partial
#: rather than counted as full support.
_TIER2_SPEC: tuple[tuple[str, tuple[str, ...], tuple[str, ...], str], ...] = (
    ("rar",      (),                            (), ""),
    ("lha",      (),                            (), ""),
    ("cpio",     (),                            (), ""),
    ("ar",       (),                            (), ""),
    ("warc",     (),                            (), ""),
    ("arj",      (),                            (), ""),
    ("compress", (),                            (), ""),
    ("deb",      (),                            (), ""),
    ("cab",      ("zlib",),                     (),
     "MSZIP cabinets are deflate; without zlib only LZX ones open"),
    ("xar",      ("libxml2", "expat"),          (),
     "the table of contents is XML and needs a parser"),
    # .rpm is the one format here whose payload libarchive genuinely
    # decompresses itself: the rpm filter strips the package header and
    # then applies gzip, xz or zstd to the cpio payload underneath.
    # Nearly every distribution ships xz, so without liblzma the
    # package opens and yields nothing.
    ("rpm",      ("zlib", "liblzma", "libzstd"), ("liblzma",),
     "most distributions ship an xz payload"),
)

# A NOTE ON .deb, because it was got wrong once and the reasoning is
# not obvious: a .deb is an `ar` archive holding debian-binary,
# control.tar.gz and data.tar.xz. libarchive does NOT descend into it --
# it hands back those three members as opaque files, and the inner
# data.tar.xz is then decompressed by Tier 1 using Python's own lzma.
# So .deb needs no payload filter from libarchive, and listing it as
# requiring liblzma was a claim made from memory rather than measured.
# It is also detected as "ar", since that is what its magic says.


def _libarchive_libraries() -> frozenset[str]:
    """
    The compile-time dependencies of the loaded libarchive.

    ``archive_version_details()`` returns something like::

        libarchive 3.8.9 zlib/1.3.1 cng/2.0 libb2/bundled

    which names exactly the optional libraries that were linked in.
    """
    la = _libarchive()
    if la is None:
        return frozenset()
    try:
        import ctypes

        fn = la.ffi.libarchive.archive_version_details
        fn.restype = ctypes.c_char_p
        detail = fn().decode("utf-8", "replace")
    except Exception:
        # Older libarchive lacks the symbol. Claiming nothing is linked
        # would under-report; the honest fallback is to say we could not
        # tell, which the caller surfaces as a warning.
        return frozenset({"?"})
    return frozenset(token.split("/")[0]
                     for token in detail.split()[2:] if "/" in token)


def supported_formats() -> dict[str, list[str]]:
    """
    What this build can actually open, by tier.

    ``tier2`` lists only formats that fully work here. ``tier2_partial``
    lists ones whose container parses but whose common payloads do not,
    and ``tier2_unavailable`` maps a format to the reason it is out of
    reach. A caller that reads only ``tier1``/``tier2`` gets a list it
    can trust rather than an aspiration.
    """
    tier1 = ["pakt", "zip", "tar", "tar.gz", "tar.bz2", "tar.xz",
             "gzip", "bzip2", "xz", "lzma"]
    if _zstd:
        tier1 += ["zstd", "tar.zstd"]
    if _brotli:
        tier1.append("brotli")
    if _py7zr:
        tier1.append("7z")
    if _pycdlib:
        tier1.append("iso")

    result: dict[str, list[str]] = {
        "tier1": sorted(set(tier1)),
        "tier2": [], "tier2_partial": [], "tier2_unavailable": [],
        "native": [],
    }
    if _libarchive() is None:
        return result

    have = _libarchive_libraries()
    unknown = "?" in have
    result["native"] = sorted(have - {"?"})

    for name, needs, prefers, note in _TIER2_SPEC:
        if needs and not unknown and not any(lib in have for lib in needs):
            result["tier2_unavailable"].append(
                f"{name}: {note or 'a required library is not linked in'} "
                f"(missing {' or '.join(needs)})")
        elif prefers and not unknown and not any(lib in have for lib in prefers):
            result["tier2_partial"].append(f"{name}: {note}")
        else:
            result["tier2"].append(name)
    return result


# --------------------------------------------------------------------------
# Listing
# --------------------------------------------------------------------------

def list_entries(path: str | os.PathLike[str], *,
                 password: Optional[str] = None) -> list[ArchiveEntry]:
    """List an archive's members without extracting anything."""
    path = os.fspath(path)
    info = identify(path)
    return _handler_for(info)(path, info, password).entries()


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------

class _Handler:
    """Common shape: enumerate members, then produce their bytes."""

    def __init__(self, path: str, info: ArchiveInfo,
                 password: Optional[str]) -> None:
        self.path = path
        self.info = info
        self.password = password

    def entries(self) -> list[ArchiveEntry]:
        raise NotImplementedError

    def read(self, entry: ArchiveEntry) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        pass


class _PaktHandler(_Handler):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        from core.pakt_reader import open_pakt
        # The password must be forwarded. Without it an encrypted .pakt
        # could not be listed or extracted through this dispatcher at
        # all, and the failure surfaced as "supply a password" even when
        # one had been supplied.
        self._archive = open_pakt(self.path, password=self.password)

    def entries(self) -> list[ArchiveEntry]:
        from core.container import EntryType
        out = []
        for e in self._archive.entries:
            out.append(ArchiveEntry(
                path=e.path, size=e.plain_size,
                is_dir=e.entry_type is EntryType.DIRECTORY,
                is_symlink=e.entry_type is EntryType.SYMLINK,
                mtime=(e.mtime_ns / 1e9) if e.mtime_ns else None,
                mode=e.mode))
        return out

    def read(self, entry: ArchiveEntry) -> bytes:
        match = next(e for e in self._archive.entries if e.path == entry.path)
        return self._archive.read(match)

    def close(self) -> None:
        self._archive.close()


class _ZipHandler(_Handler):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        # pyzipper is a zipfile superset that also reads WinZip AES-256,
        # which the stdlib cannot. Prefer it whenever it is installed.
        opener = _pyzipper.AESZipFile if _pyzipper else zipfile.ZipFile
        try:
            self._zf = opener(self.path)
        except Exception:
            self._zf = zipfile.ZipFile(self.path)
        if self.password:
            self._zf.setpassword(self.password.encode("utf-8"))

    def entries(self) -> list[ArchiveEntry]:
        out = []
        for i in self._zf.infolist():
            # Unix-created zips record the file mode in the high 16 bits
            # of external_attr, which is how a symlink is expressed.
            mode = (i.external_attr >> 16) & 0xFFFF
            is_link = (mode & 0o170000) == 0o120000
            out.append(ArchiveEntry(
                path=i.filename, size=i.file_size,
                is_dir=i.is_dir(), is_symlink=is_link,
                compressed_size=i.compress_size,
                mtime=None, mode=mode & 0o7777,
                link_target=""))
        return out

    def read(self, entry: ArchiveEntry) -> bytes:
        return self._zf.read(entry.path)

    def close(self) -> None:
        self._zf.close()


class _SevenZipHandler(_Handler):
    """
    .7z via py7zr, including AES-256 and encrypted headers.

    py7zr exposes extraction to disk rather than to memory, so the
    archive is unpacked into an isolated temporary directory first and
    the real tree is then walked, re-validated and copied out through
    the shared safety policy.

    That indirection is deliberate. Handing py7zr the user's chosen
    destination would delegate path handling to a third-party library
    and place the traversal defence outside our control. Unpacking to a
    private directory and taking only what is genuinely inside it means
    a bug there cannot become an arbitrary write here.
    """

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        if _py7zr is None:
            raise UnsupportedArchive(
                "this build cannot open .7z: py7zr is not installed")
        self._tmp: Optional[str] = None
        self._files: Optional[dict[str, str]] = None

    def _materialise(self) -> dict[str, str]:
        if self._files is not None:
            return self._files
        import tempfile
        self._tmp = tempfile.mkdtemp(prefix="compakt-7z-")
        root = os.path.realpath(self._tmp)
        with _py7zr.SevenZipFile(self.path, mode="r",
                                 password=self.password) as zf:
            zf.extractall(path=root)

        found: dict[str, str] = {}
        for base, _dirs, names in os.walk(root):
            for name in names:
                real = os.path.realpath(os.path.join(base, name))
                # Take only what actually landed inside the private
                # directory. Anything that escaped is discarded rather
                # than propagated.
                if real != root and not real.startswith(root + os.sep):
                    continue
                rel = os.path.relpath(real, root).replace(os.sep, "/")
                found[rel] = real
        self._files = found
        return found

    def entries(self) -> list[ArchiveEntry]:
        out = []
        try:
            with _py7zr.SevenZipFile(self.path, mode="r",
                                     password=self.password) as zf:
                for info in zf.list():
                    out.append(ArchiveEntry(
                        path=str(info.filename).replace("\\", "/"),
                        size=int(getattr(info, "uncompressed", 0) or 0),
                        is_dir=bool(getattr(info, "is_directory", False)),
                        compressed_size=int(getattr(info, "compressed", 0) or 0),
                    ))
        except Exception as exc:
            raise UnsupportedArchive(
                f"cannot list this .7z archive: {exc}") from None
        return out

    def read(self, entry: ArchiveEntry) -> bytes:
        files = self._materialise()
        real = files.get(entry.path)
        if real is None:
            return b""
        with open(real, "rb") as fh:
            return fh.read()

    def close(self) -> None:
        if self._tmp and os.path.isdir(self._tmp):
            import shutil
            shutil.rmtree(self._tmp, ignore_errors=True)
        self._tmp = None
        self._files = None


class _TarHandler(_Handler):
    _MODES = {"tar": "r:", "tar.gzip": "r:gz", "tar.bzip2": "r:bz2",
              "tar.xz": "r:xz"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        fmt = self.info.format
        if fmt == "tar.zstd":
            if _zstd is None:
                raise UnsupportedArchive(
                    "this build cannot open .tar.zst: zstandard is missing")
            self._raw = open(self.path, "rb")
            stream = _zstd.ZstdDecompressor().stream_reader(self._raw)
            self._tf = tarfile.open(fileobj=stream, mode="r|")
            self._streaming = True
            self._cache: dict[str, bytes] = {}
            self._members: list[tarfile.TarInfo] = []
            for member in self._tf:
                self._members.append(member)
                if member.isreg():
                    f = self._tf.extractfile(member)
                    self._cache[member.name] = f.read() if f else b""
        else:
            self._tf = tarfile.open(self.path, self._MODES.get(fmt, "r:*"))
            self._streaming = False
            self._members = self._tf.getmembers()

    def entries(self) -> list[ArchiveEntry]:
        out = []
        for m in self._members:
            if m.ischr() or m.isblk() or m.isfifo():
                # Never create device nodes or FIFOs from an archive.
                continue
            if m.islnk():
                # Hard links are refused outright: they alias an
                # existing inode and are a classic overwrite primitive.
                continue
            out.append(ArchiveEntry(
                path=m.name, size=m.size, is_dir=m.isdir(),
                is_symlink=m.issym(), mtime=float(m.mtime),
                mode=m.mode & 0o7777, link_target=m.linkname or ""))
        return out

    def read(self, entry: ArchiveEntry) -> bytes:
        if self._streaming:
            return self._cache.get(entry.path, b"")
        member = self._tf.getmember(entry.path)
        f = self._tf.extractfile(member)
        return f.read() if f else b""

    def close(self) -> None:
        self._tf.close()
        if getattr(self, "_streaming", False):
            self._raw.close()


class _SingleStreamHandler(_Handler):
    """gz, bz2, xz, lzma, zst, br -- one file, no member names."""

    def entries(self) -> list[ArchiveEntry]:
        base = os.path.basename(self.path)
        stem, ext = os.path.splitext(base)
        if not ext or ext.lower() not in (
            ".gz", ".bz2", ".xz", ".lzma", ".zst", ".zstd", ".br", ".z"
        ):
            stem = base + ".out"
        return [ArchiveEntry(path=sanitise_member_path(stem),
                             size=0, compressed_size=os.path.getsize(self.path))]

    def read(self, entry: ArchiveEntry) -> bytes:
        fmt = self.info.format
        with open(self.path, "rb") as fh:
            raw = fh.read()
        if fmt == "gzip":
            return gzip.decompress(raw)
        if fmt == "bzip2":
            return bz2.decompress(raw)
        if fmt in ("xz", "lzma"):
            return lzma.decompress(raw)
        if fmt == "zstd":
            if _zstd is None:
                raise UnsupportedArchive("zstandard is not installed")
            return _zstd.ZstdDecompressor().decompress(
                raw, max_output_size=1 << 31)
        if fmt == "brotli":
            if _brotli is None:
                raise UnsupportedArchive("brotli is not installed")
            return _brotli.decompress(raw)
        raise UnsupportedArchive(f"no decoder for {fmt}")


class _IsoHandler(_Handler):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        if _pycdlib is None:
            raise UnsupportedArchive(
                "this build cannot open .iso: pycdlib is not installed")
        self._iso = _pycdlib.PyCdlib()
        self._iso.open(self.path)
        self._facade = self._pick_facade()

    def _pick_facade(self):
        for name in ("rock_ridge_facade", "joliet_facade", "iso9660_facade",
                     "udf_facade"):
            try:
                return getattr(self._iso, name)()
            except Exception:
                continue
        return None

    def entries(self) -> list[ArchiveEntry]:
        out: list[ArchiveEntry] = []
        facade = self._facade
        if facade is None:
            return out

        def walk(directory: str) -> None:
            try:
                children = list(facade.list_children(directory))
            except Exception:
                return
            for child in children:
                if child is None or child.is_dot() or child.is_dotdot():
                    continue
                try:
                    name = child.file_identifier().decode("utf-8", "replace")
                except Exception:
                    continue
                name = name.split(";")[0]
                full = posixpath.join(directory, name)
                if child.is_dir():
                    out.append(ArchiveEntry(path=full.lstrip("/"), is_dir=True))
                    walk(full)
                else:
                    out.append(ArchiveEntry(path=full.lstrip("/"),
                                            size=child.get_data_length()))

        walk("/")
        return out

    def read(self, entry: ArchiveEntry) -> bytes:
        import io
        buf = io.BytesIO()
        self._facade.get_file_from_iso_fp(buf, "/" + entry.path)
        return buf.getvalue()

    def close(self) -> None:
        try:
            self._iso.close()
        except Exception:
            pass


class _LibarchiveHandler(_Handler):
    """
    Tier 2: rar, cab, lha, cpio, ar, deb, rpm, xar, warc, arj, .Z.

    One shared library buys roughly forty read formats, decoded
    IN-PROCESS. This is why patool was dropped: it decodes nothing
    itself and instead executes whatever archiver binary it finds on
    PATH, which is both a hole in the air-gapped guarantee and a
    privilege-inheriting hijack vector.
    """

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._la = _libarchive()
        if self._la is None:
            raise UnsupportedArchive(
                f"{self.info.format} needs the libarchive shared library, "
                f"which is not present in this build. Tier 1 formats "
                f"(.pakt, .zip, .7z, .tar, .gz, .bz2, .xz, .zst, .iso) are "
                f"unaffected.")
        self._cache: Optional[dict[str, bytes]] = None

    def _load(self) -> dict[str, bytes]:
        if self._cache is None:
            data: dict[str, bytes] = {}
            with self._la.file_reader(self.path) as reader:
                for member in reader:
                    if member.isdir:
                        data[member.pathname] = b""
                        continue
                    data[member.pathname] = b"".join(member.get_blocks())
            self._cache = data
        return self._cache

    def entries(self) -> list[ArchiveEntry]:
        out = []
        with self._la.file_reader(self.path) as reader:
            for member in reader:
                out.append(ArchiveEntry(
                    path=member.pathname, size=member.size or 0,
                    is_dir=bool(member.isdir),
                    is_symlink=bool(getattr(member, "issym", False)),
                    link_target=getattr(member, "linkpath", "") or ""))
        return out

    def read(self, entry: ArchiveEntry) -> bytes:
        return self._load().get(entry.path, b"")


_HANDLERS: dict[str, type[_Handler]] = {
    "pakt": _PaktHandler,
    "zip": _ZipHandler,
    "7z": _SevenZipHandler,
    "tar": _TarHandler,
    "tar.gzip": _TarHandler,
    "tar.bzip2": _TarHandler,
    "tar.xz": _TarHandler,
    "tar.zstd": _TarHandler,
    "gzip": _SingleStreamHandler,
    "bzip2": _SingleStreamHandler,
    "xz": _SingleStreamHandler,
    "lzma": _SingleStreamHandler,
    "zstd": _SingleStreamHandler,
    "brotli": _SingleStreamHandler,
    "iso": _IsoHandler,
}


def _handler_for(info: ArchiveInfo) -> Callable[..., _Handler]:
    handler = _HANDLERS.get(info.format)
    if handler is not None:
        return handler
    if info.tier == 2:
        return _LibarchiveHandler
    raise UnsupportedArchive(f"no handler for format {info.format!r}")


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def extract(
    path: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    password: Optional[str] = None,
    limits: Optional[ExtractLimits] = None,
    progress: Optional[Callable[[str, int], None]] = None,
) -> ExtractResult:
    """
    Extract any supported archive into ``destination``.

    Every format goes through the same safety policy: nothing is written
    outside the destination, symlinks are opt-in and may not escape,
    hardlinks and device nodes are never created, and declared expansion
    is checked before anything is decoded.
    """
    path = os.fspath(path)
    root = os.path.abspath(os.fspath(destination))
    limits = limits or ExtractLimits()
    guard = BombGuard(limits)

    info = identify(path)
    handler = _handler_for(info)(path, info, password)
    result = ExtractResult(destination=root, format=info.format)

    try:
        members = handler.entries()
        guard.declare_entry_count(len(members))
        for member in members:
            if member.compressed_size or member.size:
                guard.declare(member.size, member.compressed_size, member.path)

        os.makedirs(root, exist_ok=True)

        for member in members:
            target = safe_target(root, member.path)

            if member.is_dir:
                os.makedirs(target, exist_ok=True)
                result.entries_written += 1
                continue

            os.makedirs(os.path.dirname(target), exist_ok=True)

            if member.is_symlink:
                if not limits.allow_symlinks:
                    result.skipped.append(
                        f"{member.path} (symlink; extraction disabled)")
                    continue
                link_target = member.link_target
                if not link_target:
                    link_target = handler.read(member).decode("utf-8", "replace")
                check_link_target(root, target, link_target)
                if os.path.lexists(target):
                    os.remove(target)
                os.symlink(link_target, target)
                result.entries_written += 1
                continue

            data = handler.read(member)
            guard.account(len(data), member.path)

            with open(target, "wb") as out:
                out.write(data)
            if member.mode:
                try:
                    os.chmod(target, member.mode)
                except OSError:
                    pass
            if member.mtime:
                try:
                    os.utime(target, (member.mtime, member.mtime))
                except OSError:
                    pass

            result.entries_written += 1
            result.bytes_written += len(data)
            if progress:
                progress(member.path, len(data))
    finally:
        handler.close()

    return result
