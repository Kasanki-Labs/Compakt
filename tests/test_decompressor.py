"""
Tests for the universal extraction manager.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

The hostile archives below are built with the stdlib's own zipfile and
tarfile, which will happily write absolute paths, ``..`` components and
escaping symlinks because nothing in either format forbids them. That is
the point: these are not synthetic curiosities, they are what the
formats genuinely permit, and they are how real extractors get exploited.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
import zipfile

import pytest

from core.decompressor import (
    ExtractLimits,
    SecurityError,
    UnsupportedArchive,
    extract,
    identify,
    list_entries,
    supported_formats,
)
from core.reference_encoder import pack

PAYLOAD = b"compakt extraction payload\n" * 200


# ==========================================================================
# Fixtures
# ==========================================================================

@pytest.fixture
def tree(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_bytes(PAYLOAD)
    (src / "sub" / "b.txt").write_bytes(PAYLOAD * 2)
    return src


def make_zip(path, members: dict[str, bytes], compress=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compress) as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return str(path)


def make_tar(path, build, mode="w"):
    with tarfile.open(path, mode) as tf:
        build(tf)
    return str(path)


def add_tar_bytes(tf, name, body: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(body)
    tf.addfile(info, io.BytesIO(body))


# ==========================================================================
# Identification -- content, not extension
# ==========================================================================

def test_supported_formats_reports_tiers():
    formats = supported_formats()
    assert "zip" in formats["tier1"]
    assert "pakt" in formats["tier1"]
    assert isinstance(formats["tier2"], list)


def test_tier2_listing_never_promises_more_than_it_can_do():
    """
    A format may appear in exactly one of the three Tier 2 buckets.

    The bug this guards against is the listing claiming every Tier 2
    format the moment libarchive loads. Half of those readers hand
    their payload to a compression library chosen at compile time, so
    the honest answer depends on how the shared library was built --
    and a user who is promised .xar and then cannot open one has been
    lied to by a security tool.
    """
    from core.decompressor import _TIER2_SPEC

    formats = supported_formats()
    named = {name for name, _n, _p, _note in _TIER2_SPEC}

    full = set(formats["tier2"])
    partial = {line.split(":")[0] for line in formats["tier2_partial"]}
    gone = {line.split(":")[0] for line in formats["tier2_unavailable"]}

    assert full <= named
    assert not (full & partial) and not (full & gone) and not (partial & gone)

    if formats["tier2"] or formats["tier2_partial"]:
        # libarchive is present, so every known format is accounted for
        # in exactly one bucket -- none silently dropped.
        assert full | partial | gone == named

    # Anything degraded must say why, so the message is actionable.
    for line in formats["tier2_partial"] + formats["tier2_unavailable"]:
        assert ": " in line and len(line.split(": ", 1)[1]) > 10


def test_zip_renamed_to_txt_is_still_identified(tmp_path):
    p = make_zip(tmp_path / "archive.txt", {"a.txt": PAYLOAD})
    assert identify(p).format == "zip"


def test_tar_gz_is_distinguished_from_plain_gzip(tmp_path):
    plain = tmp_path / "p.gz"
    plain.write_bytes(gzip.compress(PAYLOAD))
    assert identify(str(plain)).format == "gzip"

    tarred = tmp_path / "t.tar.gz"
    make_tar(tarred, lambda tf: add_tar_bytes(tf, "a.txt", PAYLOAD), "w:gz")
    assert identify(str(tarred)).format == "tar.gzip"


def test_non_archive_is_refused(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"just some text, not an archive at all\n" * 50)
    with pytest.raises(UnsupportedArchive):
        identify(str(p))


def test_missing_file_is_refused(tmp_path):
    with pytest.raises(UnsupportedArchive):
        identify(str(tmp_path / "nope.zip"))


# ==========================================================================
# Round-trips
# ==========================================================================

def test_zip_roundtrip(tmp_path):
    p = make_zip(tmp_path / "t.zip", {"a.txt": PAYLOAD, "sub/b.txt": PAYLOAD * 2})
    dest = tmp_path / "out"
    result = extract(p, dest)
    assert result.format == "zip"
    assert (dest / "a.txt").read_bytes() == PAYLOAD
    assert (dest / "sub" / "b.txt").read_bytes() == PAYLOAD * 2


@pytest.mark.parametrize("suffix,mode", [
    (".tar", "w"), (".tar.gz", "w:gz"), (".tar.bz2", "w:bz2"), (".tar.xz", "w:xz"),
])
def test_tar_variants_roundtrip(tmp_path, tree, suffix, mode):
    p = make_tar(tmp_path / f"t{suffix}", lambda tf: tf.add(str(tree), "src"), mode)
    dest = tmp_path / ("out" + suffix.replace(".", "_"))
    extract(p, dest)
    assert (dest / "src" / "a.txt").read_bytes() == PAYLOAD
    assert (dest / "src" / "sub" / "b.txt").read_bytes() == PAYLOAD * 2


@pytest.mark.parametrize("name,fn", [
    ("s.txt.gz", gzip.compress),
    ("s.txt.bz2", bz2.compress),
    ("s.txt.xz", lzma.compress),
])
def test_single_stream_roundtrip(tmp_path, name, fn):
    p = tmp_path / name
    p.write_bytes(fn(PAYLOAD))
    dest = tmp_path / ("out_" + name.replace(".", "_"))
    extract(str(p), dest)
    assert (dest / "s.txt").read_bytes() == PAYLOAD


def test_zstd_and_brotli_roundtrip(tmp_path):
    zstandard = pytest.importorskip("zstandard")
    brotli = pytest.importorskip("brotli")

    z = tmp_path / "s.txt.zst"
    z.write_bytes(zstandard.ZstdCompressor().compress(PAYLOAD))
    extract(str(z), tmp_path / "outz")
    assert (tmp_path / "outz" / "s.txt").read_bytes() == PAYLOAD

    b = tmp_path / "s.txt.br"
    b.write_bytes(brotli.compress(PAYLOAD))
    extract(str(b), tmp_path / "outb")
    assert (tmp_path / "outb" / "s.txt").read_bytes() == PAYLOAD


def test_sevenzip_roundtrip(tmp_path, tree):
    py7zr = pytest.importorskip("py7zr")
    p = str(tmp_path / "t.7z")
    with py7zr.SevenZipFile(p, "w") as sz:
        sz.writeall(str(tree), "src")
    dest = tmp_path / "out"
    extract(p, dest)
    assert (dest / "src" / "a.txt").read_bytes() == PAYLOAD


def test_encrypted_sevenzip_is_detected_and_opens(tmp_path, tree):
    py7zr = pytest.importorskip("py7zr")
    p = str(tmp_path / "enc.7z")
    with py7zr.SevenZipFile(p, "w", password="hunter2") as sz:
        sz.writeall(str(tree), "src")
    assert identify(p).encrypted
    extract(p, tmp_path / "out", password="hunter2")
    assert (tmp_path / "out" / "src" / "a.txt").read_bytes() == PAYLOAD


def test_pakt_goes_through_the_same_extractor(tmp_path, tree):
    p = str(tmp_path / "t.pakt")
    pack([str(tree)], p)
    assert identify(p).format == "pakt"
    dest = tmp_path / "out"
    extract(p, dest)
    assert (dest / "src" / "a.txt").read_bytes() == PAYLOAD


def test_listing_does_not_extract(tmp_path):
    p = make_zip(tmp_path / "t.zip", {"a.txt": PAYLOAD, "b.txt": PAYLOAD})
    names = [e.path for e in list_entries(p)]
    assert sorted(names) == ["a.txt", "b.txt"]
    assert not (tmp_path / "a.txt").exists()


# ==========================================================================
# Security -- the same policy for every format
# ==========================================================================

def test_zip_slip_is_refused(tmp_path):
    """The canonical attack, in the format it is named after."""
    p = make_zip(tmp_path / "evil.zip", {"../escaped.txt": b"pwned"})
    with pytest.raises(SecurityError):
        extract(p, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_deep_zip_slip_is_refused(tmp_path):
    p = make_zip(tmp_path / "evil.zip", {"a/b/../../../../escaped.txt": b"pwned"})
    with pytest.raises(SecurityError):
        extract(p, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_tar_slip_is_refused(tmp_path):
    p = make_tar(tmp_path / "evil.tar",
                 lambda tf: add_tar_bytes(tf, "../escaped.txt", b"pwned"))
    with pytest.raises(SecurityError):
        extract(p, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_absolute_path_in_tar_is_neutralised(tmp_path):
    """
    An absolute member name must never become an absolute write. The
    leading separator is stripped and the result proved to stay inside.
    """
    p = make_tar(tmp_path / "abs.tar",
                 lambda tf: add_tar_bytes(tf, "/etc/passwd", b"pwned"))
    dest = tmp_path / "out"
    extract(p, dest)
    assert (dest / "etc" / "passwd").read_bytes() == b"pwned"


def test_windows_drive_letter_is_neutralised(tmp_path):
    p = make_zip(tmp_path / "drive.zip", {"C:/Windows/evil.dll": b"pwned"})
    dest = tmp_path / "out"
    extract(p, dest)
    assert (dest / "Windows" / "evil.dll").read_bytes() == b"pwned"


def test_reserved_device_name_is_refused(tmp_path):
    p = make_zip(tmp_path / "dev.zip", {"folder/nul": b"pwned"})
    with pytest.raises(SecurityError, match="reserved device"):
        extract(p, tmp_path / "out")


def test_symlinks_are_skipped_by_default(tmp_path):
    def build(tf):
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../../../etc/passwd"
        tf.addfile(info)
        add_tar_bytes(tf, "ok.txt", PAYLOAD)

    p = make_tar(tmp_path / "link.tar", build)
    dest = tmp_path / "out"
    result = extract(p, dest)
    assert any("symlink" in s for s in result.skipped)
    assert (dest / "ok.txt").read_bytes() == PAYLOAD
    assert not (dest / "link").exists()


def test_escaping_symlink_refused_even_when_enabled(tmp_path):
    def build(tf):
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        tf.addfile(info)

    p = make_tar(tmp_path / "link2.tar", build)
    with pytest.raises(SecurityError):
        extract(p, tmp_path / "out",
                limits=ExtractLimits(allow_symlinks=True))


def test_hardlinks_are_never_created(tmp_path):
    """A hardlink aliases an existing inode: a classic overwrite primitive."""
    def build(tf):
        add_tar_bytes(tf, "real.txt", PAYLOAD)
        info = tarfile.TarInfo("alias.txt")
        info.type = tarfile.LNKTYPE
        info.linkname = "real.txt"
        tf.addfile(info)

    p = make_tar(tmp_path / "hard.tar", build)
    dest = tmp_path / "out"
    extract(p, dest)
    assert (dest / "real.txt").exists()
    assert not (dest / "alias.txt").exists()


def test_device_nodes_are_never_created(tmp_path):
    def build(tf):
        info = tarfile.TarInfo("dev/null")
        info.type = tarfile.CHRTYPE
        info.devmajor, info.devminor = 1, 3
        tf.addfile(info)
        add_tar_bytes(tf, "ok.txt", PAYLOAD)

    p = make_tar(tmp_path / "dev.tar", build)
    dest = tmp_path / "out"
    extract(p, dest)
    assert (dest / "ok.txt").exists()
    assert not (dest / "dev" / "null").exists()


def test_declared_bomb_is_refused_before_decoding(tmp_path):
    """A zip of highly repetitive data declares its own expansion."""
    p = make_zip(tmp_path / "bomb.zip", {"big": b"\x00" * 8_000_000})
    with pytest.raises(SecurityError, match="bomb"):
        extract(p, tmp_path / "out", limits=ExtractLimits(max_ratio=50))


def test_total_size_cap_is_enforced(tmp_path):
    p = make_zip(tmp_path / "t.zip", {"a.txt": PAYLOAD, "b.txt": PAYLOAD})
    with pytest.raises(SecurityError, match="cap"):
        extract(p, tmp_path / "out",
                limits=ExtractLimits(max_total_bytes=100, max_ratio=1e9))


def test_entry_count_cap_is_enforced(tmp_path):
    p = make_zip(tmp_path / "many.zip",
                 {f"f{i}.txt": b"x" * 10 for i in range(30)})
    with pytest.raises(SecurityError, match="entries"):
        extract(p, tmp_path / "out", limits=ExtractLimits(max_entries=5))


def test_per_entry_cap_is_enforced(tmp_path):
    p = make_zip(tmp_path / "one.zip", {"a.txt": PAYLOAD})
    with pytest.raises(SecurityError, match="per-entry"):
        extract(p, tmp_path / "out",
                limits=ExtractLimits(max_entry_bytes=100, max_ratio=1e9))


def test_nothing_is_written_outside_the_destination(tmp_path):
    """Broad sweep: several attacks at once, one assertion that counts."""
    canary = tmp_path / "canary.txt"
    canary.write_bytes(b"untouched")

    p = make_zip(tmp_path / "multi.zip", {
        "../canary.txt": b"overwritten",
        "../../canary.txt": b"overwritten",
        "ok.txt": PAYLOAD,
    })
    with pytest.raises(SecurityError):
        extract(p, tmp_path / "out")
    assert canary.read_bytes() == b"untouched"


# ==========================================================================
# Tier 2 degradation
# ==========================================================================

def test_tier2_format_is_named_when_unavailable(tmp_path):
    """
    A .rar must be recognised as a .rar even without libarchive, and
    refused with a message that says what is missing. Silently
    mis-handling it would be far worse than refusing it.
    """
    p = tmp_path / "t.rar"
    p.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 200)

    info = identify(str(p))
    assert info.format == "rar"
    assert info.tier == 2

    from core.decompressor import _libarchive
    if _libarchive() is None:
        with pytest.raises(UnsupportedArchive, match="libarchive"):
            extract(str(p), tmp_path / "out")
