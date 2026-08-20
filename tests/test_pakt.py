"""
Tests for the .pakt container, encoder and reader.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

The security tests below are not defensive extras. Specification §13
makes them normative: an implementation that does not enforce them is
not a conforming reader. Archive utilities are attacked through their
extractors far more often than through their codecs, so each of those
attacks gets an explicit test that constructs a genuinely hostile
archive rather than trusting the encoder to refuse.
"""

from __future__ import annotations

import os
import struct

import pytest

from core import container as C
from core.codecs import AUTO, FAST, compress, decompress
from core.container import (
    BlockEntry,
    Codec,
    EntryFlag,
    EntryType,
    Feature,
    FileEntry,
    Footer,
    Header,
    Index,
    IndexPreamble,
    PaktCorruptError,
    PaktFormatError,
    PaktUnsupportedError,
    RoutingClass,
    validate_archive_path,
)
from core.pakt_reader import ExtractLimits, SecurityError, open_pakt
from core.reference_encoder import pack


# ==========================================================================
# Helpers
# ==========================================================================

def make_tree(root, files: dict[str, bytes]) -> str:
    for name, body in files.items():
        p = os.path.join(root, name.replace("/", os.sep))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(body)
    return str(root)


def forge_archive(path: str, entries: list[FileEntry], payloads: list[bytes],
                  *, flags: Feature = Feature.NONE) -> str:
    """
    Build a container by hand, bypassing every writer-side check.

    This is what a hostile archive looks like. The reader must defend
    itself without help from the encoder.
    """
    blocks = []
    body_parts = []
    offset = 0
    for data in payloads:
        blocks.append(BlockEntry(offset=0, stored_size=len(data),
                                 plain_size=len(data), codec=Codec.STORE,
                                 plain_crc32=C.crc32(data)))
        body_parts.append(data)

    index = Index(blocks=blocks, files=entries,
                  total_uncompressed=sum(len(p) for p in payloads))

    def build(index_obj) -> bytes:
        body = index_obj.serialise()
        pre = IndexPreamble(index_codec=Codec.STORE, plain_length=len(body),
                            plain_crc32=C.crc32(body))
        return pre.pack() + body

    stored = build(index)
    ia_off = C.HEADER_SIZE
    cursor = ia_off + len(stored)
    for blk, data in zip(blocks, body_parts):
        blk.offset = cursor
        cursor += len(data)
    stored = build(index)                    # offsets are fixed-width
    ib_off = cursor

    header = Header(feature_flags=flags, index_a_offset=ia_off,
                    index_a_length=len(stored), index_b_offset=ib_off,
                    index_b_length=len(stored),
                    container_length=ib_off + len(stored) + C.FOOTER_SIZE)

    with open(path, "wb") as fh:
        fh.write(header.pack())
        fh.write(stored)
        for data in body_parts:
            fh.write(data)
        fh.write(stored)
        fh.write(Footer(container_offset=0, index_b_offset=ib_off).pack())
    return path


# ==========================================================================
# Structure -- spec sections 3, 5, 7, 8, 12
# ==========================================================================

def test_fixed_structures_match_the_specification():
    sizes = C.selftest()
    assert sizes == {
        "header": 64, "footer": 32, "crypto_header": 72,
        "block_entry": 72, "signature": 104, "index_preamble": 24,
    }


def test_header_roundtrip():
    h = Header(feature_flags=Feature.SOLID_BLOCKS | Feature.DEDUP_WHOLE_FILE,
               index_a_offset=64, index_a_length=200, index_b_offset=9000,
               index_b_length=200, container_length=9232)
    back = Header.unpack(h.pack())
    assert back.feature_flags == h.feature_flags
    assert back.index_b_offset == 9000
    assert back.container_length == 9232


def test_header_rejects_bad_magic():
    raw = bytearray(Header().pack())
    raw[0:4] = b"XXXX"
    with pytest.raises(PaktFormatError, match="magic"):
        Header.unpack(bytes(raw))


def test_header_rejects_corrupted_crc():
    raw = bytearray(Header(container_length=100).pack())
    raw[20] ^= 0xFF
    with pytest.raises(PaktCorruptError, match="CRC"):
        Header.unpack(bytes(raw))


def test_header_rejects_future_major_version():
    h = Header()
    h.version_major = 2
    with pytest.raises(PaktUnsupportedError, match="2.0"):
        Header.unpack(h.pack())


def test_footer_roundtrip_and_magic():
    f = Footer(container_offset=4096, index_b_offset=8192)
    back = Footer.unpack(f.pack())
    assert back.container_offset == 4096
    assert back.index_b_offset == 8192


def test_index_roundtrip():
    idx = Index(
        blocks=[BlockEntry(offset=64, stored_size=10, plain_size=99,
                           codec=Codec.BROTLI)],
        files=[FileEntry(path="a/b.txt", plain_size=99, block_index=0,
                         digest=bytes(range(16)))],
        total_uncompressed=99,
    )
    back = Index.deserialise(idx.serialise())
    assert back.files[0].path == "a/b.txt"
    assert back.blocks[0].codec is Codec.BROTLI
    assert back.files[0].digest == bytes(range(16))


def test_digest_is_truncated_through_one_function():
    """
    Writer and reader must narrow the hash identically.

    If a producer stored ``sha[:16]`` and a verifier compared against
    ``sha[16:]``, every archive would fail integrity checks on content
    that was perfectly intact -- a data-loss-shaped bug with no data
    loss behind it. Routing both through :func:`file_digest` is what
    prevents that, so the property is asserted rather than assumed.
    """
    import hashlib

    full = hashlib.sha256(b"some archived bytes").digest()
    assert len(full) == 32
    narrowed = C.file_digest(full)
    assert len(narrowed) == C.DIGEST_SIZE == 16
    assert narrowed == full[:16]
    assert C.file_digest(narrowed) == narrowed      # idempotent

    with pytest.raises(C.PaktFormatError):
        C.file_digest(b"too short")


def test_digest_survives_a_real_pack_unpack(tmp_path):
    """The narrowed digest must still catch a flipped bit end to end."""
    import hashlib

    from core.reference_encoder import pack as pack_reference

    src = tmp_path / "src"
    src.mkdir()
    (src / "payload.txt").write_bytes(b"integrity matters" * 500)

    arc = str(tmp_path / "d.pakt")
    pack_reference([str(src)], arc)

    with open_pakt(arc) as a:
        entry = next(e for e in a.entries if e.path.endswith("payload.txt"))
        assert len(entry.digest) == C.DIGEST_SIZE
        assert entry.digest != bytes(C.DIGEST_SIZE)      # actually recorded
        body = a.read(entry)
        assert entry.digest == C.file_digest(hashlib.sha256(body).digest())


def test_index_detects_corruption():
    raw = bytearray(Index(files=[FileEntry(path="x")]).serialise())
    raw[10] ^= 0xFF
    with pytest.raises(PaktCorruptError, match="index CRC"):
        Index.deserialise(bytes(raw))


def test_block_entry_rejects_implausible_plain_size():
    """Spec §13.5: refuse before allocating, do not honour the claim."""
    e = BlockEntry(plain_size=C.MAX_BLOCK_PLAIN_SIZE + 1)
    with pytest.raises(PaktFormatError, match="cap"):
        BlockEntry.unpack(e.pack())


# ==========================================================================
# Feature flags -- spec section 4
# ==========================================================================

def test_reserved_network_bits_are_rejected_by_name():
    for feature, name in (
        (Feature.CHUNK_TABLE, "CHUNK_TABLE"),
        (Feature.MERKLE_DAG, "MERKLE_DAG"),
        (Feature.RS_PARITY, "RS_PARITY"),
        (Feature.CDC_CHUNKING, "CDC_CHUNKING"),
        (Feature.CONVERGENT_ENC, "CONVERGENT_ENC"),
    ):
        with pytest.raises(PaktUnsupportedError, match=name):
            Header.unpack(Header(feature_flags=feature).pack())


def test_unknown_feature_bits_are_rejected():
    h = Header()
    h.feature_flags = 1 << 40
    with pytest.raises(PaktUnsupportedError, match="unknown feature"):
        Header.unpack(h.pack())


def test_encrypted_and_reproducible_are_mutually_exclusive():
    """
    Spec §4.3. A deterministic AES-GCM nonce reused across archives
    does not weaken the cipher, it collapses it.
    """
    combo = Feature.ENCRYPTED | Feature.REPRODUCIBLE
    with pytest.raises(PaktFormatError, match="mutually exclusive"):
        Header.unpack(Header(feature_flags=combo).pack())


# ==========================================================================
# Path rules -- spec section 12.6
# ==========================================================================

@pytest.mark.parametrize("bad", [
    "../escape",
    "a/../../escape",
    "/absolute/path",
    "C:/windows/system32",
    "back\\slash",
    "trailing/..",
    "./relative",
    "double//slash",
    "",
])
def test_hostile_paths_are_rejected(bad):
    with pytest.raises(PaktFormatError):
        validate_archive_path(bad)


@pytest.mark.parametrize("name", ["con", "PRN", "aux.txt", "nul", "COM1", "lpt9"])
def test_windows_reserved_device_names_are_rejected(name):
    with pytest.raises(PaktFormatError, match="reserved device"):
        validate_archive_path(f"dir/{name}")


@pytest.mark.parametrize("good", [
    "file.txt", "a/b/c.py", "with space.md", "dot.in.name.tar",
    "unicode-café-日本語.txt", "..hidden", "a..b",
])
def test_legitimate_paths_are_accepted(good):
    validate_archive_path(good)


# ==========================================================================
# Round-trip
# ==========================================================================

def test_pack_and_extract_roundtrip(tmp_path):
    files = {
        "readme.md": b"# Compakt\n" + b"better compression.\n" * 300,
        "data.csv": b"id,v\n" + b"".join(f"{i},{i*2}\n".encode() for i in range(800)),
        "sub/app.py": b"def f():\n    return 1\n\n" * 200,
        "noise.bin": os.urandom(20000),
        "empty.txt": b"",
    }
    src = make_tree(tmp_path / "src", files)
    arc = str(tmp_path / "out.pakt")
    result = pack([src], arc)
    assert result.archive_size > 0

    dest = tmp_path / "out"
    with open_pakt(arc) as a:
        assert a.extract_all(dest) == len(a.entries)

    for name, body in files.items():
        got = (dest / "src" / name).read_bytes()
        assert got == body, name


def test_routing_reaches_the_expected_codecs(tmp_path):
    src = make_tree(tmp_path / "src", {
        "prose.md": b"the quick brown fox jumps over the lazy dog.\n" * 400,
        "blob.bin": os.urandom(30000),
    })
    result = pack([src], str(tmp_path / "a.pakt"))
    by_name = {os.path.basename(i.path): i for i in result.items}
    assert by_name["prose.md"].codec is Codec.BROTLI
    assert by_name["blob.bin"].codec is Codec.STORE


def test_duplicate_files_are_stored_once(tmp_path):
    body = b"identical content here.\n" * 500
    src = make_tree(tmp_path / "src", {
        "one.txt": body, "two.txt": body, "deep/three.txt": body,
    })
    result = pack([src], str(tmp_path / "d.pakt"))
    assert result.deduped_files == 2

    dest = tmp_path / "out"
    with open_pakt(str(tmp_path / "d.pakt")) as a:
        a.extract_all(dest)
    for name in ("one.txt", "two.txt", "deep/three.txt"):
        assert (dest / "src" / name).read_bytes() == body


def test_compression_never_inflates_a_block(tmp_path):
    """Incompressible input must fall back to STORE, not grow."""
    src = make_tree(tmp_path / "src", {"r.bin": os.urandom(50000)})
    result = pack([src], str(tmp_path / "r.pakt"))
    item = next(i for i in result.items if i.path.endswith("r.bin"))
    assert item.stored_size <= item.size


def test_archive_survives_a_corrupted_index_copy_b(tmp_path):
    """
    Copy A is used when copy B's BODY is corrupted (§2.2).

    Note what this does and does not cover. It overwrites bytes in place,
    so the file length -- and therefore the footer -- survives. That is
    corruption, not truncation. This test was once named for truncation
    and never truncated anything, which is how a reader that could not
    survive truncation at all passed it for weeks. The truncation cases
    are below and they cut the file.
    """
    src = make_tree(tmp_path / "src", {"a.txt": b"hello world\n" * 100})
    arc = str(tmp_path / "x.pakt")
    pack([src], arc)

    with open(arc, "r+b") as fh:
        header = Header.unpack(fh.read(C.HEADER_SIZE))
        fh.seek(header.index_b_offset + 40)
        fh.write(b"\xff" * 32)

    with open_pakt(arc) as a:
        assert a.index_copy_used == "A"
        assert a.read(a.entries[-1]) == b"hello world\n" * 100


# ==========================================================================
# Damage recovery -- spec section 2.1 and 2.2
# ==========================================================================
# The format's FIRST stated property is that a truncated archive is
# partially recoverable, and the GUI sells "lose the start and it still
# opens; lose the end and it still opens". Every case below was LOST
# before these tests existed: the reader refused on a bad footer and
# never reached copy A, and it read both index offsets from the header
# alone while the footer carried index_b_offset for exactly this purpose.
#
# The claim was true of the format and false of the implementation. These
# tests are what keeps them in agreement.

def _damage_corpus(tmp_path, name="d.pakt"):
    """
    An archive big enough that partial head damage is partial.

    Sized deliberately: with a 2 KB archive, zeroing 4 KiB destroys the
    footer as well and the case silently stops testing what it claims.
    """
    files = {}
    for i in range(120):
        files["f%03d.txt" % i] = ("row %d of text\n" % i).encode() * 30
    files["sub/data.json"] = b'{"a": [1, 2, 3]}\n' * 300
    src = make_tree(tmp_path / "src", files)
    arc = str(tmp_path / name)
    pack([src], arc)
    return arc, files


def _layout(arc):
    size = os.path.getsize(arc)
    with open(arc, "rb") as fh:
        fh.seek(size - C.FOOTER_SIZE)
        footer = Footer.unpack(fh.read(C.FOOTER_SIZE))
        fh.seek(footer.container_offset)
        header = Header.unpack(fh.read(C.HEADER_SIZE))
    return size, footer, header


def _opens_and_extracts(arc, tmp_path, files, out="out"):
    dest = tmp_path / out
    with open_pakt(arc) as a:
        a.extract_all(dest)
        n = len(a.entries)
        repairs = list(a.damage)
    for name, body in files.items():
        assert (dest / "src" / name.replace("/", os.sep)).read_bytes() == body
    return n, repairs


def test_tail_truncation_still_opens(tmp_path):
    """
    THE CASE THE FORMAT EXISTS FOR: an interrupted download or copy.

    Truncation removes the footer, and copy A sits near the FRONT --
    untouched. A reader that gives up on a bad footer throws away a fully
    recoverable archive, which is what it used to do.
    """
    arc, files = _damage_corpus(tmp_path)
    size, _footer, header = _layout(arc)
    # Cut inside index B, leaving every block and copy A intact.
    cut = header.index_b_offset + 16
    with open(arc, "r+b") as fh:
        fh.truncate(cut)

    n, repairs = _opens_and_extracts(arc, tmp_path, files)
    assert n > 100
    assert repairs, "recovering silently is a spec violation (§2.1 MUST warn)"


def test_destroyed_footer_still_opens(tmp_path):
    """Spec §2.1: scan for the header magic when the footer will not parse."""
    arc, files = _damage_corpus(tmp_path)
    size, _footer, _header = _layout(arc)
    with open(arc, "r+b") as fh:
        fh.seek(size - C.FOOTER_SIZE)
        fh.write(bytes(C.FOOTER_SIZE))

    _n, repairs = _opens_and_extracts(arc, tmp_path, files)
    assert repairs


def test_destroyed_header_still_opens_via_the_footer(tmp_path):
    """
    The other half of the claim: lose the START and it still opens.

    This is why the footer duplicates index_b_offset. The header is gone,
    so the offset of copy B can only come from the footer -- and the
    length has to be derived from the layout, because nothing records it
    twice.
    """
    arc, files = _damage_corpus(tmp_path)
    _size, footer, _header = _layout(arc)
    with open(arc, "r+b") as fh:
        fh.seek(footer.container_offset)
        fh.write(bytes(C.HEADER_SIZE))

    _n, repairs = _opens_and_extracts(arc, tmp_path, files)
    assert repairs
    assert any("footer" in r for r in repairs)


def test_partial_head_damage_still_opens(tmp_path):
    """4 KiB of head damage takes the header AND copy A. Copy B answers."""
    arc, files = _damage_corpus(tmp_path)
    _size, footer, header = _layout(arc)
    assert header.index_b_offset > 4096, "corpus too small for this case"
    with open(arc, "r+b") as fh:
        fh.seek(footer.container_offset)
        fh.write(bytes(4096))

    _n, repairs = _opens_and_extracts(arc, tmp_path, files)
    assert repairs


def test_either_index_copy_alone_is_enough(tmp_path):
    """Zero one copy entirely; the other must carry the archive."""
    for victim in ("A", "B"):
        arc, files = _damage_corpus(tmp_path, name="only%s.pakt" % victim)
        _size, _footer, header = _layout(arc)
        at = (header.index_a_offset if victim == "A"
              else header.index_b_offset)
        length = (header.index_a_length if victim == "A"
                  else header.index_b_length)
        with open(arc, "r+b") as fh:
            fh.seek(at)
            fh.write(bytes(length))
        _opens_and_extracts(arc, tmp_path, files, out="out" + victim)


def test_damage_in_both_copies_of_a_single_segment_index_is_refused(tmp_path):
    """
    A small archive's index is ONE segment, and one segment damaged in
    both copies cannot be reconstructed from either.

    This is the residual limit after segmenting, and it is a floor rather
    than an oversight: an index too small to split has nothing to stitch.
    Refusing is the only honest answer -- a partially decoded index would
    hand back offsets that are believed.
    """
    arc, _files = _damage_corpus(tmp_path)
    _size, _footer, header = _layout(arc)
    with open(arc, "rb") as fh:
        fh.seek(header.index_a_offset)
        pre = IndexPreamble.unpack(fh.read(C.INDEX_PREAMBLE_SIZE))
    assert pre.n_segments <= 1, "this case needs a single-segment index"

    with open(arc, "r+b") as fh:
        for at in (header.index_a_offset + header.index_a_length // 3,
                   header.index_b_offset + 2 * header.index_b_length // 3):
            fh.seek(at)
            b = fh.read(1)
            fh.seek(at)
            fh.write(bytes([b[0] ^ 0xFF]))

    with pytest.raises(PaktCorruptError):
        open_pakt(arc).entries


def _segmented_corpus(tmp_path, name="seg.pakt"):
    """
    An archive whose index is large enough to be split.

    The reference encoder stores its index uncompressed, so segmenting is
    free and it always does -- but the body still has to exceed one
    segment for there to be more than one.
    """
    files = {}
    for i in range(900):
        files["f%04d.txt" % i] = ("row %d\n" % i).encode() * 20
    src = make_tree(tmp_path / "src", files)
    arc = str(tmp_path / name)
    pack([src], arc)
    _size, _footer, header = _layout(arc)
    with open(arc, "rb") as fh:
        fh.seek(header.index_a_offset)
        pre = IndexPreamble.unpack(fh.read(C.INDEX_PREAMBLE_SIZE))
    return arc, files, header, pre


def test_the_index_is_segmented_so_copies_can_be_combined(tmp_path):
    """Segmenting is what makes the two copies complementary at all."""
    _arc, _files, _header, pre = _segmented_corpus(tmp_path)
    assert pre.segmented
    assert pre.n_segments > 1


def test_one_bad_byte_in_each_copy_still_recovers(tmp_path):
    """
    THE CASE SEGMENTING EXISTS FOR.

    Two independent single-byte faults, in DIFFERENT segments of the two
    copies. Between them every segment survives somewhere, and the reader
    takes each from whichever copy still verifies it. Before the index was
    segmented this lost the whole archive: the body was one compressed
    blob under one CRC, so a single bad byte condemned an entire copy and
    two bad bytes condemned both.

    Two small faults in different places is what failing media, bad
    cables and interrupted writes actually produce -- so this was the
    common case, not an exotic one.
    """
    arc, files, header, pre = _segmented_corpus(tmp_path)
    table = C.INDEX_PREAMBLE_SIZE + pre.n_segments * C.SEGMENT_ENTRY_SIZE + 4

    with open(arc, "r+b") as fh:
        for at in (header.index_a_offset + table + 8,          # first segment
                   header.index_b_offset + header.index_b_length - 64):  # last
            fh.seek(at)
            b = fh.read(1)
            fh.seek(at)
            fh.write(bytes([b[0] ^ 0xFF]))

    n, repairs = _opens_and_extracts(arc, tmp_path, files)
    assert n > 800
    assert any("combining" in r for r in repairs), repairs


def test_the_same_segment_damaged_in_both_copies_is_refused(tmp_path):
    """
    The limit that remains once segmenting is in: stitching helps only
    when the faults land in DIFFERENT segments. Damage the same segment in
    both copies and there is no surviving version of it anywhere, which
    must be refused rather than half-decoded.
    """
    arc, _files, header, pre = _segmented_corpus(tmp_path, name="same.pakt")
    table = C.INDEX_PREAMBLE_SIZE + pre.n_segments * C.SEGMENT_ENTRY_SIZE + 4

    with open(arc, "r+b") as fh:
        for base in (header.index_a_offset, header.index_b_offset):
            at = base + table + 8                      # segment 0 in both
            fh.seek(at)
            b = fh.read(1)
            fh.seek(at)
            fh.write(bytes([b[0] ^ 0xFF]))

    with pytest.raises(PaktCorruptError):
        open_pakt(arc).entries


def test_an_intact_archive_reports_no_damage(tmp_path):
    """
    The counterpart that stops the others passing vacuously: a healthy
    archive must report NOTHING, or "damaged" means nothing.
    """
    arc, files = _damage_corpus(tmp_path)
    n, repairs = _opens_and_extracts(arc, tmp_path, files)
    assert n > 100
    assert repairs == []


# ==========================================================================
# Reproducible output -- spec section 10
# ==========================================================================

def test_reproducible_mode_is_byte_identical(tmp_path):
    files = {"a.txt": b"stable\n" * 200, "b/c.py": b"x = 1\n" * 200}
    src = make_tree(tmp_path / "src", files)
    one = str(tmp_path / "one.pakt")
    two = str(tmp_path / "two.pakt")
    pack([src], one, reproducible=True)

    # Change every mtime; a reproducible archive must not notice.
    for root, _dirs, names in os.walk(src):
        for n in names:
            p = os.path.join(root, n)
            os.utime(p, (1_000_000, 1_000_000))
    pack([src], two, reproducible=True)

    assert open(one, "rb").read() == open(two, "rb").read()


def test_reproducible_flag_is_recorded(tmp_path):
    src = make_tree(tmp_path / "src", {"a.txt": b"x" * 100})
    arc = str(tmp_path / "r.pakt")
    pack([src], arc, reproducible=True)
    with open_pakt(arc) as a:
        assert a.header.reproducible


def test_non_reproducible_archives_keep_timestamps(tmp_path):
    src = make_tree(tmp_path / "src", {"a.txt": b"x" * 100})
    arc = str(tmp_path / "n.pakt")
    pack([src], arc)
    with open_pakt(arc) as a:
        entry = next(e for e in a.entries if e.path.endswith("a.txt"))
        assert entry.mtime_ns > 0


# ==========================================================================
# Security -- spec section 13, all normative
# ==========================================================================

def test_path_traversal_is_refused(tmp_path):
    """The classic zip-slip. An extractor must never write outside root."""
    arc = str(tmp_path / "evil.pakt")
    payload = b"pwned"
    entry = FileEntry(path="placeholder", plain_size=len(payload),
                      block_index=0)
    forge_archive(arc, [entry], [payload])

    # Rewrite the stored path to escape, after all writer checks.
    raw = open(arc, "rb").read().replace(b"placeholder", b"../escaped\x00\x00")
    open(arc, "wb").write(raw)

    with pytest.raises((SecurityError, PaktFormatError, PaktCorruptError)):
        with open_pakt(arc) as a:
            a.extract_all(tmp_path / "out")
    assert not (tmp_path / "escaped").exists()


def test_absolute_path_entry_is_refused(tmp_path):
    arc = str(tmp_path / "abs.pakt")
    entry = FileEntry(path="/etc/passwd", plain_size=3, block_index=0)
    forge_archive(arc, [entry], [b"bad"])
    with pytest.raises((SecurityError, PaktFormatError)):
        with open_pakt(arc) as a:
            a.extract_all(tmp_path / "out")


def test_decompression_bomb_is_refused_before_decoding(tmp_path):
    """
    The block table declares the expansion, so a bomb is caught from
    metadata alone -- it never gets inflated.
    """
    arc = str(tmp_path / "bomb.pakt")
    entry = FileEntry(path="bomb", plain_size=10, block_index=0)
    forge_archive(arc, [entry], [b"tiny"])

    with open(arc, "r+b") as fh:
        header = Header.unpack(fh.read(C.HEADER_SIZE))
        index = Index.deserialise(
            open(arc, "rb").read()[
                header.index_b_offset + C.INDEX_PREAMBLE_SIZE:
                header.index_b_offset + header.index_b_length])
        assert index.blocks

    with open_pakt(arc) as a:
        a.index.blocks[0].plain_size = 10_000_000
        a.index.blocks[0].stored_size = 4
        with pytest.raises(SecurityError, match="bomb"):
            a.extract_all(tmp_path / "out")


def test_total_size_cap_is_enforced(tmp_path):
    src = make_tree(tmp_path / "src", {"a.txt": b"x" * 50_000})
    arc = str(tmp_path / "big.pakt")
    pack([src], arc)
    with open_pakt(arc) as a:
        with pytest.raises(SecurityError, match="cap"):
            a.extract_all(tmp_path / "out",
                          limits=ExtractLimits(max_total_bytes=1000))


def test_entry_count_cap_is_enforced(tmp_path):
    src = make_tree(tmp_path / "src",
                    {f"f{i}.txt": b"x" * 10 for i in range(20)})
    arc = str(tmp_path / "many.pakt")
    pack([src], arc)
    with open_pakt(arc) as a:
        with pytest.raises(SecurityError, match="entries"):
            a.extract_all(tmp_path / "out", limits=ExtractLimits(max_entries=5))


def test_symlinks_are_refused_by_default(tmp_path):
    arc = str(tmp_path / "link.pakt")
    target = b"../../../etc/passwd"
    entry = FileEntry(path="link", entry_type=EntryType.SYMLINK,
                      plain_size=len(target), block_index=0)
    forge_archive(arc, [entry], [target])
    with open_pakt(arc) as a:
        with pytest.raises(SecurityError, match="symlink"):
            a.extract_all(tmp_path / "out")


def test_escaping_symlink_is_refused_even_when_symlinks_allowed(tmp_path):
    arc = str(tmp_path / "link2.pakt")
    target = b"../../outside"
    entry = FileEntry(path="link", entry_type=EntryType.SYMLINK,
                      plain_size=len(target), block_index=0)
    forge_archive(arc, [entry], [target])
    with open_pakt(arc) as a:
        with pytest.raises(SecurityError):
            a.extract_all(tmp_path / "out",
                          limits=ExtractLimits(allow_symlinks=True))


def test_tampered_block_fails_its_crc(tmp_path):
    src = make_tree(tmp_path / "src", {"a.txt": b"authentic content\n" * 200})
    arc = str(tmp_path / "t.pakt")
    pack([src], arc)

    with open(arc, "rb") as fh:
        raw = bytearray(fh.read())
    header = Header.unpack(bytes(raw[:C.HEADER_SIZE]))
    block_area = header.index_a_offset + header.index_a_length
    raw[block_area + 5] ^= 0xFF
    open(arc, "wb").write(bytes(raw))

    with open_pakt(arc) as a:
        entry = next(e for e in a.entries if e.path.endswith("a.txt"))
        with pytest.raises(PaktCorruptError):
            a.read(entry)


def test_hash_mismatch_is_a_hard_failure(tmp_path):
    arc = str(tmp_path / "h.pakt")
    payload = b"content"
    entry = FileEntry(path="f.txt", plain_size=len(payload), block_index=0,
                      digest=bytes([1] * 16))          # deliberately wrong
    forge_archive(arc, [entry], [payload])
    with open_pakt(arc) as a:
        with pytest.raises(PaktCorruptError, match="do not match the digest"):
            a.read(a.entries[0])


def test_dedup_reference_chain_is_refused(tmp_path):
    """A chain would let a crafted archive drive unbounded recursion."""
    arc = str(tmp_path / "chain.pakt")
    a_entry = FileEntry(path="a", flags=EntryFlag.DEDUP_REF, dedup_ref=1)
    b_entry = FileEntry(path="b", flags=EntryFlag.DEDUP_REF, dedup_ref=0)
    forge_archive(arc, [a_entry, b_entry], [])
    with open_pakt(arc) as archive:
        with pytest.raises(PaktFormatError, match="chain"):
            archive.read(archive.entries[0])


def test_dedup_reference_out_of_range_is_refused(tmp_path):
    arc = str(tmp_path / "oob.pakt")
    entry = FileEntry(path="a", flags=EntryFlag.DEDUP_REF, dedup_ref=999)
    forge_archive(arc, [entry], [])
    with open_pakt(arc) as archive:
        with pytest.raises(PaktFormatError, match="does not exist"):
            archive.read(archive.entries[0])


def test_truncated_file_is_not_mistaken_for_an_archive(tmp_path):
    p = tmp_path / "short.pakt"
    p.write_bytes(b"PAKT\x1a\x0a" + bytes(10))
    with pytest.raises(PaktFormatError):
        open_pakt(str(p))


def test_random_bytes_are_rejected(tmp_path):
    p = tmp_path / "junk.pakt"
    p.write_bytes(os.urandom(4096))
    with pytest.raises(PaktFormatError):
        open_pakt(str(p))


# ==========================================================================
# Relocatability -- spec section 2.1, the polyglot mechanism
# ==========================================================================

def test_container_is_locatable_behind_an_arbitrary_prefix(tmp_path):
    """
    Prepending bytes must not break the archive. This is exactly what
    the polyglot browser-openable form relies on.
    """
    src = make_tree(tmp_path / "src", {"a.txt": b"payload\n" * 100})
    arc = str(tmp_path / "p.pakt")
    pack([src], arc)
    body = open(arc, "rb").read()

    prefix = b"<!doctype html><title>Compakt</title><p>drop this file here</p>"
    footer = Footer.unpack(body[-C.FOOTER_SIZE:])
    relocated = Footer(container_offset=len(prefix),
                       index_b_offset=footer.index_b_offset).pack()

    hybrid = str(tmp_path / "hybrid.html")
    open(hybrid, "wb").write(prefix + body[:-C.FOOTER_SIZE] + relocated)

    with open_pakt(hybrid) as a:
        assert a.container_offset == len(prefix)
        entry = next(e for e in a.entries if e.path.endswith("a.txt"))
        assert a.read(entry) == b"payload\n" * 100


# ==========================================================================
# Codecs
# ==========================================================================

@pytest.mark.parametrize("codec", [Codec.STORE, Codec.ZSTD, Codec.BROTLI, Codec.LZMA])
@pytest.mark.parametrize("level", [FAST, AUTO])
def test_codec_roundtrip(codec, level):
    data = b"repeatable content for compression. " * 500
    stored = compress(data, codec, level=level)
    assert decompress(stored, codec, plain_size=len(data)) == data


@pytest.mark.parametrize("codec", [Codec.ZSTD, Codec.BROTLI, Codec.LZMA])
def test_codecs_are_deterministic(codec):
    """A prerequisite of reproducible archives (spec §10)."""
    data = b"determinism matters here. " * 900
    assert compress(data, codec) == compress(data, codec)


def test_decompress_refuses_an_oversized_claim():
    with pytest.raises(PaktCorruptError, match="cap"):
        decompress(b"", Codec.STORE, plain_size=C.MAX_BLOCK_PLAIN_SIZE + 1)


def test_decompress_detects_a_size_mismatch():
    data = b"hello"
    stored = compress(data, Codec.ZSTD)
    with pytest.raises(PaktCorruptError, match="index says"):
        decompress(stored, Codec.ZSTD, plain_size=999)
