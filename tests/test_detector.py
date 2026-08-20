"""
Tests for core.detector.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

The central claim under test is the one the product is sold on: a file
is classified by what it contains, not by what it is called. Several
tests below deliberately give a file a misleading extension.
"""

from __future__ import annotations

import os
import zlib

import pytest

from core.detector import (
    Codec,
    Detection,
    RoutingClass,
    STORE_ENTROPY_THRESHOLD,
    detect,
    detect_bytes,
    shannon_entropy,
)


# ---------------------------------------------------------------- helpers

def _sqlite_header() -> bytes:
    return b"SQLite format 3\x00" + bytes(1024)


def _png() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + os.urandom(2048)


def _incompressible(n: int = 8192) -> bytes:
    """Bytes with no exploitable structure; entropy close to 8.0."""
    return os.urandom(n)


def _compressible(n: int = 8192) -> bytes:
    """Binary, but low entropy — a run-heavy payload with a NUL."""
    return (b"\x00" + b"\x01\x02\x03\x04" * (n // 4))[:n]


# ---------------------------------------------------------------- entropy

def test_entropy_of_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_entropy_of_uniform_bytes_is_zero():
    assert shannon_entropy(b"A" * 4096) == 0.0


def test_entropy_of_all_byte_values_is_eight():
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_entropy_of_random_is_near_eight():
    assert shannon_entropy(_incompressible(65536)) > 7.9


def test_entropy_of_prose_is_moderate():
    prose = (b"the quick brown fox jumps over the lazy dog. " * 200)
    assert 3.0 < shannon_entropy(prose) < 5.0


# ------------------------------------------------- magic beats extension

def test_sqlite_renamed_to_txt_is_still_caught():
    """The headline claim: a database masquerading as a text file."""
    d = detect_bytes(_sqlite_header(), name="notes.txt")
    assert d.routing_class is RoutingClass.STRUCTURED_BLOCKS
    assert d.confidence == "magic"
    assert d.codec is Codec.ZSTD
    assert "SQLite" in d.reason


def test_png_renamed_to_csv_is_still_stored():
    d = detect_bytes(_png(), name="table.csv")
    assert d.routing_class is RoutingClass.MAXIMUM_ENTROPY_BINARY
    assert d.codec is Codec.STORE
    assert d.stored is True
    assert d.confidence == "magic"


def test_pakt_inside_pakt_is_stored_not_recompressed():
    d = detect_bytes(b"PAKT\x1a\x0a" + _incompressible(), name="inner.pakt")
    assert d.codec is Codec.STORE
    assert d.confidence == "magic"


def test_zip_signature_detected():
    d = detect_bytes(b"PK\x03\x04" + _incompressible(), name="x.bin")
    assert d.routing_class is RoutingClass.MAXIMUM_ENTROPY_BINARY


def test_mp4_ftyp_at_offset_four():
    d = detect_bytes(b"\x00\x00\x00\x20ftypisom" + _incompressible(),
                     name="clip.bin")
    assert d.routing_class is RoutingClass.MAXIMUM_ENTROPY_BINARY
    assert d.confidence == "magic"


def test_wav_is_structured_not_max_entropy():
    """Uncompressed audio looks binary but compresses well."""
    d = detect_bytes(b"RIFF\x00\x00\x00\x00WAVEfmt " + _compressible(),
                     name="tone.wav")
    assert d.routing_class is RoutingClass.STRUCTURED_BLOCKS
    assert d.codec is Codec.ZSTD


def test_elf_is_executable_and_gets_bcj():
    d = detect_bytes(b"\x7fELF\x02\x01\x01" + _compressible(), name="a.out")
    assert d.routing_class is RoutingClass.EXECUTABLE
    assert d.codec is Codec.LZMA
    assert d.apply_bcj is True


def test_pe_executable_gets_bcj():
    d = detect_bytes(b"MZ\x90\x00" + _compressible(), name="tool.exe")
    assert d.routing_class is RoutingClass.EXECUTABLE
    assert d.apply_bcj is True


# ------------------------------------------------------- text heuristics

def test_json_is_repetitive_text():
    d = detect_bytes(b'{"name": "compakt", "version": 1, "ok": true}\n' * 50,
                     name="pkg.json")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT
    assert d.codec is Codec.BROTLI


def test_geojson_is_high_context_vectors():
    body = (b'{"type": "FeatureCollection", "features": '
            b'[{"geometry": {"coordinates": [1.0, 2.0]}}]}')
    d = detect_bytes(body, name="area.geojson")
    assert d.routing_class is RoutingClass.HIGH_CONTEXT_VECTORS


def test_svg_detected_by_root_element_not_extension():
    d = detect_bytes(b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg">'
                     b'<path d="M0 0"/></svg>', name="mystery.dat")
    assert d.routing_class is RoutingClass.HIGH_CONTEXT_VECTORS
    assert d.confidence == "content"


def test_xml_is_repetitive_text():
    d = detect_bytes(b'<?xml version="1.0"?><root><a>1</a><b>2</b></root>',
                     name="cfg.xml")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT


def test_csv_detected_by_column_regularity_not_extension():
    csv = b"id,name,score\n" + b"".join(
        f"{i},row{i},{i * 3}\n".encode() for i in range(200)
    )
    d = detect_bytes(csv, name="mystery.dat")
    assert d.routing_class is RoutingClass.STRUCTURED_BLOCKS
    assert d.confidence == "content"
    assert "comma" in d.reason


def test_tsv_detected_by_tab_regularity():
    tsv = b"a\tb\tc\n" + b"".join(f"{i}\t{i}\t{i}\n".encode() for i in range(100))
    d = detect_bytes(tsv, name="data.unknown")
    assert d.routing_class is RoutingClass.STRUCTURED_BLOCKS


def test_prose_with_commas_is_not_mistaken_for_csv():
    """Regularity, not mere presence, is what identifies tabular data."""
    prose = (b"Well, it was raining, and the dog, which was large, barked.\n"
             b"Later the sun came out.\n"
             b"He said nothing at all.\n"
             b"Then, quietly, everyone left, one by one, without a word.\n") * 30
    d = detect_bytes(prose, name="story.txt")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT


def test_fasta_detected_by_content():
    fasta = b">seq1 description here\n" + b"ACGTACGTNNACGT\n" * 40
    d = detect_bytes(fasta, name="genome.dat")
    assert d.routing_class is RoutingClass.GENOMIC_STRINGS
    assert d.codec is Codec.LZMA
    assert d.confidence == "content"


def test_fastq_detected_by_record_shape():
    fastq = (b"@read1\n" + b"ACGTACGTAC\n" + b"+\n" + b"IIIIIIIIII\n") * 20
    d = detect_bytes(fastq, name="reads.dat")
    assert d.routing_class is RoutingClass.GENOMIC_STRINGS


def test_source_code_is_repetitive_text():
    src = b"def f(x):\n    return x + 1\n\n" * 100
    d = detect_bytes(src, name="mod.py")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT
    assert d.codec is Codec.BROTLI


def test_utf8_prose_is_still_text():
    """Non-ASCII prose fails a naive printable-byte test but is text."""
    lines = [
        "Ceci n'est pas une pipe.",
        "Le café était naïve, mais bon.",
        "日本語のテキストもここにあります。",
        "Größe und Straße, mit Umlauten geschrieben.",
        "Ελληνικά και ελληνικά γράμματα.",
    ]
    body = "".join(f"{lines[i % len(lines)]} {i}\n" for i in range(200)).encode()
    d = detect_bytes(body, name="notes.txt")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT
    assert d.codec is Codec.BROTLI


def test_prose_with_regular_comma_count_is_not_tabular():
    """
    Every line here carries exactly two commas, so delimiter regularity
    alone would call it CSV. Field width is what gives it away: table
    columns are short, sentence fragments are not.
    """
    body = "".join(
        f"On the {i}th day, having waited a considerable while, "
        f"the whole party finally departed without saying anything.\n"
        for i in range(120)
    ).encode()
    d = detect_bytes(body, name="diary.txt")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT


# ------------------------------------------------------ entropy decisions

def test_high_entropy_unknown_binary_is_stored():
    d = detect_bytes(_incompressible(), name="mystery.bin")
    assert d.codec is Codec.STORE
    assert d.confidence == "entropy"
    assert d.entropy >= STORE_ENTROPY_THRESHOLD


def test_compressed_data_with_misleading_extension_is_stored():
    """An extension list cannot catch this; a measurement can."""
    d = detect_bytes(_incompressible(), name="report.docx.txt")
    assert d.codec is Codec.STORE
    assert d.confidence == "entropy"


def test_low_entropy_file_claiming_to_be_zip_is_compressed_anyway():
    """The extension says 'already compressed'. The bytes disagree."""
    d = detect_bytes(_compressible(), name="fake.zip")
    assert d.codec is not Codec.STORE
    assert d.confidence == "entropy"
    assert "entropy is only" in d.reason


def test_deflate_stream_is_high_entropy_and_stored():
    # Varied input, so the deflate stream is large enough to measure.
    # A hyper-repetitive input collapses to a few hundred bytes whose
    # entropy is genuinely low, and correctly is not stored.
    corpus = b"".join(
        f"record {i} field {i * 7} value {i % 97}\n".encode()
        for i in range(5000)
    )
    payload = zlib.compress(corpus, 9)
    d = detect_bytes(payload, name="blob.dat")
    assert d.codec is Codec.STORE


# ------------------------------------------------------------ edge cases

def test_empty_file():
    d = detect_bytes(b"", name="empty.txt", total_size=0)
    assert d.routing_class is RoutingClass.UNKNOWN
    assert d.codec is Codec.STORE
    assert d.confidence == "empty"
    assert d.entropy == 0.0


def test_tiny_file_is_not_over_analysed():
    d = detect_bytes(b"hi", name="a.txt", total_size=2)
    assert d.confidence == "default"
    assert "only 2 bytes" in d.reason


def test_nul_byte_forces_binary_classification():
    d = detect_bytes(b"looks like text\x00but is not" + _compressible(),
                     name="x.txt")
    assert d.routing_class is not RoutingClass.REPETITIVE_TEXT


def test_unknown_binary_defaults_to_structured():
    d = detect_bytes(_compressible(), name="thing.unknownext")
    assert d.routing_class is RoutingClass.STRUCTURED_BLOCKS
    assert d.confidence == "default"


def test_no_extension_still_classifies():
    d = detect_bytes(b"plain words here and there\n" * 100, name="README")
    assert d.routing_class is RoutingClass.REPETITIVE_TEXT


def test_detection_describe_is_readable():
    d = detect_bytes(_sqlite_header(), name="x.db")
    text = d.describe()
    assert "STRUCTURED_BLOCKS" in text and "ZSTD" in text


# ----------------------------------------------------------- file access

def test_detect_reads_a_real_file(tmp_path):
    p = tmp_path / "renamed.txt"
    p.write_bytes(_sqlite_header())
    d = detect(p)
    assert d.routing_class is RoutingClass.STRUCTURED_BLOCKS
    assert d.confidence == "magic"


def test_detect_on_empty_real_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert detect(p).confidence == "empty"


def test_detect_missing_file_does_not_raise(tmp_path):
    """One unreadable file must never abort a whole job."""
    d = detect(tmp_path / "does-not-exist")
    assert isinstance(d, Detection)
    assert d.codec is Codec.STORE
    assert "cannot stat" in d.reason


def test_detect_directory_does_not_raise(tmp_path):
    d = detect(tmp_path)
    assert isinstance(d, Detection)


def test_sample_is_capped(tmp_path):
    from core.detector import MAX_SAMPLE
    p = tmp_path / "big.txt"
    p.write_bytes(b"x" * (MAX_SAMPLE * 3))
    d = detect(p)
    assert d.sample_size == MAX_SAMPLE


# ------------------------------------------------- format-spec agreement

def test_routing_class_ids_match_the_format_spec():
    """These IDs are frozen by docs/pakt-format-spec.md section 6.3."""
    assert RoutingClass.UNKNOWN == 0
    assert RoutingClass.REPETITIVE_TEXT == 1
    assert RoutingClass.STRUCTURED_BLOCKS == 2
    assert RoutingClass.HIGH_CONTEXT_VECTORS == 3
    assert RoutingClass.GENOMIC_STRINGS == 4
    assert RoutingClass.MAXIMUM_ENTROPY_BINARY == 5
    assert RoutingClass.EXECUTABLE == 6


def test_codec_ids_match_the_format_spec():
    """Frozen by docs/pakt-format-spec.md section 6.2."""
    assert Codec.STORE == 0
    assert Codec.ZSTD == 1
    assert Codec.BROTLI == 2
    assert Codec.LZMA == 3


def test_every_routing_class_has_a_codec():
    for cls in RoutingClass:
        d = detect_bytes(b"x" * 100, name="probe")
        assert isinstance(d.codec, Codec)
        from core.detector import _CLASS_TO_CODEC
        assert cls in _CLASS_TO_CODEC, f"{cls.name} has no codec mapping"
