"""
Binary signature and content detection.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Determines what a file actually *is*, so the compressor can route it to
the codec that suits its data profile.

The rule this module exists to enforce: **never trust a file
extension.** A SQL database renamed to ``.txt`` must be caught, and it
is — SQLite has a magic number and its entropy profile looks nothing
like prose.

Detection runs in three tiers, most reliable first:

1. **Magic bytes.** Definitive where they exist. A PNG is a PNG.
2. **Content heuristics.** Most of the formats Compakt cares about have
   no magic number at all — CSV, JSON, XML, source code, FASTA, YAML
   are all plain text and indistinguishable by header. These are
   separated by measuring the bytes: Shannon entropy, printable ratio,
   line structure, delimiter regularity, and format-specific probes.
3. **Extension.** Consulted last, as a tiebreaker only, and never
   permitted to override a confident content signal.

A detection always reports which tier produced it, so ``pakt explain``
can tell a user *why* a file was routed where it was.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass
from math import log2
from typing import Optional

from core.container import Codec, RoutingClass

__all__ = [
    "RoutingClass",
    "Codec",
    "Detection",
    "detect",
    "detect_bytes",
    "shannon_entropy",
    "MAX_SAMPLE",
    "STORE_ENTROPY_THRESHOLD",
]


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: Bytes read from the head of a file for analysis. Matches the sample
#: size used by trial compression, so the two can share a read.
MAX_SAMPLE = 65_536

#: Above this many bits per byte the data is already compressed or
#: encrypted, and compressing it again wastes CPU and usually adds bytes.
#: Measured rather than guessed from an extension list, which by
#: definition cannot catch renamed or unknown formats.
STORE_ENTROPY_THRESHOLD = 7.5

#: Below this ratio of printable bytes, a sample is not text.
_PRINTABLE_TEXT_RATIO = 0.85

#: Files at or under this size are not worth routing carefully.
_TINY_FILE_BYTES = 64

#: Mean field width above which regularly-delimited lines are prose
#: rather than a table. Columns are short; sentences are not.
_MAX_TABULAR_FIELD_WIDTH = 32


# RoutingClass and Codec are defined by the format, so core.container
# owns them and this module re-exports. They were briefly duplicated
# here, which produced enum members that compared equal by value but
# failed every `is` check across the module boundary -- the kind of bug
# that passes unit tests and only shows up at integration.


#: Which codec each routing class is compressed with.
#:
#: Brotli wins on natural-language and markup-heavy text. Zstd wins on
#: structured and columnar data, where its speed matters more than the
#: last percent of ratio. LZMA's large dictionary suits long-range
#: repetition, which is what genomic strings and executables are.
_CLASS_TO_CODEC: dict[RoutingClass, Codec] = {
    RoutingClass.REPETITIVE_TEXT: Codec.BROTLI,
    RoutingClass.HIGH_CONTEXT_VECTORS: Codec.BROTLI,
    RoutingClass.STRUCTURED_BLOCKS: Codec.ZSTD,
    RoutingClass.GENOMIC_STRINGS: Codec.LZMA,
    RoutingClass.EXECUTABLE: Codec.LZMA,
    RoutingClass.MAXIMUM_ENTROPY_BINARY: Codec.STORE,
    RoutingClass.UNKNOWN: Codec.ZSTD,
}


# --------------------------------------------------------------------------
# Magic signatures
# --------------------------------------------------------------------------

# (offset, signature, routing class, human-readable name)
_MAGIC: tuple[tuple[int, bytes, RoutingClass, str], ...] = (
    # --- our own format, so a .pakt inside a .pakt is stored, not recompressed
    (0, b"PAKT\x1a\x0a", RoutingClass.MAXIMUM_ENTROPY_BINARY, "pakt archive"),

    # --- databases and columnar stores: highly structured, compress well
    (0, b"SQLite format 3\x00", RoutingClass.STRUCTURED_BLOCKS, "SQLite database"),
    (0, b"PAR1", RoutingClass.STRUCTURED_BLOCKS, "Parquet"),
    (0, b"\x89HDF\r\n\x1a\n", RoutingClass.STRUCTURED_BLOCKS, "HDF5"),
    (0, b"ARROW1", RoutingClass.STRUCTURED_BLOCKS, "Arrow IPC"),
    (0, b"FEA1", RoutingClass.STRUCTURED_BLOCKS, "Feather"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", RoutingClass.STRUCTURED_BLOCKS,
     "OLE compound document"),

    # --- uncompressed media: looks binary, but compresses very well
    (0, b"BM", RoutingClass.STRUCTURED_BLOCKS, "BMP bitmap"),
    (0, b"II*\x00", RoutingClass.STRUCTURED_BLOCKS, "TIFF (little-endian)"),
    (0, b"MM\x00*", RoutingClass.STRUCTURED_BLOCKS, "TIFF (big-endian)"),

    # --- executables and object code: BCJ filtering pays off here
    (0, b"\x7fELF", RoutingClass.EXECUTABLE, "ELF binary"),
    (0, b"MZ", RoutingClass.EXECUTABLE, "PE/DOS executable"),
    (0, b"\xca\xfe\xba\xbe", RoutingClass.EXECUTABLE, "Java class"),
    (0, b"\x00asm", RoutingClass.EXECUTABLE, "WebAssembly"),
    (0, b"\xcf\xfa\xed\xfe", RoutingClass.EXECUTABLE, "Mach-O (64-bit LE)"),
    (0, b"\xce\xfa\xed\xfe", RoutingClass.EXECUTABLE, "Mach-O (32-bit LE)"),

    # --- already compressed or encrypted: store, never recompress
    (0, b"\x89PNG\r\n\x1a\n", RoutingClass.MAXIMUM_ENTROPY_BINARY, "PNG"),
    (0, b"\xff\xd8\xff", RoutingClass.MAXIMUM_ENTROPY_BINARY, "JPEG"),
    (0, b"GIF87a", RoutingClass.MAXIMUM_ENTROPY_BINARY, "GIF"),
    (0, b"GIF89a", RoutingClass.MAXIMUM_ENTROPY_BINARY, "GIF"),
    (0, b"%PDF-", RoutingClass.MAXIMUM_ENTROPY_BINARY, "PDF"),
    (0, b"PK\x03\x04", RoutingClass.MAXIMUM_ENTROPY_BINARY, "ZIP or ZIP-based"),
    (0, b"PK\x05\x06", RoutingClass.MAXIMUM_ENTROPY_BINARY, "ZIP (empty)"),
    (0, b"PK\x07\x08", RoutingClass.MAXIMUM_ENTROPY_BINARY, "ZIP (spanned)"),
    (0, b"\x1f\x8b", RoutingClass.MAXIMUM_ENTROPY_BINARY, "gzip"),
    (0, b"BZh", RoutingClass.MAXIMUM_ENTROPY_BINARY, "bzip2"),
    (0, b"\xfd7zXZ\x00", RoutingClass.MAXIMUM_ENTROPY_BINARY, "xz"),
    (0, b"\x28\xb5\x2f\xfd", RoutingClass.MAXIMUM_ENTROPY_BINARY, "zstandard"),
    (0, b"7z\xbc\xaf\x27\x1c", RoutingClass.MAXIMUM_ENTROPY_BINARY, "7z"),
    (0, b"Rar!\x1a\x07\x00", RoutingClass.MAXIMUM_ENTROPY_BINARY, "RAR4"),
    (0, b"Rar!\x1a\x07\x01\x00", RoutingClass.MAXIMUM_ENTROPY_BINARY, "RAR5"),
    (0, b"MSCF", RoutingClass.MAXIMUM_ENTROPY_BINARY, "CAB"),
    (0, b"\x1a\x45\xdf\xa3", RoutingClass.MAXIMUM_ENTROPY_BINARY, "Matroska/WebM"),
    (0, b"OggS", RoutingClass.MAXIMUM_ENTROPY_BINARY, "Ogg"),
    (0, b"fLaC", RoutingClass.MAXIMUM_ENTROPY_BINARY, "FLAC"),
    (0, b"ID3", RoutingClass.MAXIMUM_ENTROPY_BINARY, "MP3 (ID3)"),
    (0, b"\xff\xfb", RoutingClass.MAXIMUM_ENTROPY_BINARY, "MP3"),
    (4, b"ftyp", RoutingClass.MAXIMUM_ENTROPY_BINARY, "ISO base media (MP4/MOV)"),
)

# RIFF containers need their subtype checked at offset 8.
_RIFF_SUBTYPES: dict[bytes, tuple[RoutingClass, str]] = {
    b"WAVE": (RoutingClass.STRUCTURED_BLOCKS, "WAV (uncompressed audio)"),
    b"AVI ": (RoutingClass.MAXIMUM_ENTROPY_BINARY, "AVI"),
    b"WEBP": (RoutingClass.MAXIMUM_ENTROPY_BINARY, "WebP"),
}


# --------------------------------------------------------------------------
# Extension fallback
# --------------------------------------------------------------------------

_EXT_CLASS: dict[str, RoutingClass] = {}


def _register(cls: RoutingClass, *exts: str) -> None:
    for e in exts:
        _EXT_CLASS[e] = cls


_register(
    RoutingClass.REPETITIVE_TEXT,
    ".txt", ".md", ".rst", ".log", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".java", ".go", ".rs",
    ".rb", ".php", ".swift", ".kt", ".scala", ".lua", ".pl", ".r",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".sql", ".html", ".htm",
    ".css", ".scss", ".less", ".xml", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".tex", ".po", ".pot", ".srt", ".vtt",
)
_register(
    RoutingClass.HIGH_CONTEXT_VECTORS,
    ".svg", ".geojson", ".kml", ".gpx", ".obj", ".gltf", ".dae", ".ply",
    ".stl", ".shp", ".wkt",
)
_register(
    RoutingClass.STRUCTURED_BLOCKS,
    ".csv", ".tsv", ".parquet", ".db", ".sqlite", ".sqlite3", ".arrow",
    ".feather", ".h5", ".hdf5", ".bmp", ".wav", ".tif", ".tiff", ".raw",
    ".pcm", ".npy",
)
_register(
    RoutingClass.GENOMIC_STRINGS,
    ".fasta", ".fa", ".fna", ".ffn", ".faa", ".fastq", ".fq", ".sam",
    ".vcf", ".bed",
)
_register(
    RoutingClass.MAXIMUM_ENTROPY_BINARY,
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".br", ".lz4",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif",
    ".mp3", ".mp4", ".m4a", ".aac", ".ogg", ".opus", ".flac", ".mkv",
    ".mov", ".avi", ".webm", ".pdf", ".docx", ".xlsx", ".pptx", ".epub",
    ".jar", ".apk", ".whl", ".pakt",
)
_register(RoutingClass.EXECUTABLE, ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".wasm")

#: Extensions whose files are text but which should still be treated as
#: executable-adjacent for filtering purposes. Deliberately empty for
#: now; BCJ on text is never a win.
_BCJ_CLASSES = frozenset({RoutingClass.EXECUTABLE})


# --------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Detection:
    """The outcome of inspecting one file."""

    routing_class: RoutingClass
    codec: Codec
    entropy: float
    #: Which tier decided this: "magic", "content", "extension",
    #: "entropy", "empty" or "default".
    confidence: str
    #: Human-readable justification, surfaced by ``pakt explain``.
    reason: str
    sample_size: int
    apply_bcj: bool = False

    @property
    def stored(self) -> bool:
        """True when the file will be stored raw rather than compressed."""
        return self.codec is Codec.STORE

    def describe(self) -> str:
        return (
            f"{self.routing_class.name} via {self.confidence} "
            f"-> {self.codec.name} (entropy {self.entropy:.2f} b/B) — {self.reason}"
        )


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy of ``data`` in bits per byte, in the range [0, 8].

    8.0 means every byte value is equally likely, which is what
    compressed and encrypted data looks like. English prose sits near
    4.5; source code somewhat lower.
    """
    if not data:
        return 0.0
    n = len(data)
    total = 0.0
    for count in Counter(data).values():
        p = count / n
        total -= p * log2(p)
    return total


def _printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII, tab, LF or CR."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def _looks_like_text(data: bytes) -> bool:
    """
    True when the sample is plausibly text.

    A NUL byte is treated as decisive evidence of binary content: no
    text encoding Compakt cares about produces one, and UTF-16 is
    handled by its BOM before reaching here.
    """
    if not data:
        return False
    if b"\x00" in data:
        return False
    if _printable_ratio(data) >= _PRINTABLE_TEXT_RATIO:
        return True
    # High-ratio UTF-8 (accented prose, CJK) fails the ASCII test but is
    # still text. Trust a clean decode instead.
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# --------------------------------------------------------------------------
# Text sub-classification
# --------------------------------------------------------------------------

_FASTA_HEADER = re.compile(rb"^>[^\n]{0,300}\n", re.MULTILINE)
_NUCLEOTIDE = re.compile(rb"^[ACGTUNacgtun\-\*\s]+$")
_XML_DECL = re.compile(rb"^\s*<\?xml[\s>]", re.IGNORECASE)
_SVG_ROOT = re.compile(rb"<svg[\s>]", re.IGNORECASE)
_HTML_ROOT = re.compile(rb"<(!doctype\s+html|html)[\s>]", re.IGNORECASE)


def _is_fasta(sample: bytes) -> bool:
    """FASTA: '>' description lines alternating with nucleotide runs."""
    if not sample.lstrip().startswith(b">"):
        return False
    if not _FASTA_HEADER.search(sample):
        return False
    seq = b"".join(
        line for line in sample.split(b"\n")[1:]
        if line and not line.startswith(b">")
    )
    if len(seq) < 20:
        return False
    return bool(_NUCLEOTIDE.match(seq[:4096]))


def _is_fastq(sample: bytes) -> bool:
    """FASTQ: four-line records, '@' header then sequence then '+'."""
    lines = sample.split(b"\n")
    if len(lines) < 4 or not lines[0].startswith(b"@"):
        return False
    return lines[2].startswith(b"+")


def _is_json(sample: bytes) -> bool:
    """
    Cheap structural probe. A full parse is not possible on a truncated
    sample, so this checks the opening token and that brace-like
    punctuation is actually present in quantity.
    """
    stripped = sample.lstrip()
    if not stripped[:1] in (b"{", b"["):
        return False
    head = stripped[:4096]
    return head.count(b'"') >= 2 and (b":" in head or head[:1] == b"[")


def _is_geojson(sample: bytes) -> bool:
    head = sample[:8192]
    return b'"FeatureCollection"' in head or b'"coordinates"' in head


def _delimiter_regularity(sample: bytes, delim: bytes) -> float:
    """
    How consistently ``delim`` appears the same number of times per
    line. Returns 0.0 to 1.0. Tabular data scores near 1.0; prose that
    happens to contain commas scores low.
    """
    lines = [ln for ln in sample.split(b"\n")[:200] if ln.strip()]
    if len(lines) < 3:
        return 0.0
    # Identical repeated lines trivially agree on delimiter count, which
    # would let a paragraph repeated verbatim pass as a table. Real
    # tabular data varies from row to row.
    if len(set(lines)) < 3:
        return 0.0
    counts = [ln.count(delim) for ln in lines[:-1]]  # last line may be cut
    if not counts or counts[0] == 0:
        return 0.0
    modal = Counter(counts).most_common(1)[0]
    regularity = modal[1] / len(counts)
    if regularity < 0.9:
        return regularity
    # Regularity alone is not enough. Prose can carry a steady comma
    # count per line while being nothing like a table. Real columns are
    # short, so mean field width is what separates the two.
    fields = [f for ln in lines[:-1] for f in ln.split(delim)]
    if fields:
        mean_width = sum(len(f) for f in fields) / len(fields)
        if mean_width > _MAX_TABULAR_FIELD_WIDTH:
            return 0.0
    return regularity


def _classify_text(sample: bytes, ext: str) -> tuple[RoutingClass, str, str]:
    """
    Sub-classify a sample already known to be text.

    Returns ``(routing_class, confidence_tier, reason)``.
    """
    if _is_fastq(sample):
        return (RoutingClass.GENOMIC_STRINGS, "content",
                "FASTQ four-line record structure")
    if _is_fasta(sample):
        return (RoutingClass.GENOMIC_STRINGS, "content",
                "FASTA '>' records over nucleotide alphabet")

    if _SVG_ROOT.search(sample[:4096]):
        return (RoutingClass.HIGH_CONTEXT_VECTORS, "content", "SVG root element")

    if _is_json(sample):
        if _is_geojson(sample):
            return (RoutingClass.HIGH_CONTEXT_VECTORS, "content",
                    "GeoJSON geometry keys")
        return (RoutingClass.REPETITIVE_TEXT, "content", "JSON object or array")

    if _XML_DECL.match(sample) or _HTML_ROOT.search(sample[:4096]):
        return (RoutingClass.REPETITIVE_TEXT, "content", "XML or HTML markup")

    for delim, name in ((b",", "comma"), (b"\t", "tab"), (b";", "semicolon")):
        score = _delimiter_regularity(sample, delim)
        if score >= 0.9:
            return (RoutingClass.STRUCTURED_BLOCKS, "content",
                    f"regular {name}-delimited columns ({score:.0%} of lines)")

    if ext in _EXT_CLASS and _EXT_CLASS[ext] in (
        RoutingClass.HIGH_CONTEXT_VECTORS,
        RoutingClass.GENOMIC_STRINGS,
        RoutingClass.STRUCTURED_BLOCKS,
    ):
        return (_EXT_CLASS[ext], "extension", f"text with '{ext}' extension")

    return (RoutingClass.REPETITIVE_TEXT, "content", "plain text")


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _match_magic(sample: bytes) -> Optional[tuple[RoutingClass, str]]:
    if sample[:4] == b"RIFF" and len(sample) >= 12:
        sub = _RIFF_SUBTYPES.get(sample[8:12])
        if sub:
            return sub
        return (RoutingClass.MAXIMUM_ENTROPY_BINARY, "RIFF container")

    # ustar magic sits deep in the first tar header.
    if len(sample) >= 262 and sample[257:262] == b"ustar":
        return (RoutingClass.UNKNOWN, "tar archive (contents decide)")

    for offset, sig, cls, name in _MAGIC:
        end = offset + len(sig)
        if len(sample) >= end and sample[offset:end] == sig:
            return (cls, name)
    return None


def detect_bytes(
    sample: bytes,
    *,
    name: Optional[str] = None,
    total_size: Optional[int] = None,
) -> Detection:
    """
    Classify a file from a sample of its leading bytes.

    ``sample`` should be the first :data:`MAX_SAMPLE` bytes, or the
    whole file if it is smaller. ``name`` supplies the filename for the
    extension tiebreaker. ``total_size`` is the file's full size when
    the sample is partial.
    """
    size = total_size if total_size is not None else len(sample)
    ext = os.path.splitext(name)[1].lower() if name else ""
    entropy = shannon_entropy(sample)

    if size == 0:
        return Detection(RoutingClass.UNKNOWN, Codec.STORE, 0.0,
                         "empty", "zero-length file", 0)

    # Tier 1 -- magic bytes. Definitive.
    hit = _match_magic(sample)
    if hit is not None and hit[0] is not RoutingClass.UNKNOWN:
        cls, name_of = hit
        return Detection(
            cls, _CLASS_TO_CODEC[cls], entropy, "magic",
            f"{name_of} signature", len(sample),
            apply_bcj=cls in _BCJ_CLASSES,
        )

    # A tiny file carries no usable signal and cannot pay back analysis.
    if size <= _TINY_FILE_BYTES:
        cls = _EXT_CLASS.get(ext, RoutingClass.REPETITIVE_TEXT)
        return Detection(cls, _CLASS_TO_CODEC[cls], entropy, "default",
                         f"file is only {size} bytes", len(sample))

    # Tier 2 -- content heuristics.
    if _looks_like_text(sample):
        cls, tier, reason = _classify_text(sample, ext)
        return Detection(cls, _CLASS_TO_CODEC[cls], entropy, tier, reason,
                         len(sample))

    # Binary without a known signature. Entropy decides whether there is
    # anything left to squeeze. This is what catches compressed data
    # behind an unknown or deliberately misleading extension.
    if entropy >= STORE_ENTROPY_THRESHOLD:
        return Detection(
            RoutingClass.MAXIMUM_ENTROPY_BINARY, Codec.STORE, entropy,
            "entropy",
            f"{entropy:.2f} bits/byte is at or above the {STORE_ENTROPY_THRESHOLD} "
            f"threshold; already compressed or encrypted",
            len(sample),
        )

    # Tier 3 -- extension, as a tiebreaker only.
    if ext in _EXT_CLASS:
        cls = _EXT_CLASS[ext]
        # The content check above already established this is not text.
        # An extension implying text must not overrule that. Same
        # principle as the entropy override below, applied the other way
        # round: measurement beats naming, in both directions.
        if cls in (RoutingClass.REPETITIVE_TEXT, RoutingClass.HIGH_CONTEXT_VECTORS):
            cls = RoutingClass.STRUCTURED_BLOCKS
            return Detection(
                cls, _CLASS_TO_CODEC[cls], entropy, "content",
                f"'{ext}' implies text but the content is binary "
                f"({entropy:.2f} bits/byte)",
                len(sample),
            )
        # Never let an extension claim "already compressed" when the
        # measured entropy says otherwise. The measurement wins.
        if cls is RoutingClass.MAXIMUM_ENTROPY_BINARY:
            cls = RoutingClass.STRUCTURED_BLOCKS
            return Detection(
                cls, _CLASS_TO_CODEC[cls], entropy, "entropy",
                f"'{ext}' suggests compressed data but entropy is only "
                f"{entropy:.2f} bits/byte, so it is compressed anyway",
                len(sample),
            )
        return Detection(cls, _CLASS_TO_CODEC[cls], entropy, "extension",
                         f"binary with '{ext}' extension", len(sample),
                         apply_bcj=cls in _BCJ_CLASSES)

    return Detection(
        RoutingClass.STRUCTURED_BLOCKS, _CLASS_TO_CODEC[RoutingClass.STRUCTURED_BLOCKS],
        entropy, "default",
        f"unrecognised binary at {entropy:.2f} bits/byte", len(sample),
    )


def detect(path: str | os.PathLike[str]) -> Detection:
    """
    Classify the file at ``path``.

    Reads at most :data:`MAX_SAMPLE` bytes. Never raises for an
    unreadable file: permission errors and races are reported as an
    UNKNOWN/STORE detection so a single bad file cannot abort a job.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return Detection(RoutingClass.UNKNOWN, Codec.STORE, 0.0, "default",
                         f"cannot stat file: {exc.strerror or exc}", 0)

    try:
        with open(path, "rb") as fh:
            sample = fh.read(MAX_SAMPLE)
    except OSError as exc:
        return Detection(RoutingClass.UNKNOWN, Codec.STORE, 0.0, "default",
                         f"cannot read file: {exc.strerror or exc}", 0)

    return detect_bytes(sample, name=os.fspath(path), total_size=size)
