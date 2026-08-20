"""
Codec dispatch for the .pakt container.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Thin, deliberately boring wrappers around Zstandard, Brotli and LZMA,
plus the BCJ branch filter. Every codec here is a pure function of its
input: no sockets, no temporary files, no global state.

Determinism matters. Compakt offers reproducible archives, so each of
these must produce identical bytes for identical input at a fixed
level, on any machine. All four do.

What this module does *not* contain is any decision about *which* codec
to use. That judgement is the routing engine's, and it lives elsewhere.
"""

from __future__ import annotations

import lzma
from dataclasses import dataclass
from typing import Optional

from core.container import (
    Codec,
    MAX_BLOCK_PLAIN_SIZE,
    PaktCorruptError,
    PaktUnsupportedError,
)

__all__ = [
    "Level", "AUTO", "FAST",
    "compress", "decompress", "available_codecs",
    "apply_bcj", "reverse_bcj", "bcj_available",
    "lzma_dict_size", "brotli_lgwin",
    "BROTLI_WINDOW_MAX", "LZMA_DICT_MAX",
]


# --------------------------------------------------------------------------
# Optional imports
# --------------------------------------------------------------------------
# Every codec is declared in the format, but an implementation is
# permitted to lack one -- it must then refuse clearly rather than
# guess (spec section 14). These probes are what make that possible.

try:
    import zstandard as _zstd
except ImportError:                                   # pragma: no cover
    _zstd = None

try:
    import brotli as _brotli
except ImportError:                                   # pragma: no cover
    _brotli = None

try:
    import bcj as _bcj
except ImportError:                                   # pragma: no cover
    _bcj = None


def available_codecs() -> set[Codec]:
    """Codecs this build can actually encode and decode."""
    found = {Codec.STORE, Codec.LZMA}                 # LZMA is stdlib
    if _zstd is not None:
        found.add(Codec.ZSTD)
    if _brotli is not None:
        found.add(Codec.BROTLI)
    return found


def bcj_available() -> bool:
    return _bcj is not None


# --------------------------------------------------------------------------
# Levels
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Level:
    """
    A SEARCH EFFORT profile, one setting per codec.

    Effort only. A codec's window -- how far back it may look for a
    repeat -- is sized from the data being compressed and is not part of
    this, for the reasons set out below.
    """

    name: str
    zstd: int
    brotli: int
    lzma_preset: int


#: The default, and the only setting most people should ever use. It is
#: called auto because the interesting decisions are not in this table:
#: the codec is chosen per block by measurement, the window is sized to
#: the block, and effort is scaled down on blocks large enough for it to
#: matter. This triple is only the ceiling those decisions work under.
AUTO = Level("auto", zstd=15, brotli=10, lzma_preset=6)

#: For bulk. The one question the data cannot answer is how much of the
#: user's time we may spend -- a 50 GB backup and a 10 MB folder want
#: different answers to that, and only the user knows which they have.
#: That is the whole reason a second setting exists.
FAST = Level("fast", zstd=3, brotli=5, lzma_preset=1)

# WHY THERE IS NO "MAXIMUM" ANY MORE. There was one -- zstd 22, brotli
# q11, lzma preset 9 -- and measured across nine corpora it bought about
# 0.5% for two to three times the time, while coming out LARGER than the
# default on two of them. A setting that can lose while costing triple
# is not a choice worth offering.
#
# Most of what it appeared to buy was reach, not effort: preset 9 is
# preset 6 with a bigger dictionary, and zstd 22 jumps to a 128 MiB
# window where zstd 15 sits at 4 MiB. The default now sizes the window
# from the data, so it gets that part for almost nothing, and what
# remained was the expensive half.


# --------------------------------------------------------------------------
# How far back a codec may look
# --------------------------------------------------------------------------
#
# THE LEVEL DOES NOT SET THIS, AND MUST NOT. A codec's window is how far
# back it can find a repeat; the level is how hard it searches within
# that window. Presets bundle the two, so asking for more search also
# asks for more memory and vice versa -- and the two cost wildly
# different amounts. MEASURED on a 64 MiB block of enwik8:
#
#   lzma preset 6 (8 MiB dictionary)     0.2643    57.9s
#   lzma preset 9 (64 MiB dictionary)    0.2521    64.2s   <- 4.6% smaller
#   brotli q11, lgwin 22 (4 MiB)         0.2707   183.7s
#   brotli q11, lgwin 24 (16 MiB)        0.2582   186.9s   <- 4.6% smaller
#
# Both gains are 4.6% for almost no time -- 11% for LZMA, 1.7% for
# brotli. Search effort, by contrast, buys about 0.5% for two to three
# times the time. So the window is the cheap half of the bargain and
# there is no reason to ration it by level: it is sized from the DATA at
# every level, and the level continues to govern search effort alone.
#
# Both defaults were badly wrong before this. LZMA inherited preset 6's
# 8 MiB on blocks up to 64 MiB, and brotli was never given a window at
# all, so it took the library default of lgwin 22 -- a 4 MiB window on
# blocks sixteen times that size.

#: Largest LZMA dictionary we will ask for, which is also the memory a
#: reader needs to decode one block. 64 MiB is the block cap, so a
#: dictionary can never usefully exceed it, and it matches 7-Zip -mx9 --
#: no archive we write demands more to open than the tool we are
#: measured against.
LZMA_DICT_MAX = 64 * 1024 * 1024

#: liblzma's floor. Anything smaller is rejected outright.
LZMA_DICT_MIN = 4096

#: Brotli's largest STANDARD window, from RFC 7932: lgwin 24 is 16 MiB.
#: Larger windows exist but are the "large window" extension, which a
#: decoder must opt into -- so writing one would produce archives that
#: conforming brotli decoders refuse. This is a hard ceiling, not a
#: tuning choice, and it is the reason brotli cannot reach across a
#: block bigger than 16 MiB however much effort it is given.
BROTLI_LGWIN_MAX = 24
BROTLI_LGWIN_MIN = 10

#: The block size above which brotli can no longer see the whole block.
BROTLI_WINDOW_MAX = 1 << BROTLI_LGWIN_MAX

#: Zstandard's window is level-derived too, and was starved the same
#: way: level 15 defaults to windowLog 22, a 4 MiB window, on blocks of
#: up to 64 MiB. (Level 22 jumps to windowLog 27, which is part of why
#: the old MAXIMUM setting sometimes looked better than it deserved --
#: it was buying window, not search.) 27 is the reference decoder's
#: default acceptance limit, so staying at or below it keeps every frame
#: readable by a stock zstd; the 64 MiB block cap means 26 is the most
#: we ever actually ask for.
ZSTD_WINDOW_LOG_MAX = 27
ZSTD_WINDOW_LOG_MIN = 10


def _covering_pow2(size: int) -> int:
    """The smallest power of two that is at least ``size``."""
    return 1 << max(0, (max(size, 1) - 1).bit_length())


def lzma_dict_size(size: int) -> int:
    """
    A dictionary just large enough to reach across ``size`` bytes.

    Exact rather than approximate: a dictionary cannot reference bytes
    the input does not contain, so anything beyond the input is wasted
    reader memory, and anything short of it costs ratio. Sizing it to
    the data is therefore better than every preset in both directions --
    it gives a 64 MiB block the reach preset 6 withheld, and spares a
    small block the memory preset 9 would have demanded.
    """
    return max(LZMA_DICT_MIN, min(_covering_pow2(size), LZMA_DICT_MAX))


def brotli_lgwin(size: int) -> int:
    """
    log2 of a brotli window that covers ``size``, within RFC 7932.

    Capped at 16 MiB, so on a larger block brotli is reaching across
    only part of it. That is a property of the format and the reason a
    large block is not a fair contest between brotli and LZMA.

    Rounds up one step further than :func:`lzma_dict_size` does, and
    deliberately: a brotli window holds ``(1 << lgwin) - 16`` bytes, so
    an input of exactly 2**k needs lgwin k+1 to be covered, where an
    LZMA dictionary of 2**k covers 2**k exactly.
    """
    want = max(size, 1).bit_length()
    return max(BROTLI_LGWIN_MIN, min(want, BROTLI_LGWIN_MAX))


def zstd_window_log(size: int) -> int:
    """
    log2 of a zstd window that covers ``size``, within a stock decoder.

    Level-independent for the same reason as the other two: reach is
    cheap and search is not, so there is no case for rationing reach by
    the effort setting the user chose.
    """
    want = (max(size, 1) - 1).bit_length()
    return max(ZSTD_WINDOW_LOG_MIN, min(want, ZSTD_WINDOW_LOG_MAX))


def _lzma_filters(level: Level, size: int) -> list[dict]:
    """
    LZMA1 filters: the preset's search settings, our dictionary size.

    Presets 6 through 9 differ from one another ONLY in dictionary size
    (8, 16, 32 and 64 MiB), so overriding that one field is exactly the
    part of a higher preset worth having, and none of the part that
    merely costs time.
    """
    return [{"id": lzma.FILTER_LZMA1,
             "preset": level.lzma_preset,
             "dict_size": lzma_dict_size(size)}]

_LEVELS = {lv.name: lv for lv in (AUTO, FAST)}


def level_by_name(name: str) -> Level:
    try:
        return _LEVELS[name.lower()]
    except KeyError:
        raise ValueError(
            f"unknown level {name!r}; choose from {sorted(_LEVELS)}") from None


# --------------------------------------------------------------------------
# Compression
# --------------------------------------------------------------------------

def _require(codec: Codec) -> None:
    if codec not in available_codecs():
        raise PaktUnsupportedError(
            f"this build cannot handle {codec.name}: the supporting library "
            f"is not installed")


def compress(
    data: bytes,
    codec: Codec,
    *,
    level: Level = AUTO,
    dictionary: Optional[bytes] = None,
) -> bytes:
    """
    Compress ``data`` with ``codec``.

    Returns the stored bytes exactly as they belong in the container.
    For :attr:`Codec.STORE` this is ``data`` itself.
    """
    _require(codec)

    if codec is Codec.STORE:
        return data

    if codec is Codec.ZSTD:
        # The window travels in the frame header, so widening it needs no
        # cooperation from the reader.
        #
        # SOURCE_SIZE IS NOT OPTIONAL HERE. from_level() derives its
        # parameters for a source of UNKNOWN length unless it is given
        # one, and the unknown-length answer is measurably worse on small
        # inputs -- zstd's own small-source tuning is what is being
        # skipped. MEASURED against the plain level API, which has always
        # passed the length for us:
        #
        #   one 31 KiB source file                       +2.96%
        #   jsonlogs, 8,000 files compressed singly       +2.49%
        #   sitepackages, 3,952 files compressed singly   +2.32%
        #   mixed, 460 files compressed singly            +0.67%
        #
        # It cost nothing on a large block, which is why the benchmark
        # that introduced it -- measured on 64 MiB of enwik8 -- did not
        # see it. Passing the length restores every one of those to
        # parity and leaves the large-block window gain untouched.
        params = _zstd.ZstdCompressionParameters.from_level(
            level.zstd, source_size=len(data),
            window_log=zstd_window_log(len(data)))
        if dictionary:
            cctx = _zstd.ZstdCompressor(
                compression_params=params,
                dict_data=_zstd.ZstdCompressionDict(dictionary),
            )
        else:
            cctx = _zstd.ZstdCompressor(compression_params=params)
        return cctx.compress(data)

    if codec is Codec.BROTLI:
        # The window is in the stream header, so a decoder reads it back
        # and no reader needs to be told which one we chose.
        return _brotli.compress(data, quality=level.brotli,
                                lgwin=brotli_lgwin(len(data)))

    if codec is Codec.LZMA:
        # FORMAT_ALONE is LZMA1 with the properties byte and dictionary
        # size in a 13-byte header, so a stored block is self-describing
        # and needs no side-channel state to decode. That is what lets
        # the dictionary be sized per block without any format change:
        # the size travels with the block.
        return lzma.compress(data, format=lzma.FORMAT_ALONE,
                             filters=_lzma_filters(level, len(data)))

    raise PaktUnsupportedError(f"no encoder for codec id {int(codec)}")


def decompress(
    data: bytes,
    codec: Codec,
    *,
    plain_size: Optional[int] = None,
    dictionary: Optional[bytes] = None,
) -> bytes:
    """
    Decompress a stored block.

    ``plain_size`` comes from the block table and is used to bound the
    allocation *before* decoding, rather than growing a buffer as output
    arrives. Spec section 13.5 requires this: a block claiming an
    implausible size must be refused, not honoured.
    """
    _require(codec)

    if plain_size is not None:
        if plain_size > MAX_BLOCK_PLAIN_SIZE:
            raise PaktCorruptError(
                f"block claims {plain_size} uncompressed bytes, above the "
                f"{MAX_BLOCK_PLAIN_SIZE} byte cap")

    # A codec that fails to decode means the stored bytes are damaged or
    # tampered with. Surface that as corruption rather than leaking a
    # library-specific exception: the user needs to know the archive is
    # bad, not which third-party decoder objected.
    try:
        if codec is Codec.STORE:
            out = data
        elif codec is Codec.ZSTD:
            if dictionary:
                dctx = _zstd.ZstdDecompressor(
                    dict_data=_zstd.ZstdCompressionDict(dictionary))
            else:
                dctx = _zstd.ZstdDecompressor()
            if plain_size is not None:
                out = dctx.decompress(data, max_output_size=plain_size)
            else:
                out = dctx.decompress(data)
        elif codec is Codec.BROTLI:
            out = _brotli.decompress(data)
        elif codec is Codec.LZMA:
            out = lzma.decompress(data, format=lzma.FORMAT_ALONE)
        else:                                         # pragma: no cover
            raise PaktUnsupportedError(f"no decoder for codec id {int(codec)}")
    except (PaktUnsupportedError, PaktCorruptError):
        raise
    except MemoryError:
        # Refusing is correct; a crafted block should not be allowed to
        # exhaust the machine on our behalf.
        raise PaktCorruptError(
            f"{codec.name} block demanded more memory than is available; "
            f"refusing as a likely crafted archive") from None
    except Exception as exc:
        raise PaktCorruptError(
            f"{codec.name} block failed to decode ({exc}); the archive is "
            f"damaged or has been tampered with") from None

    if plain_size is not None and len(out) != plain_size:
        raise PaktCorruptError(
            f"block decoded to {len(out)} bytes but the index says "
            f"{plain_size}")
    return out


# --------------------------------------------------------------------------
# BCJ branch filter
# --------------------------------------------------------------------------
# Rewrites x86 relative branch targets to absolute before compression,
# which makes them repeat and typically buys 5-15% on executables. It is
# a reversible transform, not a codec, and it is applied to whole blocks.

def apply_bcj(data: bytes) -> bytes:
    """
    Filter a whole block. The encoder is stateful across calls, so a
    fresh one is used per block and flushed immediately -- blocks must
    stay independently decodable (spec section 6.1).
    """
    if _bcj is None:
        raise PaktUnsupportedError("BCJ filter requested but pybcj is absent")
    encoder = _bcj.BCJEncoder()
    return encoder.encode(data) + encoder.flush()


def reverse_bcj(data: bytes) -> bytes:
    if _bcj is None:
        raise PaktUnsupportedError(
            "this archive has BCJ-filtered blocks but pybcj is absent, so "
            "they cannot be decoded")
    return _bcj.BCJDecoder(len(data)).decode(data)
