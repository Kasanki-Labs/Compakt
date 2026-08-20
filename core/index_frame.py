"""
Index framing: how the catalogue is laid out on disk, and how it is put
back together from a damaged archive.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

WHY THIS MODULE EXISTS AT ALL. Writing the index is the encoders' job and
reading it is the reader's, so the framing rules would naturally live in
three places -- both encoders and the reader. Two implementations of one
rule drift, and the copy that drifts is always the one nobody is reading.
Here the encode and decode sides sit next to each other where a change to
one is visibly a change to the other.

WHAT THE FRAMING BUYS. `.pakt` keeps two copies of the index, one at each
end of the container, so damage at either end is survivable. That worked
only when damage missed one copy ENTIRELY: the body was a single
compressed blob under a single CRC, so one bad byte condemned a whole
copy, and one bad byte in EACH copy lost the archive -- even though
between the two of them every byte had survived somewhere.

Two independent small faults is exactly what ageing media, bad cables and
half-finished writes produce, so that was the common case rather than an
exotic one. Segmenting the body fixes it: each segment is compressed and
checksummed on its own, so a reader can take segment *i* from whichever
copy still verifies it, and the archive survives damage in both copies as
long as no single segment is damaged in both.

THE COST IS MEASURED, NOT ASSUMED. Independent segments cannot share
compression context, and on an index whose redundancy is long-range that
hurts badly -- on a corpus of 1,800 mostly-duplicate files, 64 KiB
segments cost 47% more index than one blob, because the repeated digests
and paths only compress against each other across the whole thing. On
other corpora segmenting is FREE or slightly better. So the size is
chosen by trying candidates and measuring, and a writer that finds
segmentation too expensive emits a single segment, which is the old
layout and still correct.
"""

from __future__ import annotations

from typing import Callable, Optional

from core import container as C
from core.codecs import AUTO, Level, compress, decompress
from core.container import (
    INDEX_FLAG_SEGMENTED,
    INDEX_PREAMBLE_SIZE,
    SEGMENT_ENTRY_SIZE,
    Codec,
    IndexPreamble,
    PaktCorruptError,
    PaktFormatError,
    SegmentEntry,
    pack_segment_table,
    unpack_segment_table,
)

__all__ = ["frame", "assemble", "choose_segment_size", "SEGMENT_CANDIDATES"]


#: Candidate segment sizes, largest last. Smaller segments mean finer
#: recovery granularity; larger ones mean more compression context. The
#: writer measures rather than picking.
SEGMENT_CANDIDATES = (64 * 1024, 256 * 1024, 1024 * 1024)

#: How much larger a segmented index may be than the best layout found
#: before the extra recoverability stops being worth it. Recovery is the
#: point of the exercise, so this is deliberately not zero -- but the
#: duplicates corpus shows the cost can run to tens of percent, and
#: paying that on every archive to protect against damage that may never
#: come is not a trade to make silently.
SEGMENT_COST_MARGIN = 0.02


def _split(body: bytes, size: int) -> list[bytes]:
    if size <= 0:
        return [body]
    return [body[i:i + size] for i in range(0, max(len(body), 1), size)] or [b""]


def _encode_segments(body: bytes, codec: Codec, level: Level,
                     size: int) -> tuple[bytes, list[SegmentEntry]]:
    entries: list[SegmentEntry] = []
    payloads: list[bytes] = []
    for piece in _split(body, size):
        stored = compress(piece, codec, level=level) if codec is not Codec.STORE \
            else piece
        entries.append(SegmentEntry(stored_length=len(stored),
                                    plain_length=len(piece),
                                    plain_crc32=C.crc32(piece)))
        payloads.append(stored)
    return b"".join(payloads), entries


def _framed_length(body: bytes, codec: Codec, level: Level, size: int) -> int:
    payload, entries = _encode_segments(body, codec, level, size)
    return (INDEX_PREAMBLE_SIZE + len(entries) * SEGMENT_ENTRY_SIZE + 4
            + len(payload))


def choose_segment_size(body: bytes, codec: Codec,
                        level: Level = AUTO) -> Optional[int]:
    """
    The smallest segment size whose cost is within the margin of the best.

    Returns None to mean "do not segment", which a writer emits as the
    single-blob layout.

    Smallest-within-margin rather than simply smallest-total: more
    segments is better for recovery, so the tie-break favours
    recoverability and only the SIZE is allowed to veto it.

    STORE is a special case worth stating: an uncompressed index has no
    compression context to lose, so segmenting it is free and the finest
    granularity always wins. The reference encoder stores its index
    uncompressed, which means the open implementation gets the strongest
    recovery of the two at no cost whatsoever.
    """
    if not body:
        return None

    if codec is Codec.STORE:
        return SEGMENT_CANDIDATES[0]

    unsegmented = INDEX_PREAMBLE_SIZE + len(compress(body, codec, level=level))
    costs: list[tuple[int, int]] = []
    for size in SEGMENT_CANDIDATES:
        if size >= len(body) and costs:
            # One segment already; larger candidates cannot differ.
            break
        costs.append((size, _framed_length(body, codec, level, size)))

    if not costs:
        return None
    best = min(min(c for _s, c in costs), unsegmented)
    allowed = best * (1.0 + SEGMENT_COST_MARGIN)
    for size, cost in costs:                       # smallest first
        if cost <= allowed:
            return size
    return None


def frame(body: bytes, codec: Codec, *, level: Level = AUTO,
          segment_size: Optional[int] = None) -> bytes:
    """
    Build the on-disk index region: preamble, then either one blob or a
    segment table followed by its segments.

    ``plain_crc32`` in the preamble still covers the WHOLE body even when
    segmented. The per-segment checksums say which pieces survived; the
    whole-body one says the reassembly is right. Keeping both means a
    reader never trusts a stitched index it has not verified end to end.
    """
    if segment_size is None:
        stored = compress(body, codec, level=level) \
            if codec is not Codec.STORE else body
        preamble = IndexPreamble(index_codec=codec, plain_length=len(body),
                                 plain_crc32=C.crc32(body))
        return preamble.pack() + stored

    payload, entries = _encode_segments(body, codec, level, segment_size)
    preamble = IndexPreamble(index_codec=codec, plain_length=len(body),
                             plain_crc32=C.crc32(body),
                             flags=INDEX_FLAG_SEGMENTED,
                             n_segments=len(entries))
    return preamble.pack() + pack_segment_table(entries) + payload


def _parse(raw: bytes) -> tuple[IndexPreamble, list[SegmentEntry], bytes]:
    """One copy's preamble, segment table and payload region."""
    preamble = IndexPreamble.unpack(raw)
    rest = raw[INDEX_PREAMBLE_SIZE:]
    if not preamble.segmented:
        return preamble, [], rest
    table_len = preamble.n_segments * SEGMENT_ENTRY_SIZE + 4
    entries = unpack_segment_table(rest, preamble.n_segments)
    return preamble, entries, rest[table_len:]


def _decode_one(entry: SegmentEntry, stored: bytes,
                codec: Codec) -> Optional[bytes]:
    """A segment's plain bytes, or None if it did not survive."""
    if len(stored) != entry.stored_length:
        return None
    try:
        plain = stored if codec is Codec.STORE else decompress(
            stored, codec, plain_size=entry.plain_length)
    except C.PaktError:
        return None
    if len(plain) != entry.plain_length:
        return None
    if C.crc32(plain) != entry.plain_crc32:
        return None
    return plain


def assemble(copies: list[bytes],
             on_repair: Optional[Callable[[str], None]] = None) -> bytes:
    """
    The index body, taking each segment from whichever copy still has it.

    ``copies`` is the raw region of each index copy that could be read, in
    preference order -- the reader passes copy B first because it is
    written after the block data and therefore reflects a completed write.

    Raises if no combination yields a body matching the whole-body CRC.
    Reporting failure is the only honest outcome there: a stitched index
    that does not verify is worse than none, because every offset in it
    would be believed.
    """
    parsed = []
    problems: list[str] = []
    for i, raw in enumerate(copies):
        try:
            parsed.append(_parse(raw))
        except C.PaktError as exc:
            problems.append(f"copy {i}: {exc}")
    if not parsed:
        raise PaktCorruptError(
            "no index copy could even be framed -- " + "; ".join(problems))

    # Unsegmented copies are all-or-nothing; try each in order.
    segmented = [p for p in parsed if p[0].segmented]
    if not segmented:
        for preamble, _entries, payload in parsed:
            codec = preamble.index_codec
            body = _decode_one(
                SegmentEntry(stored_length=len(payload),
                             plain_length=preamble.plain_length,
                             plain_crc32=preamble.plain_crc32),
                payload, codec)
            if body is not None:
                return body
        raise PaktCorruptError(
            "every index copy failed its checksum, and this archive's index "
            "is not segmented, so surviving parts cannot be combined")

    # Segmented: stitch per segment across every copy that agrees on shape.
    reference = segmented[0][0]
    n = reference.n_segments
    out: list[Optional[bytes]] = [None] * n
    taken_from: dict[int, int] = {}

    for copy_i, (preamble, entries, payload) in enumerate(parsed):
        if not preamble.segmented or preamble.n_segments != n:
            continue
        if preamble.plain_crc32 != reference.plain_crc32:
            # Copies that describe different content are not two copies of
            # one index; mixing them would fabricate a catalogue.
            problems.append(f"copy {copy_i}: describes a different index")
            continue
        offset = 0
        for i, entry in enumerate(entries):
            stored = payload[offset:offset + entry.stored_length]
            offset += entry.stored_length
            if out[i] is not None:
                continue
            plain = _decode_one(entry, stored, preamble.index_codec)
            if plain is not None:
                out[i] = plain
                taken_from[i] = copy_i

    missing = [i for i, seg in enumerate(out) if seg is None]
    if missing:
        # Worded from how many copies were actually offered. The reader
        # calls this with ONE copy on the ordinary path, and "damaged in
        # every copy" would then overstate what was examined.
        where = ("this copy" if len(copies) == 1
                 else f"all {len(copies)} copies")
        raise PaktCorruptError(
            f"index segment(s) {missing} are damaged in {where}; "
            f"{n - len(missing)} of {n} segments survived")

    body = b"".join(seg for seg in out if seg is not None)
    if len(body) != reference.plain_length or \
            C.crc32(body) != reference.plain_crc32:
        raise PaktCorruptError(
            "the reassembled index does not match its whole-body checksum")

    if on_repair is not None and len(set(taken_from.values())) > 1:
        spread = ", ".join(f"segment {i} from copy {c}"
                           for i, c in sorted(taken_from.items())
                           if c != 0)
        on_repair(f"index reassembled across copies ({spread})")
    return body
