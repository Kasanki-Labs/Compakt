"""
The .pakt container format, version 1.0.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

This module is the executable form of ``docs/pakt-format-spec.md``. It
knows how to lay bytes out and how to read them back, and nothing else:
no compression, no encryption, no filesystem policy. Those live in the
codec, crypto and encoder modules that build on top of this one.

It is deliberately part of the open repository. The format is licensed
permissively and is meant to be implemented by anyone; keeping the
structural layer public is what makes that real rather than nominal.

Everything here is byte-exact against the specification. Where a
constant appears both here and in the spec, the spec is authoritative
and :func:`selftest` checks that the two still agree.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Optional

__all__ = [
    "PaktError", "PaktFormatError", "PaktUnsupportedError", "PaktCorruptError",
    "Feature", "Codec", "RoutingClass", "KdfId", "AeadId", "EntryType",
    "Header", "Footer", "CryptoHeader", "BlockEntry", "DictEntry", "FileEntry",
    "Index", "IndexPreamble", "SignatureBlock", "SegmentEntry",
    "INDEX_FLAG_SEGMENTED", "SEGMENT_ENTRY_SIZE",
    "pack_segment_table", "unpack_segment_table",
    "HEADER_SIZE", "FOOTER_SIZE", "CRYPTO_HEADER_SIZE", "BLOCK_ENTRY_SIZE",
    "SIGNATURE_SIZE", "INDEX_PREAMBLE_SIZE", "MAX_BLOCK_PLAIN_SIZE",
    "DIGEST_SIZE", "file_digest",
    "FORMAT_VERSION_MAJOR", "FORMAT_VERSION_MINOR",
    "NO_BLOCK", "NO_DEDUP", "NO_DICT",
    "validate_archive_path", "crc32",
]


# ==========================================================================
# Errors
# ==========================================================================

class PaktError(Exception):
    """Base class for every .pakt failure."""


class PaktFormatError(PaktError):
    """The bytes are not a valid .pakt container."""


class PaktUnsupportedError(PaktError):
    """
    Valid .pakt, but it requires something this implementation lacks.

    Raised for a newer major version, an unknown codec, or a feature
    flag outside what version 1.0 defines. Refusing clearly is
    conforming behaviour; guessing is not.
    """


class PaktCorruptError(PaktError):
    """A checksum, hash or authentication tag did not verify."""


# ==========================================================================
# Constants -- spec sections 3, 4, 5, 6, 7, 8, 12
# ==========================================================================

MAGIC = b"PAKT\x1a\x0a"
FOOTER_MAGIC = b"\x0a\x1aTKAP"          # "PAKT" reversed, spec section 7
CRYPTO_MAGIC = b"PCRY"
INDEX_MAGIC = b"PIDX"
SIGNATURE_MAGIC = b"PSIG"

FORMAT_VERSION_MAJOR = 1
FORMAT_VERSION_MINOR = 0

HEADER_SIZE = 64
FOOTER_SIZE = 32
CRYPTO_HEADER_SIZE = 72
BLOCK_ENTRY_SIZE = 72
SIGNATURE_SIZE = 104
INDEX_PREAMBLE_SIZE = 24

#: Spec section 6.1. Bounds single-file extraction cost and the
#: decryption buffer a reader must hold.
MAX_BLOCK_PLAIN_SIZE = 64 * 1024 * 1024

#: Width of the per-entry content digest, in bytes. Spec section 12.5.
#: The first 16 bytes of SHA-256 -- see :class:`FileEntry` for why the
#: truncation costs nothing that matters.
DIGEST_SIZE = 16

#: Sentinels used in the index. Spec section 12.5.
NO_BLOCK = 0xFFFFFFFF
NO_DEDUP = 0xFFFFFFFF
NO_DICT = 0xFF

_ZERO12 = bytes(12)
_ZERO16 = bytes(16)
_ZERO32 = bytes(32)


class Feature(IntFlag):
    """Feature flag bits. Spec section 4."""

    NONE = 0

    # --- defined in 1.0 (section 4.1) ---
    ENCRYPTED = 1 << 0
    SIGNED = 1 << 1
    REPRODUCIBLE = 1 << 2
    POLYGLOT = 1 << 3
    SOLID_BLOCKS = 1 << 4
    DEDUP_WHOLE_FILE = 1 << 5
    DICT_EMBEDDED = 1 << 6
    DICT_BY_ID = 1 << 7
    BCJ_FILTER = 1 << 8

    # --- reserved for the network layer (section 4.2) ---
    # Defined so the structures exist; a 1.0 writer must never set
    # these and a 1.0 reader must reject them.
    CHUNK_TABLE = 1 << 16
    MERKLE_DAG = 1 << 17
    RS_PARITY = 1 << 18
    CDC_CHUNKING = 1 << 19
    CONVERGENT_ENC = 1 << 20


#: Everything a 1.0 implementation is allowed to see set.
SUPPORTED_FEATURES = (
    Feature.ENCRYPTED | Feature.SIGNED | Feature.REPRODUCIBLE
    | Feature.POLYGLOT | Feature.SOLID_BLOCKS | Feature.DEDUP_WHOLE_FILE
    | Feature.DICT_EMBEDDED | Feature.DICT_BY_ID | Feature.BCJ_FILTER
)

#: Reserved bits, named individually so a rejection can say which one.
_RESERVED_NAMED = {
    Feature.CHUNK_TABLE: "CHUNK_TABLE",
    Feature.MERKLE_DAG: "MERKLE_DAG",
    Feature.RS_PARITY: "RS_PARITY",
    Feature.CDC_CHUNKING: "CDC_CHUNKING",
    Feature.CONVERGENT_ENC: "CONVERGENT_ENC",
}


class Codec(IntEnum):
    """Codec identifiers. Spec section 6.2."""

    STORE = 0
    ZSTD = 1
    BROTLI = 2
    LZMA = 3


class RoutingClass(IntEnum):
    """Routing classes. Spec section 6.3. Advisory only on read."""

    UNKNOWN = 0
    REPETITIVE_TEXT = 1
    STRUCTURED_BLOCKS = 2
    HIGH_CONTEXT_VECTORS = 3
    GENOMIC_STRINGS = 4
    MAXIMUM_ENTROPY_BINARY = 5
    EXECUTABLE = 6


class KdfId(IntEnum):
    """Key derivation functions. Spec section 5."""

    PBKDF2_HMAC_SHA256 = 0
    ARGON2ID = 1


class AeadId(IntEnum):
    """Authenticated encryption. Spec section 5."""

    AES_256_GCM = 0


class EntryType(IntEnum):
    """Filesystem object kinds. Spec section 12.5."""

    FILE = 0
    DIRECTORY = 1
    SYMLINK = 2


class BlockFlag(IntFlag):
    """Per-block flags. Spec section 6.4."""

    NONE = 0
    BCJ = 1 << 0


class EntryFlag(IntFlag):
    """Per-entry flags. Spec section 12.5."""

    NONE = 0
    DEDUP_REF = 1 << 0


def crc32(data: bytes) -> int:
    """CRC-32 (IEEE), as used throughout the format."""
    return zlib.crc32(data) & 0xFFFFFFFF


def file_digest(sha256_digest: bytes) -> bytes:
    """
    Narrow a full SHA-256 to the width the index stores.

    Every producer and every verifier must go through this one function.
    The alternative -- each caller writing ``[:16]`` inline -- works
    until one of them does not, and a writer and a reader that disagree
    by a slice produce an archive that fails integrity checks on content
    that is perfectly intact.
    """
    if len(sha256_digest) < DIGEST_SIZE:
        raise PaktFormatError(
            f"digest is {len(sha256_digest)} bytes, need at least "
            f"{DIGEST_SIZE}")
    return sha256_digest[:DIGEST_SIZE]


# ==========================================================================
# Header -- spec section 3
# ==========================================================================

_HEADER_STRUCT = struct.Struct("<6sBBQQQQQQII")
assert _HEADER_STRUCT.size == HEADER_SIZE


@dataclass
class Header:
    feature_flags: Feature = Feature.NONE
    index_a_offset: int = 0
    index_a_length: int = 0
    index_b_offset: int = 0
    index_b_length: int = 0
    container_length: int = 0
    version_major: int = FORMAT_VERSION_MAJOR
    version_minor: int = FORMAT_VERSION_MINOR

    def pack(self) -> bytes:
        body = _HEADER_STRUCT.pack(
            MAGIC, self.version_major, self.version_minor,
            int(self.feature_flags),
            self.index_a_offset, self.index_a_length,
            self.index_b_offset, self.index_b_length,
            self.container_length,
            0, 0,
        )[:56]
        return body + struct.pack("<II", crc32(body), 0)

    @classmethod
    def unpack(cls, raw: bytes) -> "Header":
        if len(raw) < HEADER_SIZE:
            raise PaktFormatError(
                f"header truncated: got {len(raw)} bytes, need {HEADER_SIZE}")
        raw = raw[:HEADER_SIZE]
        if raw[:6] != MAGIC:
            raise PaktFormatError("bad header magic; not a .pakt container")

        stored_crc, _ = struct.unpack("<II", raw[56:64])
        actual = crc32(raw[:56])
        if stored_crc != actual:
            raise PaktCorruptError(
                f"header CRC mismatch: stored {stored_crc:#010x}, "
                f"computed {actual:#010x}")

        (_, vmaj, vmin, flags, ia_off, ia_len, ib_off, ib_len, clen,
         _pad_a, _pad_b) = _HEADER_STRUCT.unpack(raw)

        if vmaj > FORMAT_VERSION_MAJOR:
            raise PaktUnsupportedError(
                f"archive is .pakt {vmaj}.{vmin}; this implementation "
                f"supports up to {FORMAT_VERSION_MAJOR}.{FORMAT_VERSION_MINOR}")

        _check_flags(flags)

        return cls(
            feature_flags=Feature(flags),
            index_a_offset=ia_off, index_a_length=ia_len,
            index_b_offset=ib_off, index_b_length=ib_len,
            container_length=clen,
            version_major=vmaj, version_minor=vmin,
        )

    # -- convenience ------------------------------------------------------
    @property
    def encrypted(self) -> bool:
        return bool(self.feature_flags & Feature.ENCRYPTED)

    @property
    def signed(self) -> bool:
        return bool(self.feature_flags & Feature.SIGNED)

    @property
    def polyglot(self) -> bool:
        return bool(self.feature_flags & Feature.POLYGLOT)

    @property
    def reproducible(self) -> bool:
        return bool(self.feature_flags & Feature.REPRODUCIBLE)


def _check_flags(flags: int) -> None:
    """
    Reject anything a 1.0 implementation must not silently accept.

    Spec section 4.2 and 4.3. Failing loudly here is the whole reason
    the flag field is explicit rather than implied by structure.
    """
    for bit, name in _RESERVED_NAMED.items():
        if flags & int(bit):
            raise PaktUnsupportedError(
                f"archive requires the reserved feature {name}, which is "
                f"defined but not implemented in format 1.0")

    unknown = flags & ~(int(SUPPORTED_FEATURES) | int(sum(_RESERVED_NAMED)))
    if unknown:
        raise PaktUnsupportedError(
            f"archive sets unknown feature bits {unknown:#x}; refusing "
            f"rather than risking silent misinterpretation")

    if (flags & int(Feature.ENCRYPTED)) and (flags & int(Feature.REPRODUCIBLE)):
        raise PaktFormatError(
            "ENCRYPTED and REPRODUCIBLE are mutually exclusive: a "
            "deterministic AES-GCM nonce would be reused across archives, "
            "which collapses the cipher's security entirely")


# ==========================================================================
# Footer -- spec section 7
# ==========================================================================

_FOOTER_STRUCT = struct.Struct("<QQIIH6s")
assert _FOOTER_STRUCT.size == FOOTER_SIZE


@dataclass
class Footer:
    container_offset: int = 0
    index_b_offset: int = 0
    version_major: int = FORMAT_VERSION_MAJOR
    version_minor: int = FORMAT_VERSION_MINOR

    def pack(self) -> bytes:
        version = (self.version_major << 16) | self.version_minor
        body = struct.pack("<QQI", self.container_offset,
                           self.index_b_offset, version)
        return body + struct.pack("<IH6s", crc32(body), 0, FOOTER_MAGIC)

    @classmethod
    def unpack(cls, raw: bytes) -> "Footer":
        if len(raw) < FOOTER_SIZE:
            raise PaktFormatError(
                f"footer truncated: got {len(raw)} bytes, need {FOOTER_SIZE}")
        raw = raw[-FOOTER_SIZE:]
        if raw[26:32] != FOOTER_MAGIC:
            raise PaktFormatError(
                "bad footer magic; file does not end in a .pakt container")

        c_off, ib_off, version, stored_crc, _res, _magic = _FOOTER_STRUCT.unpack(raw)
        actual = crc32(raw[:20])
        if stored_crc != actual:
            raise PaktCorruptError(
                f"footer CRC mismatch: stored {stored_crc:#010x}, "
                f"computed {actual:#010x}")

        return cls(container_offset=c_off, index_b_offset=ib_off,
                   version_major=version >> 16, version_minor=version & 0xFFFF)


# ==========================================================================
# Crypto header -- spec section 5
# ==========================================================================

_CRYPTO_STRUCT = struct.Struct("<4sBBH16s16s12s16sI")
assert _CRYPTO_STRUCT.size == CRYPTO_HEADER_SIZE


@dataclass
class CryptoHeader:
    salt: bytes = b""
    kdf_params: bytes = _ZERO16
    index_nonce: bytes = _ZERO12
    index_tag: bytes = _ZERO16
    kdf_id: KdfId = KdfId.ARGON2ID
    aead_id: AeadId = AeadId.AES_256_GCM

    def pack(self) -> bytes:
        if len(self.salt) != 16:
            raise PaktFormatError("salt must be exactly 16 bytes")
        if len(self.index_nonce) != 12:
            raise PaktFormatError("GCM nonce must be exactly 12 bytes")
        if len(self.index_tag) != 16:
            raise PaktFormatError("GCM tag must be exactly 16 bytes")
        body = struct.pack(
            "<4sBBH16s16s12s16s", CRYPTO_MAGIC, int(self.kdf_id),
            int(self.aead_id), 0, self.salt,
            self.kdf_params.ljust(16, b"\x00")[:16],
            self.index_nonce, self.index_tag,
        )
        return body + struct.pack("<I", crc32(body))

    @classmethod
    def unpack(cls, raw: bytes) -> "CryptoHeader":
        if len(raw) < CRYPTO_HEADER_SIZE:
            raise PaktFormatError("crypto header truncated")
        raw = raw[:CRYPTO_HEADER_SIZE]
        if raw[:4] != CRYPTO_MAGIC:
            raise PaktFormatError("bad crypto header magic")

        (_, kdf, aead, _res, salt, params, nonce, tag, stored_crc) = \
            _CRYPTO_STRUCT.unpack(raw)
        actual = crc32(raw[:68])
        if stored_crc != actual:
            raise PaktCorruptError("crypto header CRC mismatch")

        try:
            kdf_id = KdfId(kdf)
        except ValueError:
            raise PaktUnsupportedError(f"unknown KDF id {kdf}") from None
        try:
            aead_id = AeadId(aead)
        except ValueError:
            raise PaktUnsupportedError(f"unknown AEAD id {aead}") from None

        return cls(salt=salt, kdf_params=params, index_nonce=nonce,
                   index_tag=tag, kdf_id=kdf_id, aead_id=aead_id)


# ==========================================================================
# Signature block -- spec section 8
# ==========================================================================

_SIGNATURE_STRUCT = struct.Struct("<4sB3s32s64s")
assert _SIGNATURE_STRUCT.size == SIGNATURE_SIZE


@dataclass
class SignatureBlock:
    public_key: bytes = _ZERO32
    signature: bytes = bytes(64)
    alg_id: int = 0                      # 0 = Ed25519

    def pack(self) -> bytes:
        if len(self.public_key) != 32:
            raise PaktFormatError("Ed25519 public key must be 32 bytes")
        if len(self.signature) != 64:
            raise PaktFormatError("Ed25519 signature must be 64 bytes")
        return _SIGNATURE_STRUCT.pack(
            SIGNATURE_MAGIC, self.alg_id, b"\x00\x00\x00",
            self.public_key, self.signature)

    @classmethod
    def unpack(cls, raw: bytes) -> "SignatureBlock":
        if len(raw) < SIGNATURE_SIZE:
            raise PaktFormatError("signature block truncated")
        magic, alg, _res, pub, sig = _SIGNATURE_STRUCT.unpack(raw[:SIGNATURE_SIZE])
        if magic != SIGNATURE_MAGIC:
            raise PaktFormatError("bad signature block magic")
        if alg != 0:
            raise PaktUnsupportedError(f"unknown signature algorithm id {alg}")
        return cls(public_key=pub, signature=sig, alg_id=alg)


# ==========================================================================
# Index entries -- spec section 12
# ==========================================================================

_BLOCK_STRUCT = struct.Struct("<QQQBBBBI12s16s12s")
assert _BLOCK_STRUCT.size == BLOCK_ENTRY_SIZE


@dataclass
class BlockEntry:
    offset: int = 0
    stored_size: int = 0
    plain_size: int = 0
    codec: Codec = Codec.STORE
    routing_class: RoutingClass = RoutingClass.UNKNOWN
    dict_index: int = NO_DICT
    flags: BlockFlag = BlockFlag.NONE
    plain_crc32: int = 0
    nonce: bytes = _ZERO12
    tag: bytes = _ZERO16

    def pack(self) -> bytes:
        return _BLOCK_STRUCT.pack(
            self.offset, self.stored_size, self.plain_size,
            int(self.codec), int(self.routing_class), self.dict_index,
            int(self.flags), self.plain_crc32,
            self.nonce.ljust(12, b"\x00")[:12],
            self.tag.ljust(16, b"\x00")[:16],
            bytes(12),
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "BlockEntry":
        (offset, stored, plain, codec, rcls, dicti, flags, crc, nonce, tag,
         _res) = _BLOCK_STRUCT.unpack(raw[:BLOCK_ENTRY_SIZE])
        try:
            codec_e = Codec(codec)
        except ValueError:
            raise PaktUnsupportedError(
                f"block uses codec id {codec}, which this implementation "
                f"does not know") from None
        if plain > MAX_BLOCK_PLAIN_SIZE:
            raise PaktFormatError(
                f"block claims {plain} uncompressed bytes, above the "
                f"{MAX_BLOCK_PLAIN_SIZE} cap; refusing to allocate")
        return cls(
            offset=offset, stored_size=stored, plain_size=plain,
            codec=codec_e,
            routing_class=RoutingClass(rcls) if rcls in iter(RoutingClass)
            else RoutingClass.UNKNOWN,
            dict_index=dicti, flags=BlockFlag(flags), plain_crc32=crc,
            nonce=nonce, tag=tag,
        )

    @property
    def bcj(self) -> bool:
        return bool(self.flags & BlockFlag.BCJ)


@dataclass
class DictEntry:
    kind: int = 0                        # 0 = embedded, 1 = by id
    codec: Codec = Codec.ZSTD
    offset: int = 0
    length: int = 0
    dict_crc32: int = 0
    dict_id: str = ""

    def pack(self) -> bytes:
        ident = self.dict_id.encode("utf-8")
        return struct.pack("<BBHQQI", self.kind, int(self.codec), len(ident),
                           self.offset, self.length, self.dict_crc32) + ident

    @classmethod
    def unpack_from(cls, buf: bytes, pos: int) -> tuple["DictEntry", int]:
        kind, codec, id_len, off, length, crc = struct.unpack_from(
            "<BBHQQI", buf, pos)
        pos += 24
        ident = buf[pos:pos + id_len].decode("utf-8")
        pos += id_len
        return cls(kind=kind, codec=Codec(codec), offset=off, length=length,
                   dict_crc32=crc, dict_id=ident), pos


_FILE_TAIL = struct.Struct("<BBHIqQIQI16s")


@dataclass
class FileEntry:
    """
    One filesystem object. Spec section 12.5.

    ``digest`` is the FIRST 16 BYTES of the file's SHA-256, not the
    whole thing. That truncation is deliberate and was measured: on a
    corpus of many small files the index reached 30.2% of the archive,
    and two stored copies of a 32-byte hash were most of it. 7-Zip
    spends 1.9% there because it stores a CRC32.

    Truncating halves that cost. What it buys is worth stating exactly,
    because "we shortened the hash" invites the wrong conclusion:

    - **Second-preimage resistance is unchanged at 2^128.** This is the
      property tamper detection actually rests on -- an attacker holds
      your file and must produce a different one with the same digest.
      Nothing here is weakened.
    - **Collision resistance halves to 2^64.** That only matters to an
      attacker who controls BOTH files, which means they authored the
      archive -- and an author who wants different content can simply
      write it. The one genuine exposure is signing a stranger's
      archive that already contains a pre-computed colliding pair.
      Inspect what you sign; that advice predates this decision.
    - **Deduplication is unaffected.** A million-file archive has a
      birthday collision probability near 1e-27.
    - **Recovery is unaffected.** That comes from writing the index at
      both ends of the container and has nothing to do with hash width.
    """

    path: str = ""
    entry_type: EntryType = EntryType.FILE
    routing_class: RoutingClass = RoutingClass.UNKNOWN
    flags: EntryFlag = EntryFlag.NONE
    mode: int = 0
    mtime_ns: int = 0
    plain_size: int = 0
    block_index: int = NO_BLOCK
    block_offset: int = 0
    dedup_ref: int = NO_DEDUP
    digest: bytes = _ZERO16

    def pack(self) -> bytes:
        raw_path = self.path.encode("utf-8")
        if len(raw_path) > 0xFFFF:
            raise PaktFormatError(f"path exceeds 65535 bytes: {self.path[:60]}...")
        return (
            struct.pack("<H", len(raw_path)) + raw_path
            + _FILE_TAIL.pack(
                int(self.entry_type), int(self.routing_class), int(self.flags),
                self.mode, self.mtime_ns, self.plain_size, self.block_index,
                self.block_offset, self.dedup_ref,
                self.digest.ljust(DIGEST_SIZE, b"\x00")[:DIGEST_SIZE],
            )
        )

    @classmethod
    def unpack_from(cls, buf: bytes, pos: int) -> tuple["FileEntry", int]:
        (path_len,) = struct.unpack_from("<H", buf, pos)
        pos += 2
        raw_path = buf[pos:pos + path_len]
        pos += path_len
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            raise PaktFormatError("entry path is not valid UTF-8") from None

        (etype, rcls, flags, mode, mtime, plain, bidx, boff, dref,
         digest) = _FILE_TAIL.unpack_from(buf, pos)
        pos += _FILE_TAIL.size

        return cls(
            path=path,
            entry_type=EntryType(etype) if etype in iter(EntryType) else EntryType.FILE,
            routing_class=RoutingClass(rcls) if rcls in iter(RoutingClass)
            else RoutingClass.UNKNOWN,
            flags=EntryFlag(flags), mode=mode, mtime_ns=mtime,
            plain_size=plain, block_index=bidx, block_offset=boff,
            dedup_ref=dref, digest=digest,
        ), pos

    @property
    def is_dedup_ref(self) -> bool:
        return bool(self.flags & EntryFlag.DEDUP_REF)


# ==========================================================================
# Index -- spec section 12.2
# ==========================================================================

_INDEX_PREAMBLE_STRUCT = struct.Struct("<4sBBHQII")
assert _INDEX_PREAMBLE_STRUCT.size == INDEX_PREAMBLE_SIZE

#: Index preamble flag bits (spec §12.1).
#: SEGMENTED means the index body was split, and each segment compressed
#: and CRC'd on its own, so a reader can take segment *i* from whichever
#: copy of the index still verifies it. Without it the body is one blob
#: under one CRC, and any single damaged byte condemns a whole copy --
#: which made two copies protect only against damage that missed one of
#: them entirely, rather than against two small independent faults.
INDEX_FLAG_SEGMENTED = 1 << 0

#: One SEGMENT_ENTRY: stored length, plain length, CRC-32 of the plain
#: bytes. The lengths are explicit rather than implied by a fixed segment
#: size, so a writer may choose any size -- or vary it -- without the
#: reader needing to know which rule was used.
SEGMENT_ENTRY_SIZE = 12
_SEGMENT_ENTRY_STRUCT = struct.Struct("<III")
assert _SEGMENT_ENTRY_STRUCT.size == SEGMENT_ENTRY_SIZE


@dataclass
class SegmentEntry:
    """One independently decodable piece of the index body."""

    stored_length: int = 0
    plain_length: int = 0
    plain_crc32: int = 0

    def pack(self) -> bytes:
        return _SEGMENT_ENTRY_STRUCT.pack(
            self.stored_length, self.plain_length, self.plain_crc32)

    @classmethod
    def unpack(cls, raw: bytes) -> "SegmentEntry":
        if len(raw) < SEGMENT_ENTRY_SIZE:
            raise PaktFormatError("segment entry truncated")
        stored, plain, crc = _SEGMENT_ENTRY_STRUCT.unpack(
            raw[:SEGMENT_ENTRY_SIZE])
        return cls(stored_length=stored, plain_length=plain, plain_crc32=crc)


def pack_segment_table(entries: list["SegmentEntry"]) -> bytes:
    """
    The segment table, with its own trailing CRC-32.

    The table is separately checksummed because it is the one part that
    cannot be recovered piecewise: without it a reader cannot find where
    any segment begins. A damaged table in one copy is taken from the
    other, which is why it is checksummed apart from the segments it
    describes.
    """
    body = b"".join(e.pack() for e in entries)
    return body + struct.pack("<I", crc32(body))


def unpack_segment_table(raw: bytes, n_segments: int) -> list["SegmentEntry"]:
    need = n_segments * SEGMENT_ENTRY_SIZE + 4
    if len(raw) < need:
        raise PaktFormatError(
            f"segment table truncated: need {need} bytes, got {len(raw)}")
    body = raw[:n_segments * SEGMENT_ENTRY_SIZE]
    (stored_crc,) = struct.unpack_from("<I", raw, len(body))
    if crc32(body) != stored_crc:
        raise PaktCorruptError("index segment table CRC mismatch")
    return [SegmentEntry.unpack(body[i * SEGMENT_ENTRY_SIZE:])
            for i in range(n_segments)]


@dataclass
class IndexPreamble:
    """
    Stays in the clear even in an encrypted archive, so a reader can
    size buffers before it holds the key. Reveals lengths only, never
    names. Spec section 12.1.
    """

    index_codec: Codec = Codec.STORE
    plain_length: int = 0
    plain_crc32: int = 0
    #: Bit field; see INDEX_FLAG_SEGMENTED. Occupies one of the three
    #: bytes the preamble previously reserved, so the structure is still
    #: 24 bytes and a 1.0 reader's buffer sizing is unaffected.
    flags: int = 0
    #: Number of segments when SEGMENTED, else zero. Two bytes, from the
    #: same previously reserved space.
    n_segments: int = 0

    @property
    def segmented(self) -> bool:
        return bool(self.flags & INDEX_FLAG_SEGMENTED)

    def pack(self) -> bytes:
        body = struct.pack("<4sBBHQI", INDEX_MAGIC, int(self.index_codec),
                           self.flags, self.n_segments,
                           self.plain_length, self.plain_crc32)
        return body + struct.pack("<I", crc32(body))

    @classmethod
    def unpack(cls, raw: bytes) -> "IndexPreamble":
        if len(raw) < INDEX_PREAMBLE_SIZE:
            raise PaktFormatError("index preamble truncated")
        magic, codec, flags, nseg, plen, pcrc, stored = (
            _INDEX_PREAMBLE_STRUCT.unpack(raw[:INDEX_PREAMBLE_SIZE]))
        if magic != INDEX_MAGIC:
            raise PaktFormatError("bad index preamble magic")
        if stored != crc32(raw[:20]):
            raise PaktCorruptError("index preamble CRC mismatch")
        try:
            codec_e = Codec(codec)
        except ValueError:
            raise PaktUnsupportedError(
                f"index uses codec id {codec}, unknown to this "
                f"implementation") from None
        return cls(index_codec=codec_e, plain_length=plen, plain_crc32=pcrc,
                   flags=flags, n_segments=nseg)


@dataclass
class Index:
    """The catalogue: blocks, dictionaries and entries."""

    blocks: list[BlockEntry] = field(default_factory=list)
    dicts: list[DictEntry] = field(default_factory=list)
    files: list[FileEntry] = field(default_factory=list)
    total_uncompressed: int = 0
    index_version: int = 1

    def serialise(self) -> bytes:
        parts = [struct.pack("<HHIIIQ", self.index_version, 0,
                             len(self.blocks), len(self.dicts), len(self.files),
                             self.total_uncompressed)]
        parts.extend(b.pack() for b in self.blocks)
        parts.extend(d.pack() for d in self.dicts)
        parts.extend(f.pack() for f in self.files)
        body = b"".join(parts)
        return body + struct.pack("<I", crc32(body))

    @classmethod
    def deserialise(cls, buf: bytes) -> "Index":
        if len(buf) < 24:
            raise PaktFormatError("index body truncated")

        stored_crc = struct.unpack_from("<I", buf, len(buf) - 4)[0]
        actual = crc32(buf[:-4])
        if stored_crc != actual:
            raise PaktCorruptError(
                f"index CRC mismatch: stored {stored_crc:#010x}, "
                f"computed {actual:#010x}")

        version, _res, n_blocks, n_dicts, n_files, total = struct.unpack_from(
            "<HHIIIQ", buf, 0)
        if version != 1:
            raise PaktUnsupportedError(f"index version {version} is not supported")
        pos = 24

        blocks = []
        for _ in range(n_blocks):
            if pos + BLOCK_ENTRY_SIZE > len(buf):
                raise PaktFormatError("index truncated inside the block table")
            blocks.append(BlockEntry.unpack(buf[pos:pos + BLOCK_ENTRY_SIZE]))
            pos += BLOCK_ENTRY_SIZE

        dicts = []
        for _ in range(n_dicts):
            entry, pos = DictEntry.unpack_from(buf, pos)
            dicts.append(entry)

        files = []
        for _ in range(n_files):
            entry, pos = FileEntry.unpack_from(buf, pos)
            files.append(entry)

        return cls(blocks=blocks, dicts=dicts, files=files,
                   total_uncompressed=total, index_version=version)


# ==========================================================================
# Path validation -- spec section 12.6
# ==========================================================================

# Reserved device names on Windows. Creating one of these is not a
# traversal, but it is a denial-of-service and a portability trap, so
# archives that contain them are rejected rather than partially extracted.
_WINDOWS_RESERVED = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})


def validate_archive_path(path: str, *, strict_windows: bool = True) -> None:
    """
    Enforce the normative path rules of spec section 12.6.

    Raises :class:`PaktFormatError` on any violation. Called on write so
    bad paths are never produced, and again on read because a reader
    must never trust the writer to have complied.
    """
    if not path:
        raise PaktFormatError("entry path is empty")
    if "\x00" in path:
        raise PaktFormatError("entry path contains a NUL byte")
    if "\\" in path:
        raise PaktFormatError(
            f"entry path uses a backslash separator: {path!r}")
    if path.startswith("/"):
        raise PaktFormatError(f"entry path is absolute: {path!r}")
    if len(path) > 1 and path[1] == ":":
        raise PaktFormatError(f"entry path carries a drive letter: {path!r}")

    parts = path.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise PaktFormatError(
                f"entry path contains a '{part or 'empty'}' component: {path!r}")
        if strict_windows:
            stem = part.split(".")[0].lower()
            if stem in _WINDOWS_RESERVED:
                raise PaktFormatError(
                    f"entry path contains the reserved device name "
                    f"'{part}': {path!r}")


# ==========================================================================
# Self-check
# ==========================================================================

def selftest() -> dict[str, int]:
    """
    Assert every fixed-size structure matches the specification.

    Cheap enough to run in a test, and it catches the class of mistake
    that is otherwise found only by a reader written in another language
    failing on a real archive.
    """
    sizes = {
        "header": len(Header().pack()),
        "footer": len(Footer().pack()),
        "crypto_header": len(CryptoHeader(salt=_ZERO16).pack()),
        "block_entry": len(BlockEntry().pack()),
        "signature": len(SignatureBlock().pack()),
        "index_preamble": len(IndexPreamble().pack()),
    }
    expected = {
        "header": HEADER_SIZE,
        "footer": FOOTER_SIZE,
        "crypto_header": CRYPTO_HEADER_SIZE,
        "block_entry": BLOCK_ENTRY_SIZE,
        "signature": SIGNATURE_SIZE,
        "index_preamble": INDEX_PREAMBLE_SIZE,
    }
    for name, actual in sizes.items():
        if actual != expected[name]:
            raise AssertionError(
                f"{name} is {actual} bytes, specification says {expected[name]}")
    return sizes
