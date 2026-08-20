"""
The .pakt reference encoder.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

A complete, working encoder that produces valid `.pakt` 1.0 archives.
It exists for two reasons, and both matter:

1. **It proves the format is implementable.** Anyone can read this
   alongside ``docs/pakt-format-spec.md`` and build their own encoder.
   A specification nobody can implement is a hostage note.
2. **It makes this repository self-sufficient.** Compakt builds, runs
   and round-trips without the proprietary routing engine. Your data is
   never held behind a component you cannot see.

What it deliberately does NOT do is the clever part. The production
engine adds solid blocks grouped by routing class, trial compression to
pick codecs by measurement rather than by class, adaptive levels,
trained dictionaries, and BCJ filtering where it actually pays. That
judgement is the routing engine's and lives in a separate repository.

This encoder therefore compresses somewhat worse and runs somewhat
slower. It is a real implementation, not a stub, and the archives it
writes are indistinguishable in validity from the engine's.

DELIBERATE SIMPLIFICATION: the index is stored uncompressed. Because
every field in the block table is fixed-width, an uncompressed index has
a size that does not depend on the offsets it contains, which removes a
circular dependency (index size depends on offsets, offsets depend on
index size). The production engine compresses the index and resolves
that circularity by iterating to a fixed point. Being obviously correct
matters more here than being small.
"""

from __future__ import annotations

import hashlib
import os
import stat as statmod
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Iterable, Optional

from core import container as C
from core import index_frame
from core.codecs import AUTO, Level, compress
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
    MAX_BLOCK_PLAIN_SIZE,
    PaktFormatError,
    RoutingClass,
    validate_archive_path,
)
from core.detector import detect
from core import crypto

__all__ = ["pack", "PackResult", "PackedItem", "walk_sources"]

#: Read granularity when hashing. Large enough to be fast, small enough
#: not to matter against the block cap.
_HASH_CHUNK = 1 << 20


# ==========================================================================
# Results
# ==========================================================================

@dataclass
class PackedItem:
    """One entry as it ended up in the archive. Feeds `pakt explain`."""

    path: str
    size: int
    stored_size: int
    codec: Codec
    routing_class: RoutingClass
    reason: str
    deduped: bool = False

    @property
    def ratio(self) -> float:
        return (self.stored_size / self.size) if self.size else 1.0


@dataclass
class PackResult:
    archive_path: str
    items: list[PackedItem] = field(default_factory=list)
    total_input: int = 0
    total_stored: int = 0
    archive_size: int = 0
    deduped_files: int = 0
    deduped_bytes: int = 0

    @property
    def ratio(self) -> float:
        return (self.archive_size / self.total_input) if self.total_input else 1.0

    def summary(self) -> str:
        saved = self.total_input - self.archive_size
        pct = (saved / self.total_input * 100) if self.total_input else 0.0
        line = (f"{len(self.items)} entries, {self.total_input:,} -> "
                f"{self.archive_size:,} bytes ({pct:.1f}% smaller)")
        if self.deduped_files:
            line += (f", {self.deduped_files} duplicate(s) storing "
                     f"{self.deduped_bytes:,} bytes once")
        return line


# ==========================================================================
# Source discovery
# ==========================================================================

@dataclass
class _Source:
    abs_path: str
    arc_path: str
    entry_type: EntryType
    size: int
    mode: int
    mtime_ns: int


def _to_archive_path(rel: str) -> str:
    """Normalise a host-relative path to the format's rules (§12.6)."""
    return rel.replace(os.sep, "/").replace("\\", "/").strip("/")


def walk_sources(
    sources: Iterable[str | os.PathLike[str]],
    *,
    follow_symlinks: bool = False,
) -> list[_Source]:
    """
    Expand files and directories into the entries to be archived.

    Paths inside the archive are relative to each source's parent, so
    packing ``/home/me/project`` yields ``project/...`` rather than an
    absolute path.
    """
    found: list[_Source] = []
    seen: set[str] = set()

    def add(abs_path: str, arc_path: str) -> None:
        arc_path = _to_archive_path(arc_path)
        if not arc_path or arc_path in seen:
            return
        try:
            st = os.lstat(abs_path)
        except OSError:
            return

        if statmod.S_ISLNK(st.st_mode) and not follow_symlinks:
            etype, size = EntryType.SYMLINK, 0
        elif statmod.S_ISDIR(st.st_mode):
            etype, size = EntryType.DIRECTORY, 0
        elif statmod.S_ISREG(st.st_mode):
            etype, size = EntryType.FILE, st.st_size
        else:
            return                                    # sockets, fifos, devices

        validate_archive_path(arc_path)
        seen.add(arc_path)
        found.append(_Source(abs_path, arc_path, etype, size,
                             st.st_mode & 0o7777, st.st_mtime_ns))

    for src in sources:
        src = os.fspath(src)
        base = os.path.basename(os.path.normpath(src))
        if os.path.isdir(src) and not os.path.islink(src):
            add(src, base)
            for root, dirs, files in os.walk(src, followlinks=follow_symlinks):
                dirs.sort()
                files.sort()
                rel_root = os.path.relpath(root, os.path.dirname(
                    os.path.normpath(src)))
                for d in dirs:
                    add(os.path.join(root, d), os.path.join(rel_root, d))
                for f in files:
                    add(os.path.join(root, f), os.path.join(rel_root, f))
        else:
            add(src, base)

    return found


def _sha256_file(path: str) -> tuple[bytes, int]:
    """Hash a file without holding it in memory. Returns (digest, size)."""
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(_HASH_CHUNK):
            h.update(chunk)
            total += len(chunk)
    return h.digest(), total


# ==========================================================================
# Packing
# ==========================================================================

def pack(
    sources: Iterable[str | os.PathLike[str]],
    output: str | os.PathLike[str],
    *,
    level: Level = AUTO,
    reproducible: bool = False,
    follow_symlinks: bool = False,
    password: Optional[str] = None,
    sign_key: Optional[bytes] = None,
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> PackResult:
    """
    Pack ``sources`` into a `.pakt` archive at ``output``.

    One block per file, routed by :mod:`core.detector`, with whole-file
    deduplication. Duplicate content is stored once no matter how many
    times it appears — the SHA-256 that makes that possible is already
    required for integrity, so dedup costs one dictionary lookup.

    ``reproducible`` normalises timestamps and sorts entries so that
    identical input yields byte-identical output (spec §10).
    """
    output = os.fspath(output)
    items = walk_sources(sources, follow_symlinks=follow_symlinks)
    if not items:
        raise PaktFormatError("nothing to pack: no readable files found")

    # Spec section 10: deterministic order is a precondition of
    # reproducible output, and costs nothing to apply always.
    items.sort(key=lambda s: s.arc_path.encode("utf-8"))

    index = Index()
    result = PackResult(archive_path=output)
    flags = Feature.NONE
    if reproducible:
        flags |= Feature.REPRODUCIBLE

    crypto_header = None
    key = None
    if password:
        if reproducible:
            # Spec section 4.3. Byte-identical output would demand a
            # deterministic nonce, and AES-GCM nonce reuse does not
            # weaken the cipher, it destroys it.
            raise PaktFormatError(
                "an archive cannot be both encrypted and reproducible: "
                "reproducible output requires a deterministic nonce, and "
                "reusing a GCM nonce would allow both plaintext recovery "
                "and archive forgery")
        crypto_header, key = crypto.make_crypto_header(password)
        flags |= Feature.ENCRYPTED
    if sign_key is not None:
        flags |= Feature.SIGNED

    # --- pass 1: hash everything, decide routing, resolve duplicates ---
    by_digest: dict[tuple[bytes, int], int] = {}
    plan: list[tuple[_Source, Optional[bytes], Codec, RoutingClass, str, int]] = []

    for src in items:
        if src.entry_type is EntryType.DIRECTORY:
            plan.append((src, None, Codec.STORE, RoutingClass.UNKNOWN, "directory", -1))
            continue

        if src.entry_type is EntryType.SYMLINK:
            target = os.readlink(src.abs_path).encode("utf-8")
            digest = hashlib.sha256(target).digest()
            plan.append((src, digest, Codec.STORE, RoutingClass.UNKNOWN,
                         "symlink target", -1))
            continue

        try:
            digest, real_size = _sha256_file(src.abs_path)
        except OSError as exc:
            # One unreadable file must not abort the whole job.
            if progress:
                progress(f"skipped {src.arc_path}: {exc.strerror or exc}", 0, 0)
            continue
        src.size = real_size

        # Named dedup_key, not key: `key` in this scope is the derived
        # archive encryption key, and shadowing it here silently broke
        # encryption while leaving deduplication working perfectly.
        dedup_key = (digest, real_size)
        if dedup_key in by_digest:
            plan.append((src, digest, Codec.STORE, RoutingClass.UNKNOWN,
                         "duplicate of an earlier entry", by_digest[dedup_key]))
            continue

        det = detect(src.abs_path)
        by_digest[dedup_key] = len(plan)
        plan.append((src, digest, det.codec, det.routing_class, det.reason, -1))

    # --- pass 2: write ---
    with open(output, "wb") as fh:
        # Reserve the header; the real one is written last, once the
        # index offsets and container length are known. The crypto
        # header is reserved alongside it and filled in at the same
        # time, since its index nonce and tag only exist after the
        # index has been sealed.
        fh.write(bytes(C.HEADER_SIZE))
        if crypto_header is not None:
            fh.write(bytes(C.CRYPTO_HEADER_SIZE))

        # The index is stored uncompressed, so its serialised size is
        # independent of the offsets inside it. That lets us build a
        # correctly-sized placeholder now and fill it in at the end.
        entry_slots = _build_entries(plan, reproducible)
        index.files = entry_slots
        index.total_uncompressed = sum(e.plain_size for e in entry_slots)

        placeholder_len = _stored_index_length(index, _provisional_blocks(plan))
        index_a_offset = C.HEADER_SIZE + (
            C.CRYPTO_HEADER_SIZE if crypto_header is not None else 0)
        fh.write(bytes(placeholder_len))

        block_start = fh.tell()
        blocks: list[BlockEntry] = []
        entry_by_index = {i: e for i, e in enumerate(entry_slots)}

        for slot, (src, digest, codec, rcls, reason, dup_of) in enumerate(plan):
            entry = entry_by_index[slot]

            if src.entry_type is EntryType.DIRECTORY:
                result.items.append(PackedItem(src.arc_path, 0, 0, Codec.STORE,
                                               rcls, reason))
                continue

            if dup_of >= 0:
                entry.flags |= EntryFlag.DEDUP_REF
                entry.dedup_ref = dup_of
                entry.block_index = C.NO_BLOCK
                result.deduped_files += 1
                result.deduped_bytes += src.size
                result.total_input += src.size
                result.items.append(PackedItem(src.arc_path, src.size, 0,
                                               Codec.STORE, rcls, reason,
                                               deduped=True))
                continue

            payload = _read_payload(src)
            entry.block_index = len(blocks)
            entry.block_offset = 0

            stored_total = 0
            # A file above the cap spans consecutive blocks (spec §12.5).
            for piece_start in range(0, max(len(payload), 1), MAX_BLOCK_PLAIN_SIZE):
                piece = payload[piece_start:piece_start + MAX_BLOCK_PLAIN_SIZE]
                stored = compress(piece, codec, level=level)
                # Never let "compression" make a block larger. Falling
                # back to STORE is always available and always valid.
                if len(stored) >= len(piece):
                    stored, used = piece, Codec.STORE
                else:
                    used = codec
                nonce = tag = b""
                if key is not None:
                    nonce = crypto.new_nonce()
                    stored, tag = crypto.seal(
                        key, nonce, stored,
                        crypto.block_aad(crypto_header.salt, len(blocks)))
                offset = fh.tell()
                fh.write(stored)
                blocks.append(BlockEntry(
                    offset=offset, stored_size=len(stored),
                    plain_size=len(piece), codec=used, routing_class=rcls,
                    plain_crc32=C.crc32(piece),
                    nonce=nonce or bytes(12), tag=tag or bytes(16),
                ))
                stored_total += len(stored)
                if not payload:
                    break

            result.total_input += src.size
            result.total_stored += stored_total
            result.items.append(PackedItem(src.arc_path, src.size, stored_total,
                                           codec, rcls, reason))
            if progress:
                progress(src.arc_path, src.size, stored_total)

        index.blocks = blocks

        # --- index copy B, then the real copy A ---
        stored_index = _serialise_index(index)
        if len(stored_index) != placeholder_len:
            raise PaktFormatError(
                f"internal error: index reservation was {placeholder_len} "
                f"bytes but the final index is {len(stored_index)}")

        if key is not None:
            # GCM ciphertext is exactly as long as its plaintext, which
            # is what lets an encrypted index occupy the space reserved
            # for a plain one. The tag lives in the crypto header.
            nonce_used = crypto.new_nonce()
            sealed, index_tag = crypto.seal(
                key, nonce_used, stored_index,
                crypto.index_aad(crypto_header.salt))
            crypto_header.index_nonce = nonce_used
            crypto_header.index_tag = index_tag
            stored_index = sealed

        index_b_offset = fh.tell()
        fh.write(stored_index)

        signature_offset = fh.tell()
        footer_offset = signature_offset + (
            C.SIGNATURE_SIZE if sign_key is not None else 0)
        container_length = footer_offset + C.FOOTER_SIZE

        header = Header(
            feature_flags=flags,
            index_a_offset=index_a_offset,
            index_a_length=len(stored_index),
            index_b_offset=index_b_offset,
            index_b_length=len(stored_index),
            container_length=container_length,
        )

        if sign_key is not None:
            # Spec section 8: the signature covers the header, the
            # crypto header if present, and index copy B as stored.
            message = header.pack()
            if crypto_header is not None:
                message += crypto_header.pack()
            message += stored_index
            fh.write(crypto.sign_bytes(sign_key, message).pack())

        fh.write(Footer(container_offset=0,
                        index_b_offset=index_b_offset).pack())

        # Seek back and complete the reserved regions. Copy A is
        # byte-identical to copy B by construction.
        fh.seek(0)
        fh.write(header.pack())
        if crypto_header is not None:
            fh.write(crypto_header.pack())
        fh.seek(index_a_offset)
        fh.write(stored_index)

    result.archive_size = os.path.getsize(output)
    return result


# ==========================================================================
# Helpers
# ==========================================================================

def _read_payload(src: _Source) -> bytes:
    if src.entry_type is EntryType.SYMLINK:
        return os.readlink(src.abs_path).encode("utf-8")
    with open(src.abs_path, "rb") as fh:
        return fh.read()


def _build_entries(plan, reproducible: bool) -> list[FileEntry]:
    entries: list[FileEntry] = []
    for src, digest, codec, rcls, _reason, _dup in plan:
        validate_archive_path(src.arc_path)
        entries.append(FileEntry(
            path=src.arc_path,
            entry_type=src.entry_type,
            routing_class=rcls,
            mode=0 if reproducible else src.mode,
            mtime_ns=0 if reproducible else src.mtime_ns,
            plain_size=0 if src.entry_type is EntryType.DIRECTORY else src.size,
            block_index=C.NO_BLOCK,
            dedup_ref=C.NO_DEDUP,
            # Dedup above keeps the full 256-bit digest in memory; only
            # the on-disk record is narrowed. Spec section 12.5.
            digest=C.file_digest(digest) if digest else bytes(C.DIGEST_SIZE),
        ))
    return entries


def _provisional_blocks(plan) -> int:
    """
    How many block entries the index will hold.

    Exact, not an estimate: the count is fully determined by the plan,
    which is why an uncompressed index can be reserved precisely.
    """
    n = 0
    for src, _digest, _codec, _rcls, _reason, dup_of in plan:
        if src.entry_type is EntryType.DIRECTORY or dup_of >= 0:
            continue
        size = 0 if src.entry_type is EntryType.SYMLINK else src.size
        if src.entry_type is EntryType.SYMLINK:
            size = len(os.readlink(src.abs_path).encode("utf-8"))
        n += max(1, -(-size // MAX_BLOCK_PLAIN_SIZE))
    return n


def _serialise_index(index: Index) -> bytes:
    """
    The index region, stored uncompressed and SEGMENTED.

    Segmenting costs an uncompressed index nothing -- there is no
    compression context to lose, only 12 bytes of table per segment -- and
    it buys the property that a segment damaged in one copy can be taken
    from the other. So the open reference implementation gets the
    strongest damage recovery of the two encoders, for free, which is the
    right way round for the half of the project a sceptic can read.

    The length is still exactly predictable, which is what lets the writer
    reserve space for copy A before the offsets inside it are known: every
    field is fixed width and the segment count follows from the body
    length by division.
    """
    body = index.serialise()
    return index_frame.frame(
        body, Codec.STORE,
        segment_size=index_frame.choose_segment_size(body, Codec.STORE))


def _stored_index_length(index: Index, n_blocks: int) -> int:
    """Size the index will occupy once ``n_blocks`` entries are added."""
    probe = Index(blocks=[BlockEntry() for _ in range(n_blocks)],
                  dicts=list(index.dicts), files=list(index.files),
                  total_uncompressed=index.total_uncompressed)
    return len(_serialise_index(probe))
