"""
The .pakt reader.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Reads and extracts `.pakt` 1.0 archives, and implements every normative
requirement of specification §13. Those requirements are not optional
polish: archive utilities are attacked through their extractors far more
often than through their codecs, and an implementation that skips them
is not a conforming reader whatever else it gets right.

Enforced here:

- **Path traversal** — every target is resolved against the extraction
  root *at the moment of creation* and rejected if it escapes. Checking
  the stored string is not sufficient, because a symlink created earlier
  in the same extraction can change where a later path resolves to.
- **Symlink escape** — links pointing outside the root are refused, and
  symlinks are opt-in rather than default.
- **Decompression bombs** — total output, per-block ratio and entry
  count are all capped, and breaching a cap aborts rather than filling
  the disk and reporting failure afterwards.
- **Integrity** — block CRC-32 after decompression, entry SHA-256 after
  reconstruction, both hard failures on mismatch.
- **Bounded allocation** — buffers are sized from the block table before
  decoding, never grown as output arrives.

This module handles `.pakt` only. The multi-format extractor that
dispatches `.zip`, `.7z`, `.rar` and the rest is a separate concern.
"""

from __future__ import annotations

import hashlib
import os
import warnings
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, Optional

from core import container as C
from core import index_frame
from core.codecs import decompress, reverse_bcj
from core.safety import (
    ExtractLimits,
    SecurityError,
    check_link_target,
    safe_target,
)
from core.container import (
    BlockEntry,
    Codec,
    CryptoHeader,
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
    SignatureBlock,
    validate_archive_path,
)
from core import crypto

__all__ = ["PaktArchive", "ExtractLimits", "SecurityError", "open_pakt",
           "PasswordRequired", "PaktDamageWarning"]


class PasswordRequired(PaktFormatError):
    """The archive is encrypted and no password was supplied."""


class PaktDamageWarning(UserWarning):
    """
    An archive opened only because the reader repaired around damage.

    A warning rather than an error on purpose: the data came back, and
    refusing would throw away a recovery that worked. A warning rather
    than silence because spec 2.1 requires a reader that recovers to
    say so -- an archive that opens quietly after losing its footer
    teaches its owner that nothing is wrong with it.
    """


# The safety policy is shared with every other archive format
# (core.safety). Defining a second copy here is exactly how two
# implementations of one security control drift apart, and the copy
# that drifts is always the one nobody is reading.


@dataclass
class _LoadedIndex:
    index: Index
    which: str                                        # "A" or "B"


class PaktArchive:
    """
    An open `.pakt` archive.

    Use as a context manager::

        with open_pakt("backup.pakt") as archive:
            for entry in archive.entries:
                print(entry.path, entry.plain_size)
            archive.extract_all("out/")
    """

    def __init__(self, fh: BinaryIO, *, path: str = "<stream>",
                 password: Optional[str] = None) -> None:
        self._fh = fh
        self.path = path
        self._block_cache: dict[int, bytes] = {}
        self._dict_cache: dict[int, bytes] = {}
        self._key: Optional[bytes] = None
        self.crypto_header = None

        #: Every structural repair this reader had to make, in the order
        #: it made them. Empty for an intact archive. Spec §2.1 requires
        #: that a reader which recovers MUST warn, and it cannot warn
        #: about what it did not record.
        self.damage: list[str] = []

        self.footer = self._read_footer_or_none()
        self.container_offset = self._locate_container()
        self.header = self._read_header_or_recover()

        if self.header.encrypted:
            if not password:
                raise PasswordRequired(
                    "this archive is encrypted; a password is needed to read "
                    "even its file listing, because the index is encrypted too")
            self.crypto_header = CryptoHeader.unpack(
                self._read_at(C.HEADER_SIZE, C.CRYPTO_HEADER_SIZE))
            self._key = crypto.key_from_crypto_header(password,
                                                      self.crypto_header)

        loaded = self._load_index()
        self.index = loaded.index
        self.index_copy_used = loaded.which

        # Spec §2.1: a reader that recovers MUST warn. Raised HERE, in the
        # reader, rather than in each caller -- the obligation is the
        # reader's, and the CLI, the window and any third-party consumer
        # all inherit it this way instead of three of them remembering.
        if self.damage:
            warnings.warn(
                "this .pakt archive is damaged and was recovered: "
                + "; ".join(self.damage),
                PaktDamageWarning, stacklevel=3)

    # -- signatures -------------------------------------------------------

    def verify_signature(self, *, deep: bool = True) -> bytes:
        """
        Check the archive's Ed25519 signature and return the public key.

        WHAT THE SIGNATURE ITSELF COVERS (spec §8): the header, the
        crypto header if present, and index copy B. It does NOT directly
        cover the block data. Authenticity of the *contents* comes from
        a chain: the signature authenticates the index, and the index
        carries a SHA-256 for every entry.

        That chain is only complete if the hashes are actually checked,
        so ``deep=True`` (the default) walks every entry and verifies
        them. Reporting "signature verifies" while leaving the payload
        unchecked would be a dangerous half-truth -- an attacker could
        alter file contents and the archive would still pass.

        ``deep=False`` verifies the signature alone. It is fast and
        useful for identifying a signer before deciding whether to
        spend time on the contents, but it is not proof the data is
        intact.

        A valid signature proves who produced the archive. Whether that
        key is one you should trust is a separate question, and one this
        method deliberately does not answer.
        """
        if not self.header.signed:
            raise PaktFormatError("this archive carries no signature")

        raw_index = self._read_at(self.header.index_b_offset,
                                  self.header.index_b_length)
        sig_offset = self.header.index_b_offset + self.header.index_b_length
        block = SignatureBlock.unpack(
            self._read_at(sig_offset, C.SIGNATURE_SIZE))

        message = self.header.pack()
        if self.crypto_header is not None:
            message += self.crypto_header.pack()
        message += raw_index

        crypto.verify_signature(block, message)

        if deep:
            # Close the chain. read() verifies each entry's SHA-256
            # against the now-authenticated index and raises on any
            # mismatch.
            for entry in self.index.files:
                if entry.entry_type is EntryType.DIRECTORY:
                    continue
                self.read(entry)

        return block.public_key

    # -- construction -----------------------------------------------------

    def __enter__(self) -> "PaktArchive":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._block_cache.clear()
        try:
            self._fh.close()
        except Exception:
            pass

    # -- structural reads -------------------------------------------------

    def _read_footer(self) -> Footer:
        self._fh.seek(0, os.SEEK_END)
        size = self._fh.tell()
        if size < C.HEADER_SIZE + C.FOOTER_SIZE:
            raise PaktFormatError(f"file is only {size} bytes; too small to be .pakt")
        self._fh.seek(size - C.FOOTER_SIZE)
        return Footer.unpack(self._fh.read(C.FOOTER_SIZE))

    # -- recovery ---------------------------------------------------------
    # The format is built so that damage at either END is survivable: the
    # index is written twice and the footer duplicates the offset of copy
    # B. None of that helps unless the reader actually reaches for it, so
    # what follows is the machinery that does.
    #
    # THE FAILURE THIS FIXES. A tail-truncated archive -- an interrupted
    # download or copy, which is the most ordinary damage there is --
    # loses its footer, and a reader that gives up on a bad footer never
    # looks at copy A sitting intact near the front. The claim that copy
    # A survives truncation was true of the FORMAT and false of the
    # READER. Same for the head: the footer carries index_b_offset
    # precisely so a destroyed header can be worked around.

    def _file_size(self) -> int:
        self._fh.seek(0, os.SEEK_END)
        return self._fh.tell()

    def _read_footer_or_none(self) -> Optional[Footer]:
        """
        The footer, or None if it is unreadable and recovery should try.

        A file too SHORT to hold the fixed structures is not a damaged
        archive, it is not an archive -- so that stays a hard failure
        rather than entering the recovery path, which would otherwise
        compute negative offsets from it.
        """
        size = self._file_size()
        if size < C.HEADER_SIZE + C.FOOTER_SIZE:
            raise PaktFormatError(
                f"file is only {size} bytes; too small to be .pakt")
        try:
            return self._read_footer()
        except C.PaktError as exc:
            self.damage.append(f"footer unreadable ({exc}); recovering")
            return None

    def _header_magic_at(self, offset: int) -> bool:
        if offset < 0 or offset + C.HEADER_SIZE > self._file_size():
            return False
        self._fh.seek(offset)
        return self._fh.read(len(C.MAGIC)) == C.MAGIC

    def _scan_for(self, needle: bytes) -> Optional[int]:
        """
        Find ``needle`` by scanning forward from offset 0.

        Chunked with an overlap so a match straddling a chunk boundary is
        not missed, which is the classic bug in this shape of loop.
        """
        window = 1 << 20
        overlap = len(needle) - 1
        pos = 0
        size = self._file_size()
        while pos < size:
            self._fh.seek(pos)
            chunk = self._fh.read(window + overlap)
            if not chunk:
                break
            found = chunk.find(needle)
            if found >= 0:
                return pos + found
            pos += window
        return None

    def _locate_container(self) -> int:
        """
        Where the header begins. Spec §2.1: if footer validation fails, a
        reader SHOULD recover by scanning for the header magic.
        """
        # The footer's own offset first, when there is a header at it.
        if self.footer is not None and self._header_magic_at(
                self.footer.container_offset):
            return self.footer.container_offset

        # Otherwise look for a header elsewhere -- this is the polyglot
        # and wrong-offset case.
        scanned = self._scan_for(C.MAGIC)
        if scanned is not None:
            if self.footer is None or scanned != self.footer.container_offset:
                self.damage.append(
                    f"container located by scanning, at {scanned}")
            return scanned

        # No header magic anywhere. That does NOT mean there is nothing to
        # recover: a destroyed header is exactly the case the footer's
        # duplicated offsets exist for, so an intact footer is still
        # believed and the header is reconstructed from it further down.
        if self.footer is not None:
            offset = self.footer.container_offset
            if 0 <= offset < self._file_size():
                self.damage.append(
                    "no header magic found; trusting the footer's offset and "
                    "reconstructing the header")
                return offset

        raise PaktFormatError(
            "no .pakt header found anywhere in this file, and the footer is "
            "unreadable; there is nothing here to recover")

    def _read_header_or_recover(self) -> Header:
        try:
            self._fh.seek(self.container_offset)
            return Header.unpack(self._fh.read(C.HEADER_SIZE))
        except C.PaktError as exc:
            self.damage.append(f"header unreadable ({exc}); recovering")
            return self._reconstruct_header()

    def _reconstruct_header(self) -> Header:
        """
        Rebuild just enough header to reach index copy B.

        The footer duplicates index_b_offset for exactly this case. What
        it does not carry is the LENGTH, and the preamble does not record
        the stored size either -- so the length is derived from the
        layout: copy B is the last structure before the optional
        signature block and the footer (§2), so it runs to whichever of
        those begins.

        AN ENCRYPTED ARCHIVE CANNOT BE RECOVERED THIS WAY, and the reason
        is structural rather than an omission: the crypto header sits
        immediately after the header, so damage that destroys one has
        almost certainly destroyed the other, and with it the salt and
        the index nonce. There is no key derivation without them. Said
        plainly here so nobody reads the failure as a bug.
        """
        size = self._file_size()
        end = size - C.FOOTER_SIZE                        # absolute

        if end - C.SIGNATURE_SIZE >= 0:
            self._fh.seek(end - C.SIGNATURE_SIZE)
            if self._fh.read(len(C.SIGNATURE_MAGIC)) == C.SIGNATURE_MAGIC:
                end -= C.SIGNATURE_SIZE
                self.damage.append(
                    "signature block found; excluded from index B")

        b_offset = None
        if self.footer is not None and self.footer.index_b_offset:
            b_offset = self.footer.index_b_offset
            self.damage.append(
                f"index B offset {b_offset} taken from the footer")
        else:
            found = self._scan_for(C.INDEX_MAGIC)
            if found is not None:
                b_offset = found - self.container_offset
                self.damage.append(
                    f"index located by scanning, at {found}")

        if b_offset is None:
            raise PaktCorruptError(
                "the header is destroyed and neither the footer nor a scan "
                "could locate an index copy; if this archive was encrypted "
                "the crypto header is gone too and recovery is impossible")

        length = end - (self.container_offset + b_offset)
        if length <= 0:
            raise PaktCorruptError(
                "the header is destroyed and the recovered index offset "
                "lies past the end of the file")
        return Header(index_b_offset=b_offset, index_b_length=length)

    def _read_header(self) -> Header:
        self._fh.seek(self.container_offset)
        return Header.unpack(self._fh.read(C.HEADER_SIZE))

    def _read_at(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at a container-relative offset."""
        self._fh.seek(self.container_offset + offset)
        data = self._fh.read(length)
        if len(data) != length:
            raise PaktFormatError(
                f"archive truncated: wanted {length} bytes at offset "
                f"{offset}, got {len(data)}")
        return data

    def _load_index(self) -> _LoadedIndex:
        """
        Load copy B, falling back to copy A.

        Copy B is written after the block data and therefore reflects a
        completed write, so it is preferred (spec §2.2). Copy A is the
        recovery path for an archive whose tail was truncated.
        """
        errors: list[str] = []
        raw_copies: list[tuple[str, bytes]] = []

        for which, offset, length in (
            ("B", self.header.index_b_offset, self.header.index_b_length),
            ("A", self.header.index_a_offset, self.header.index_a_length),
        ):
            if not length:
                continue
            try:
                return _LoadedIndex(self._parse_index(offset, length), which)
            except crypto.WrongPassword:
                # Do not fall through to copy A. Both copies are sealed
                # with the same key, so a failure here means the key is
                # wrong, not that the archive is damaged -- and telling
                # someone their archive is corrupt when they merely
                # mistyped a password is a lie that generates false bug
                # reports.
                raise
            except C.PaktError as exc:
                errors.append(f"copy {which}: {exc}")
                self.damage.append(f"index copy {which} unusable ({exc})")
                raw = self._raw_index(offset, length)
                if raw is not None:
                    raw_copies.append((which, raw))

        # NEITHER COPY IS WHOLE. That is not the end of it when the index
        # is segmented: each segment carries its own checksum, so a
        # segment damaged in one copy can be taken from the other. Two
        # small faults in different places -- which is what failing media
        # actually produces -- lose nothing.
        if len(raw_copies) > 1:
            try:
                body = index_frame.assemble(
                    [raw for _which, raw in raw_copies],
                    on_repair=self.damage.append)
            except C.PaktError as exc:
                errors.append(f"stitching: {exc}")
            else:
                names = "+".join(which for which, _raw in raw_copies)
                self.damage.append(
                    f"index recovered by combining copies {names}")
                return _LoadedIndex(Index.deserialise(body), names)

        raise PaktCorruptError(
            "both index copies are unreadable -- " + "; ".join(errors))

    def _raw_index(self, offset: int, length: int) -> Optional[bytes]:
        """
        An index copy's bytes, decrypted if need be, without parsing.

        Used only on the stitching path. Returns None when the region
        cannot even be read -- a truncated tail, or a key that will not
        open it -- because there is nothing to contribute then.
        """
        try:
            raw = self._read_at(offset, length)
        except C.PaktError:
            return None
        if self._key is None:
            return raw
        try:
            return crypto.open_sealed(
                self._key, self.crypto_header.index_nonce, raw,
                self.crypto_header.index_tag,
                crypto.index_aad(self.crypto_header.salt))
        except Exception:
            # An encrypted index is sealed as ONE region under a single
            # GCM tag, so any damage fails authentication for the whole
            # copy and there are no verified pieces left to stitch. That
            # is a property of sealing the region, not an oversight here;
            # per-segment sealing would change it and is a format matter.
            return None

    def _parse_index(self, offset: int, length: int) -> Index:
        raw = self._read_at(offset, length)

        if self._key is not None:
            # Spec section 5.3: authenticate before anything is read
            # out. The preamble is inside the sealed region here, so
            # even the index's lengths stay unreadable without the key.
            raw = crypto.open_sealed(
                self._key, self.crypto_header.index_nonce, raw,
                self.crypto_header.index_tag,
                crypto.index_aad(self.crypto_header.salt))

        # One copy, all of it, through the shared framing so that a
        # segmented and an unsegmented index are read by the same code the
        # writers used to produce them.
        body = index_frame.assemble([raw], on_repair=self.damage.append)
        return Index.deserialise(body)

    # -- listing ----------------------------------------------------------

    @property
    def entries(self) -> list[FileEntry]:
        return self.index.files

    def __len__(self) -> int:
        return len(self.index.files)

    # -- block access -----------------------------------------------------

    def _block(self, i: int) -> bytes:
        """Decode block ``i``, verifying its CRC before returning it."""
        if i in self._block_cache:
            return self._block_cache[i]
        try:
            entry = self.index.blocks[i]
        except IndexError:
            raise PaktFormatError(
                f"entry references block {i}, but the archive has "
                f"{len(self.index.blocks)}") from None

        dictionary = self._dictionary(entry.dict_index)
        stored = self._read_at(entry.offset, entry.stored_size)

        if self._key is not None:
            # The tag is verified here, before a single byte is handed
            # to a codec -- let alone written to disk.
            stored = crypto.open_sealed(
                self._key, entry.nonce, stored, entry.tag,
                crypto.block_aad(self.crypto_header.salt, i))

        plain = decompress(stored, entry.codec, plain_size=entry.plain_size,
                           dictionary=dictionary)
        if entry.bcj:
            plain = reverse_bcj(plain)

        if C.crc32(plain) != entry.plain_crc32:
            raise PaktCorruptError(
                f"block {i} failed its CRC check; the archive is damaged")

        # Bounded cache: blocks are capped at 64 MiB, so hold a handful.
        if len(self._block_cache) > 4:
            self._block_cache.clear()
        self._block_cache[i] = plain
        return plain

    def _dictionary(self, index: int) -> Optional[bytes]:
        """
        Load an embedded dictionary referenced by a block.

        A block compressed against a trained dictionary is undecodable
        without it -- zstd reports "Dictionary mismatch" rather than
        producing wrong data, which is the right failure but still a
        failure. This was missing entirely at first: the engine wrote
        dictionaries, the format recorded them, and the reader ignored
        them, so every archive that used one was unreadable.
        """
        if index == C.NO_DICT or index >= len(self.index.dicts):
            return None
        if index in self._dict_cache:
            return self._dict_cache[index]

        entry = self.index.dicts[index]
        if entry.kind != 0:
            raise PaktUnsupportedError(
                f"block needs dictionary {entry.dict_id!r}, which is "
                f"referenced by identifier rather than embedded; this "
                f"build cannot resolve it")

        data = self._read_at(entry.offset, entry.length)
        if entry.dict_crc32 and C.crc32(data) != entry.dict_crc32:
            raise PaktCorruptError(
                f"dictionary {index} failed its CRC check")

        self._dict_cache[index] = data
        return data

    def read(self, entry: FileEntry) -> bytes:
        """
        Reconstruct one entry's content and verify its SHA-256.

        Follows a deduplication reference to the entry that actually
        holds the bytes.
        """
        if entry.is_dedup_ref:
            if not (0 <= entry.dedup_ref < len(self.index.files)):
                raise PaktFormatError(
                    f"entry {entry.path!r} points at duplicate index "
                    f"{entry.dedup_ref}, which does not exist")
            target = self.index.files[entry.dedup_ref]
            if target.is_dedup_ref:
                raise PaktFormatError(
                    "deduplication reference points at another reference; "
                    "chains are not permitted")
            data = self.read(target)
        elif entry.block_index == C.NO_BLOCK:
            data = b""
        else:
            data = self._reconstruct(entry)

        if entry.plain_size and len(data) != entry.plain_size:
            raise PaktCorruptError(
                f"{entry.path!r} reconstructed to {len(data)} bytes, index "
                f"says {entry.plain_size}")
        if entry.digest != bytes(C.DIGEST_SIZE):
            actual = C.file_digest(hashlib.sha256(data).digest())
            if actual != entry.digest:
                raise PaktCorruptError(
                    f"{entry.path!r} failed content verification; the bytes "
                    f"do not match the digest recorded when it was archived")
        return data

    def _reconstruct(self, entry: FileEntry) -> bytes:
        """Assemble an entry, spanning consecutive blocks if oversized."""
        first = entry.block_index
        if entry.plain_size <= C.MAX_BLOCK_PLAIN_SIZE:
            block = self._block(first)
            start = entry.block_offset
            return block[start:start + entry.plain_size]

        # Spec §12.5: a file above the cap owns consecutive blocks.
        n = -(-entry.plain_size // C.MAX_BLOCK_PLAIN_SIZE)
        return b"".join(self._block(first + k) for k in range(n))

    # -- extraction -------------------------------------------------------

    def extract_all(
        self,
        destination: str | os.PathLike[str],
        *,
        limits: Optional[ExtractLimits] = None,
    ) -> int:
        """
        Extract every entry into ``destination``.

        Returns the number of entries written. Raises before writing
        anything outside the destination, and aborts the whole
        extraction on any integrity or security failure.
        """
        limits = limits or ExtractLimits()
        root = os.path.abspath(os.fspath(destination))
        os.makedirs(root, exist_ok=True)

        if len(self.index.files) > limits.max_entries:
            raise SecurityError(
                f"archive declares {len(self.index.files)} entries, above "
                f"the {limits.max_entries} cap")

        self._precheck_bomb(limits)

        written = 0
        total = 0
        for entry in self.index.files:
            target = self._safe_target(root, entry.path)

            if entry.entry_type is EntryType.DIRECTORY:
                os.makedirs(target, exist_ok=True)
                written += 1
                continue

            os.makedirs(os.path.dirname(target), exist_ok=True)

            if entry.entry_type is EntryType.SYMLINK:
                if not limits.allow_symlinks:
                    raise SecurityError(
                        f"archive contains the symlink {entry.path!r}; "
                        f"symlink extraction is disabled by default")
                self._write_symlink(root, target, self.read(entry))
                written += 1
                continue

            data = self.read(entry)
            total += len(data)
            if total > limits.max_total_bytes:
                raise SecurityError(
                    f"extraction exceeded the {limits.max_total_bytes} byte "
                    f"total cap; aborting rather than filling the disk")

            with open(target, "wb") as out:
                out.write(data)
            if entry.mode:
                try:
                    os.chmod(target, entry.mode)
                except OSError:
                    pass
            written += 1

        return written

    def _precheck_bomb(self, limits: ExtractLimits) -> None:
        """
        Refuse implausible expansion *before* decoding anything.

        Checked against the declared block table, so a bomb is caught
        without having to inflate it first.
        """
        # For .pakt the format itself already bounds expansion: every
        # block is capped at 64 MiB uncompressed (spec section 6.1),
        # so no single block can produce an unbounded amount however
        # extreme its ratio. The absolute total below is what actually
        # protects the disk.
        declared = sum(b.plain_size for b in self.index.blocks)
        if declared > limits.max_total_bytes:
            raise SecurityError(
                f"archive declares {declared} uncompressed bytes, above the "
                f"{limits.max_total_bytes} cap")

        for i, block in enumerate(self.index.blocks):
            if block.stored_size == 0:
                continue
            ratio = block.plain_size / block.stored_size
            if ratio > limits.max_ratio:
                raise SecurityError(
                    f"block {i} expands {ratio:.0f}x, above the "
                    f"{limits.max_ratio:.0f}x cap; refusing as a likely "
                    f"decompression bomb")

    def _safe_target(self, root: str, arc_path: str) -> str:
        """
        Resolve an entry path against the root and prove it stays inside.

        Validated again here even though the writer was required to
        produce conforming paths — a reader must never trust the writer
        (spec §12.6). Resolution happens per entry, at creation time, so
        a symlink written earlier cannot redirect a later path.
        """
        # .pakt's own path rules are stricter than the shared policy --
        # the format forbids what other formats merely tolerate -- so
        # both run. The format check first, then the universal
        # resolve-and-prove that every handler shares.
        validate_archive_path(arc_path)
        return safe_target(root, arc_path)

    def _write_symlink(self, root: str, target: str, raw: bytes) -> None:
        link_target = raw.decode("utf-8")
        check_link_target(root, target, link_target)
        if os.path.lexists(target):
            os.remove(target)
        os.symlink(link_target, target)

    # -- reporting --------------------------------------------------------

    def describe(self) -> str:
        flags = self.header.feature_flags
        names = [f.name for f in Feature if f.value and (flags & f)] or ["none"]
        return (
            f"{self.path}: .pakt {self.header.version_major}."
            f"{self.header.version_minor}, {len(self.index.files)} entries, "
            f"{len(self.index.blocks)} blocks, index copy "
            f"{self.index_copy_used}, features: {', '.join(names)}"
        )


def open_pakt(path: str | os.PathLike[str], *,
              password: Optional[str] = None) -> PaktArchive:
    """Open a `.pakt` archive for reading."""
    path = os.fspath(path)
    return PaktArchive(open(path, "rb"), path=path, password=password)
