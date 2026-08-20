# The `.pakt` Container Format — Version 1.0

**Status:** FROZEN. This document defines `.pakt` format version 1.0.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)
Licensed under the Apache License, Version 2.0. See `LICENSE-SPEC`.

---

## 0. About this document

`.pakt` is the container format written by Compakt. This specification
is licensed permissively and separately from the Compakt application so
that anyone can implement it — reader, writer, or both — in any
language, for any purpose, without permission.

Format 1.0 is the first and only published version. There is no
earlier revision and no backward-compatibility burden. Everything the
format will ever need to express structurally is defined here, whether
or not version 1.0 writers emit it.

### 0.1 Conventions

- All integers are **little-endian** and unsigned unless stated.
- `u8`, `u16`, `u32`, `u64` denote unsigned integers of that bit width;
  `i64` denotes a signed 64-bit integer.
- Offsets are **absolute, measured from the start of the container**,
  which is not necessarily the start of the file (see §2).
- "MUST", "MUST NOT", "SHOULD" and "MAY" carry their ordinary
  specification force.
- Byte ranges are written `[start, end)` — end exclusive.
- Reserved fields MUST be written as zero and MUST be ignored on read,
  except where a reader is explicitly required to reject them.

### 0.2 Design commitments

Six properties drove the layout, and every structural choice below
follows from one of them:

1. **A truncated archive is partially recoverable.** The index is
   written twice, at both ends of the container.
2. **Unknown archives fail loudly, never silently.** Feature flags are
   explicit and readers reject anything they do not understand.
3. **The file listing is not public.** When encryption is enabled the
   index itself is encrypted, unlike ZIP, which leaks every filename.
4. **Authentication precedes disclosure.** No plaintext byte reaches
   the disk before its authentication tag has been verified.
5. **The container is relocatable.** An arbitrary prefix may precede
   it, which is what makes the polyglot form possible.
6. **The network layer has somewhere to go.** Structures for chunking,
   Merkle verification and parity are defined but not emitted.

---

## 1. Terminology

| Term | Meaning |
|---|---|
| **Container** | The `.pakt` structure proper, beginning at the header. |
| **Prefix** | Optional arbitrary bytes before the container (§2.1). |
| **Block** | A unit of compression. May hold many files (a *solid block*). |
| **Index** | The metadata catalogue: blocks, dictionaries, file entries. |
| **Entry** | One filesystem object recorded in the index. |
| **Routing class** | The detector's classification of a file's data profile. |

---

## 2. File layout

```
+=====================================+  file offset 0
|  PREFIX (optional, arbitrary size)  |   polyglot HTML + WASM stub
+=====================================+  <-- container offset
|  HEADER                    64 bytes |
+-------------------------------------+
|  CRYPTO HEADER   72 bytes, optional |   present iff ENCRYPTED
+-------------------------------------+
|  INDEX COPY A            (variable) |   primary
+-------------------------------------+
|  BLOCK DATA              (variable) |   the compressed payload
+-------------------------------------+
|  DICTIONARY DATA         (variable) |   present iff DICT_EMBEDDED
+-------------------------------------+
|  INDEX COPY B            (variable) |   byte-identical to copy A
+-------------------------------------+
|  SIGNATURE BLOCK  104 bytes, opt.   |   present iff SIGNED
+-------------------------------------+
|  FOOTER                    32 bytes |
+=====================================+  end of file
```

### 2.1 Locating the container

A reader MUST locate the container by reading the final 32 bytes of the
file and validating the footer (§7). The footer carries the container
offset. A reader MUST NOT assume the container begins at file offset 0.

This is what allows a `.pakt` file to also be a valid HTML document:
the browser reads from the top and ignores the trailing binary; the
`.pakt` reader reads the footer and ignores the leading text.

If footer validation fails, a reader SHOULD attempt recovery by
scanning for the header magic (§3) from file offset 0, and MUST warn
that the archive is damaged.

### 2.2 Why the index appears twice

Copy A survives truncation of the tail. Copy B survives corruption of
the head. They MUST be byte-identical; a reader that finds both valid
and differing MUST treat the archive as damaged and SHOULD prefer copy
B, which is written after the block data and therefore reflects the
completed write.

Both claims above depend on a reader that reaches for the other copy, and
neither is free. Truncation removes the *footer*, so a reader MUST be
prepared to locate the container without it (§2.1) or copy A is
unreachable however intact it is. Corruption of the head removes the
*header*, and with it both index offsets — which is why the footer
duplicates `index_b_offset` (§7). A reader that takes both offsets from
the header alone cannot honour this section.

Neither copy being whole does not end it. Where the index is segmented
(§12.7) a reader MAY combine them, taking each segment from whichever
copy still verifies its checksum, and recovers unless some one segment is
damaged in both.

A writer produces them by reserving space for copy A, writing the
blocks, writing copy B, then seeking back to fill copy A. Writers
therefore require a seekable output stream. Streaming writers are not
supported in 1.0.

---

## 3. Header (64 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 6 | `magic` | `50 41 4B 54 1A 0A` — `"PAKT"`, EOF char, LF |
| 6 | 1 | `version_major` | `1` |
| 7 | 1 | `version_minor` | `0` |
| 8 | 8 | `feature_flags` | u64, see §4 |
| 16 | 8 | `index_a_offset` | u64 |
| 24 | 8 | `index_a_length` | u64, stored length |
| 32 | 8 | `index_b_offset` | u64 |
| 40 | 8 | `index_b_length` | u64, stored length |
| 48 | 8 | `container_length` | u64, header through footer inclusive |
| 56 | 4 | `header_crc32` | CRC-32 (IEEE) over bytes `[0, 56)` |
| 60 | 4 | `reserved` | zero |

The magic sequence is deliberately shaped like the PNG signature: the
`1A` byte terminates output if the file is `type`d on DOS/Windows, and
the `0A` catches CR/LF mangling by naive text transfer.

A reader MUST reject the archive if `magic` does not match, if
`header_crc32` fails, or if `version_major` is greater than the version
it implements.

---

## 4. Feature flags

`feature_flags` is a u64 bitfield. Bit 0 is the least significant bit.

### 4.1 Defined in 1.0

| Bit | Name | Meaning |
|---|---|---|
| 0 | `ENCRYPTED` | Crypto header present; index and blocks are sealed. |
| 1 | `SIGNED` | Signature block present (§8). |
| 2 | `REPRODUCIBLE` | Built under the determinism rules of §10. |
| 3 | `POLYGLOT` | A prefix is present; codec set is constrained (§9). |
| 4 | `SOLID_BLOCKS` | At least one block holds more than one file. |
| 5 | `DEDUP_WHOLE_FILE` | At least one entry is a duplicate reference. |
| 6 | `DICT_EMBEDDED` | Dictionary data section present. |
| 7 | `DICT_BY_ID` | At least one dictionary is referenced by identifier. |
| 8 | `BCJ_FILTER` | At least one block had a BCJ branch filter applied. |

### 4.2 Reserved for the network layer

These bits are **defined but MUST NOT be set by a 1.0 writer.** A 1.0
reader MUST reject any archive in which any of them is set. They exist
so that archives written today remain structurally compatible with a
future distributed layer, without a format break.

| Bit | Name | Reserved for |
|---|---|---|
| 16 | `CHUNK_TABLE` | Content-defined chunk table (§11.1) |
| 17 | `MERKLE_DAG` | Merkle tree over chunk hashes (§11.2) |
| 18 | `RS_PARITY` | Reed–Solomon parity blocks (§11.3) |
| 19 | `CDC_CHUNKING` | FastCDC chunk boundaries in use |
| 20 | `CONVERGENT_ENC` | Convergent encryption mode (§11.4) |

Bits 9–15 and 21–63 are reserved. A writer MUST set them to zero. A
reader MUST reject any archive in which a reserved bit is set.

### 4.3 Mutual exclusions

**`ENCRYPTED` and `REPRODUCIBLE` MUST NOT both be set.** A writer MUST
refuse; a reader MUST reject.

This is not a stylistic restriction. Reproducibility requires that
identical input produce identical output bytes, which includes the
AES-GCM nonce. AES-GCM security depends absolutely on never reusing a
(key, nonce) pair — reuse does not degrade security gracefully, it
collapses it: an attacker recovers plaintext by XOR and recovers the
GHASH authentication key, which permits forging archives that verify
correctly. Rather than manage that hazard, 1.0 forbids the combination.

The alternative — deriving the nonce from a hash of the plaintext — is
convergent encryption. It is safe against reuse but reveals that two
archives have identical contents. That construction is reserved under
bit 20 and is out of scope for 1.0.

---

## 5. Crypto header (72 bytes, present iff `ENCRYPTED`)

Immediately follows the header.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | `"PCRY"` |
| 4 | 1 | `kdf_id` | `0` = PBKDF2-HMAC-SHA256, `1` = Argon2id |
| 5 | 1 | `aead_id` | `0` = AES-256-GCM |
| 6 | 2 | `reserved` | zero |
| 8 | 16 | `salt` | CSPRNG, unique per archive |
| 24 | 16 | `kdf_params` | interpretation depends on `kdf_id` |
| 40 | 12 | `index_nonce` | GCM nonce for the index |
| 52 | 16 | `index_tag` | GCM tag for the index |
| 68 | 4 | `crypto_crc32` | CRC-32 over bytes `[0, 68)` |

`kdf_params` layout:

- **PBKDF2** (`kdf_id = 0`): `u32 iterations`, 12 bytes reserved.
  Writers MUST use at least 600,000 iterations.
- **Argon2id** (`kdf_id = 1`): `u32 time_cost`, `u32 memory_kib`,
  `u32 parallelism`, 4 bytes reserved. Writers SHOULD use at least
  `time_cost = 3`, `memory_kib = 65536`, `parallelism = 4`.

**Writers SHOULD default to Argon2id.** PBKDF2 is retained for
implementations without an Argon2 binding. Argon2id is memory-hard and
therefore far more resistant to GPU and ASIC cracking, which is the
realistic attack against a password-protected archive.

The derived key is 32 bytes and is used for both the index and all
blocks. Each encrypted region carries its own unique nonce.

### 5.1 Nonce discipline

Every nonce in an encrypted archive MUST be generated by a CSPRNG and
MUST be unique within that archive. Writers MUST NOT derive nonces from
a counter, a file path, a block index, or any other value that could
collide across archives sharing a password.

### 5.2 Additional authenticated data

Each GCM operation MUST bind its context so that regions cannot be
transplanted between archives or reordered within one. AAD is:

- **Index:** `"pakt/1.0/index"` followed by the 16-byte `salt`.
- **Block *n*:** `"pakt/1.0/block"`, the 16-byte `salt`, then `u32 n`
  (the block's index in the block table).

Both strings are ASCII with no terminator. The label provides domain
separation, so an index can never be accepted as a block or the
reverse. The salt binds every region to one specific archive, since it
is unique per archive and covered by the crypto header's own CRC. The
block index binds each block to its position, so blocks cannot be
reordered or swapped between archives sharing a password.

The salt is used rather than the header because **the header is not
known when blocks are encrypted.** It records `index_a_offset`,
`index_b_offset` and `container_length`, none of which can be computed
until the encrypted payload has been sized — but sizing it requires
encrypting it first. The salt carries the same binding property, is
fixed before any encryption begins, and breaks that cycle.

### 5.3 Authenticate before disclosure

A reader MUST verify a region's GCM tag over the complete ciphertext
before releasing any plaintext from that region — to disk, to a
caller, or to any observable channel. A wrong password or a tampered
archive MUST fail cleanly, never after having scattered
attacker-influenced bytes across the filesystem.

Because blocks are capped at 64 MiB (§6.1), this requires at most
64 MiB of buffer per in-flight block.

---

## 6. Blocks

A block is a byte range of compressed data. Files are concatenated into
blocks grouped by routing class, so that similar data compresses
together — this is what recovers the cross-file redundancy that
per-file compression discards.

### 6.1 Block constraints

- A block's **uncompressed** content MUST NOT exceed **64 MiB**
  (67,108,864 bytes). This bounds the work needed to extract a single
  file, and bounds the decryption buffer.
- A file larger than 64 MiB occupies one or more blocks by itself and
  MUST NOT share them.
- Blocks are independently decodable. Decoding block *n* MUST NOT
  require any other block.
- Implementations SHOULD cap total concurrent in-flight block memory.
  At 64 MiB per block and one block per worker thread, sixteen workers
  imply a 1 GiB working set before trial compression is counted.

### 6.2 Codec identifiers

| ID | Codec | Notes |
|---|---|---|
| 0 | `STORE` | No compression. Content is stored verbatim. |
| 1 | `ZSTD` | Zstandard frame. |
| 2 | `BROTLI` | Brotli stream. |
| 3 | `LZMA` | LZMA1 with explicit properties, or LZMA2. |

IDs 4–255 are reserved. A reader MUST reject a block whose codec ID it
does not implement, and MUST report which codec was required.

### 6.3 Routing classes

Recorded per block and per entry so that `pakt explain` can report why
a codec was chosen. Advisory: a reader MUST NOT use these to decide how
to decode, only the codec ID.

| ID | Class |
|---|---|
| 0 | `UNKNOWN` |
| 1 | `REPETITIVE_TEXT` |
| 2 | `STRUCTURED_BLOCKS` |
| 3 | `HIGH_CONTEXT_VECTORS` |
| 4 | `GENOMIC_STRINGS` |
| 5 | `MAXIMUM_ENTROPY_BINARY` |
| 6 | `EXECUTABLE` |

### 6.4 Filters

If a block's `flags` bit 0 is set, a BCJ x86 branch filter was applied
to the block's content *before* compression. A reader MUST reverse the
filter *after* decompression. Filters are per-block, never per-file.

---

## 7. Footer (32 bytes, at end of file)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `container_offset` | u64, file offset where the header begins |
| 8 | 8 | `index_b_offset` | u64, duplicated for recovery |
| 16 | 4 | `version` | u32, `(major << 16) \| minor` |
| 20 | 4 | `footer_crc32` | CRC-32 over bytes `[0, 20)` |
| 24 | 2 | `reserved` | zero |
| 26 | 6 | `magic` | `0A 1A 54 4B 41 50` — `"PAKT"` reversed |

The footer is fixed size and terminal so that a reader can find it in a
single seek regardless of prefix length or archive size.

---

## 8. Signature block (104 bytes, present iff `SIGNED`)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `magic` — `"PSIG"` |
| 4 | 1 | `alg_id` — `0` = Ed25519 |
| 5 | 3 | `reserved` |
| 8 | 32 | `public_key` |
| 40 | 64 | `signature` |

The signature covers, in order: the 64 header bytes, the crypto header
if present, and index copy B exactly as stored. Verification MUST
happen before extraction when the caller requests it, and a failure
MUST abort.

Signing proves who produced an archive. It does not imply encryption,
and it does not prevent reading — an unencrypted signed archive is
fully readable by an implementation that ignores the signature.

---

## 9. The polyglot form

When `POLYGLOT` is set, the file begins with an arbitrary prefix: an
HTML document carrying an embedded WebAssembly decoder, so the archive
can be opened in a browser with nothing installed.

### 9.1 Constraints

- Every block MUST use codec `STORE` or `ZSTD`. `BROTLI` and `LZMA` are
  forbidden.
- `index_codec` (§12.1) MUST also be `STORE` or `ZSTD`, for both index
  copies. The index is not a block, so the constraint above does not
  reach it, and an index the stub cannot decompress locks the archive
  just as completely as a block it cannot decompress.
- Dictionaries, if used, MUST be embedded, never referenced by id.
- The prefix MUST NOT be covered by any checksum in the container.
  It is not part of the container and may be replaced or stripped
  without invalidating the archive.

The codec restriction is the whole point of the flag. A stub that had
to carry WASM builds of Brotli, Zstandard *and* LZMA would add roughly
a megabyte to every archive, before base64 inlining added a third
again. Restricting the polyglot form to a single codec keeps the stub
small enough to be worth prepending. Ordinary `.pakt` archives are
unaffected and continue to use the full codec set.

The index rule is stated separately because it is the easier one to
miss: a writer that routes blocks correctly and then compresses its
index with whatever performed best will produce an archive that a
conforming minimal stub cannot open, and it will do so without
violating any other rule in this document.

### 9.2 Known limitation

A page loaded from a `file://` URL cannot read its own bytes; browsers
block it. The practical flow is therefore: open the file, then drag the
same file onto the page it just opened. Implementations SHOULD state
this plainly in the stub rather than implying a pure double-click
experience that will not occur.

---

## 10. Reproducible mode

When `REPRODUCIBLE` is set, identical input MUST produce a
byte-identical archive on any machine, on any date, under any locale.
A writer claiming this flag MUST observe all of the following:

1. `mtime_ns` on every entry is written as `0`.
2. Entries are sorted by path, comparing raw UTF-8 bytes ascending.
3. Files are assigned to blocks by a deterministic rule that depends
   only on sorted order, routing class and size.
4. `ENCRYPTED` is not set (§4.3), so no random nonce or salt exists.
5. Dictionaries are either referenced by id, or trained by a
   deterministic procedure with a fixed seed and fixed sample order.
6. Codec parameters are fixed by routing class, never by wall-clock or
   by an adaptive time budget.
7. No field anywhere records a build timestamp, hostname, username,
   process id, or absolute source path.

Compression itself must be deterministic for a given codec and
parameter set. All four supported codecs are, at fixed parameters and a
fixed input.

---

## 11. Reserved network structures

**These are defined so that archives written by version 1.0 remain
structurally compatible with a future distributed storage layer.** A
1.0 writer MUST NOT emit them and a 1.0 reader MUST reject any archive
whose flags claim them (§4.2).

They are specified now, rather than later, because the project has
committed to there being no format break: version 1.0 is what every
future reader must support forever. Retrofitting these would require
the break that commitment forbids.

### 11.1 Chunk table

Appended to the index after the file table when `CHUNK_TABLE` is set.

```
u32  n_chunks
n_chunks * CHUNK_ENTRY:
    u64  offset            offset within the uncompressed block
    u32  length            chunk length in bytes
    u32  block_index       block the chunk belongs to
    32   sha256            hash of the chunk's plaintext
```

### 11.2 Merkle DAG

When `MERKLE_DAG` is set, a 32-byte root hash follows the chunk table,
then a level-ordered serialisation of interior nodes. The tree is
binary, over `sha256` chunk hashes in chunk-table order, with an odd
final node promoted unchanged. The root permits verifying any single
chunk without possessing the whole archive.

### 11.3 Reed–Solomon parity

When `RS_PARITY` is set, parity blocks follow the dictionary data
section and are described by:

```
u32  n_parity_blocks
u16  data_shards
u16  parity_shards
n_parity_blocks * PARITY_ENTRY:
    u64  offset
    u64  length
    u32  covers_first_block
    u32  covers_last_block
```

### 11.4 Convergent encryption

When `CONVERGENT_ENC` is set, block nonces are derived from a hash of
block plaintext rather than generated randomly, permitting deduplication
across users who do not share a password. This mode leaks the fact that
two archives contain identical data and is subject to
confirmation-of-file attacks. It is reserved, not endorsed, and MUST
NOT be enabled without an explicit, informed user choice.

---

## 12. Index

The index is the catalogue. It is serialised, then optionally
compressed, then optionally encrypted, in that order. `index_a_length`
and `index_b_length` in the header record the **stored** length after
all transformations.

### 12.1 Index preamble (24 bytes, never encrypted)

Precedes the transformed index blob at both copies.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `magic` — `"PIDX"` |
| 4 | 1 | `index_codec` — codec ID (§6.2) applied to the blob |
| 5 | 1 | `flags` — bit 0: `SEGMENTED` (§12.7) |
| 6 | 2 | `n_segments` — u16, count when `SEGMENTED`, else zero |
| 8 | 8 | `plain_length` — u64, serialised length before transforms |
| 16 | 4 | `plain_crc32` — CRC-32 over the serialised blob |
| 20 | 4 | `preamble_crc32` — CRC-32 over bytes `[0, 20)` |

`flags` and `n_segments` occupy the three bytes this structure previously
reserved, so the preamble is still 24 bytes.

The preamble stays in the clear so a reader can size its buffers before
holding the key. It reveals only lengths, never names.

> **Known divergence, unresolved.** The reference implementation seals the
> preamble along with the rest of the index region in an encrypted
> archive, so its lengths are *not* readable without the key — the
> opposite of the paragraph above. The implementation's behaviour leaks
> less; this paragraph is what a second implementer would build against.
> One of the two must change and neither has yet.

### 12.2 Index body

```
u16  index_version        = 1
u16  reserved
u32  n_blocks
u32  n_dicts
u32  n_files
u64  total_uncompressed   sum of all entry sizes, before dedup
block_table               n_blocks * BLOCK_ENTRY   (§12.3)
dict_table                n_dicts  * DICT_ENTRY    (§12.4)
file_table                n_files  * FILE_ENTRY    (§12.5)
u32  body_crc32           CRC-32 over everything above
```

### 12.3 `BLOCK_ENTRY` (72 bytes, fixed)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `offset` — container-absolute offset of block data |
| 8 | 8 | `stored_size` — bytes on disk |
| 16 | 8 | `plain_size` — bytes after decompression |
| 24 | 1 | `codec` (§6.2) |
| 25 | 1 | `routing_class` (§6.3) |
| 26 | 1 | `dict_index` — index into `dict_table`, `0xFF` = none |
| 27 | 1 | `flags` — bit 0: BCJ filter applied |
| 28 | 4 | `plain_crc32` — CRC-32 of decompressed content |
| 32 | 12 | `nonce` — GCM nonce; zero when not encrypted |
| 44 | 16 | `tag` — GCM tag; zero when not encrypted |
| 60 | 12 | `reserved` |

The nonce and tag fields are always present, so a block entry has one
fixed size. At 72 bytes per 64 MiB block, the table costs about 1 KiB
per gigabyte of archive.

### 12.4 `DICT_ENTRY` (variable)

```
u8   kind           0 = embedded, 1 = referenced by id
u8   codec          codec the dictionary applies to
u16  id_len         length of id_utf8, zero when embedded
u64  offset         container-absolute; zero when referenced
u64  length         dictionary length in bytes
u32  dict_crc32     CRC-32 of the dictionary bytes
id_len bytes        id_utf8
```

Referenced dictionaries let an archive name a dictionary it does not
carry. A reader that cannot resolve the identifier MUST fail with a
clear message naming it, and MUST NOT attempt to decode without it.

### 12.5 `FILE_ENTRY` (variable)

```
u16  path_len
path_len bytes      path_utf8   (§12.6)
u8   entry_type     0 = file, 1 = directory, 2 = symlink
u8   routing_class  (§6.3)
u16  flags          bit 0: entry is a duplicate reference
u32  mode           POSIX permission bits; zero if unknown
i64  mtime_ns       nanoseconds since the Unix epoch; zero if reproducible
u64  plain_size     uncompressed size in bytes
u32  block_index    block holding the content; 0xFFFFFFFF if none
u64  block_offset   offset of the content within the decompressed block
u32  dedup_ref      index of the entry this duplicates; else 0xFFFFFFFF
16   digest         first 16 bytes of the SHA-256 of the entry's
                    uncompressed content
```

`digest` is **truncated deliberately**, and an implementation MUST use
the first 16 bytes of SHA-256 — not a different 16, and not a different
hash. Writers and readers that disagree by a slice produce archives that
fail integrity checks on content that is perfectly intact.

The truncation was measured before it was adopted. On an archive of many
small unique files the index reached three quarters of the container and
two stored copies of a 32-byte hash were most of that; narrowing the
field made such archives 28–35% smaller. On archives of large or
duplicated files it changes almost nothing, which is the expected shape:
duplicated files share a digest, so those bytes compressed away already.

What the shorter field costs is worth stating precisely, because
"shortened hash" invites the wrong conclusion:

- **Second-preimage resistance is unchanged at 2^128.** This is the
  property integrity checking rests on — an attacker holds the archived
  file and must produce a *different* file with the same digest.
- **Collision resistance halves to 2^64.** This matters only to an
  attacker who controls *both* files, which means they authored the
  archive — and an author who wants different content can simply write
  it. The one real exposure is signing a third party's archive that
  already contains a pre-computed colliding pair.
- **Deduplication is unaffected.** A million-entry archive has a
  birthday collision probability near 10^-27.
- **Recovery is unaffected.** That property comes from §7 and §12.1
  writing the index at both ends of the container, and has nothing to do
  with hash width.

- **Files larger than the block cap** occupy *consecutive* blocks
  beginning at `block_index`, with `block_offset = 0`. The count is
  `ceil(plain_size / 64 MiB)`, and per §6.1 such a file never shares a
  block with another entry, so the run is unambiguous. A reader
  reconstructs the content by concatenating those blocks in order.
- **Directories** carry `plain_size = 0`, `block_index = 0xFFFFFFFF`,
  and a zeroed `digest`.
- **Symlinks** store their target as the content, UTF-8 encoded, in a
  block like any other payload.
- **Duplicate references** set flags bit 0, point `dedup_ref` at the
  first entry with matching `digest` and `plain_size`, and set
  `block_index = 0xFFFFFFFF`. Deduplication is free: the hash is
  already required for integrity.

### 12.6 Path rules

Paths are the single largest source of archive vulnerabilities, so the
constraints are normative on both sides.

A writer MUST emit paths that:

- use `/` as separator, never `\`;
- are relative — no leading `/`, no drive letter, no UNC prefix;
- contain no `.` or `..` component;
- contain no NUL byte;
- are valid UTF-8;
- are unique within the archive.

A reader MUST reject any entry violating the above, and MUST
additionally refuse to write outside the extraction root after
resolution (§13.1). A reader MUST NOT trust the writer to have complied.

### 12.7 Segmented index

When `SEGMENTED` is set in the preamble `flags`, the index body is split
into `n_segments` pieces, each transformed and checksummed *independently*,
and a segment table follows the preamble:

```
n_segments * SEGMENT_ENTRY        (12 bytes each, below)
u32  table_crc32                  CRC-32 over the entries above
segment payloads, concatenated in order
```

`SEGMENT_ENTRY`:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `stored_length` — bytes on disk for this segment |
| 4 | 4 | `plain_length` — bytes after decoding |
| 8 | 4 | `plain_crc32` — CRC-32 of this segment's plain bytes |

**Why this exists.** The index is written twice (§2.2) so that damage at
either end of the container is survivable. As a single blob under a single
checksum that only helps when damage misses one copy *entirely*: one bad
byte condemns a whole copy, and one bad byte in *each* copy loses the
archive even though every byte survived somewhere between them. Two small
independent faults is what failing media and interrupted writes produce,
so that was the ordinary case rather than an exotic one.

A reader MUST verify each segment against its own `plain_crc32`, and MAY
take segment *i* from whichever copy of the index verifies it, provided
both copies agree on `n_segments` and `plain_crc32` in the preamble.
Copies whose preamble `plain_crc32` differs describe different content and
MUST NOT be combined.

After reassembly a reader MUST still verify the whole body against the
preamble's `plain_crc32`. The per-segment checksums say which pieces
survived; the whole-body checksum says the reassembly is correct, and a
stitched index that has not been verified end to end must not be used —
every offset in it would be believed.

Segment lengths are explicit rather than implied by a fixed size, so a
writer may choose any segmentation, or none. `SEGMENTED` unset, or set
with `n_segments` of 1, is valid and equivalent in recoverability to the
unsegmented layout.

**A writer should not segment unconditionally.** Segments cannot share
compression context, and where an index's redundancy is long-range — many
near-identical paths, repeated digests — splitting it costs real space. On
a measured corpus of 1,800 largely duplicate files, 64 KiB segments cost
33% more index than one blob, while on other corpora segmenting was
slightly *smaller* than not. Choose by measurement.

---

## 13. Reader security requirements

These are normative. An implementation that omits them is not a
conforming `.pakt` reader, whatever else it does correctly. Archive
utilities are attacked through their extractors far more often than
through their codecs.

### 13.1 Path traversal

Before creating any filesystem object, a reader MUST resolve the
target path against the extraction root, following the rules of the
host platform, and MUST verify the result remains inside that root.
Entries resolving outside MUST be rejected and the extraction aborted.

Checking the stored path string is not sufficient. Resolution must
account for symlinks already created during this extraction, so
resolution MUST be performed at the moment of creation rather than
once up front.

### 13.2 Symlinks and links

A reader MUST reject any symlink whose target resolves outside the
extraction root, and MUST reject hard links entirely. Readers SHOULD
default to refusing symlinks altogether and require explicit opt-in.

### 13.3 Decompression bombs

A reader MUST enforce, and MUST allow the caller to configure:

- a maximum total uncompressed output size;
- a maximum ratio of uncompressed to stored bytes, evaluated per block
  and across the archive;
- a maximum entry count.

On breach, extraction MUST abort with a clear diagnostic. A reader MUST
NOT fill the disk and then report failure. Defaults SHOULD be generous
enough not to obstruct legitimate archives — a ratio limit of 1000:1
and a total-size limit derived from available disk space are
reasonable starting points.

### 13.4 Integrity

- Block `plain_crc32` MUST be verified after decompression.
- Entry `digest` MUST be verified after reconstruction, and a mismatch
  MUST be a hard failure for that entry.
- When `ENCRYPTED`, every GCM tag MUST be verified before any plaintext
  is written (§5.3).
- When `SIGNED` and verification was requested, the signature MUST be
  checked before extraction begins.

### 13.5 Resource discipline

A reader MUST bound its own memory using `plain_size` from the block
table *before* allocating, rather than growing a buffer as output
arrives. A block entry claiming an implausible `plain_size` MUST be
rejected against the 64 MiB cap of §6.1 rather than honoured.

---

## 14. Conformance

An implementation is a **conforming reader** if it validates the footer
and header, rejects unknown and reserved feature flags, honours every
requirement of §13, and correctly decodes `STORE` at minimum.

An implementation is a **conforming writer** if it produces archives
that a conforming reader accepts, honours the path rules of §12.6, sets
feature flags accurately, and never sets a reserved bit.

Neither role requires implementing every codec. A reader that
encounters a codec it lacks MUST say which one was needed. Refusing
clearly is conforming behaviour; guessing is not.

---

## 15. Changes

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-08-18 | Initial specification. Frozen. |

Corrections applied during implementation, before any archive was
written by any implementation. The format has not shipped, so these are
corrections to an unpublished draft rather than breaking changes:

- **Multi-block files were inexpressible.** §6.1 allowed a file to
  exceed the 64 MiB block cap, but `FILE_ENTRY` names a single
  `block_index`, so there was no way to record the rest. Resolved in
  §12.5 without a layout change: such a file occupies consecutive
  blocks from `block_index`, which is unambiguous precisely because
  §6.1 already forbids it from sharing them.
- **The AAD definition was circular.** §5.2 originally bound each GCM
  operation to "the 64 header bytes", but the header records index
  offsets and the container length, none of which exist until the
  encrypted payload has been sized — which requires having encrypted
  it. Rebound to the per-archive `salt` plus a domain-separating
  label, which carries the identical binding property and is fixed
  before any encryption starts.
- **Crypto header size 64 → 72 bytes.** As first drafted, `index_tag`
  at offset 52 ran to 68 while `crypto_crc32` was placed at 60, so the
  two fields overlapped and the stated total was wrong. Field offsets
  are unchanged; only the CRC moved to 68 and the size to 72.
- **The polyglot codec restriction did not reach the index.** §9.1
  constrained every *block* to `STORE` or `ZSTD` but said nothing about
  `index_codec`, so a writer could satisfy every rule in this document
  and still produce a polyglot archive whose index needed a Brotli or
  LZMA decoder — unopenable by exactly the minimal stub the flag exists
  to enable. §9.1 now covers the index explicitly. No layout change,
  and no archive is affected: the constraint was always implied by the
  purpose of the flag and is now written down.
