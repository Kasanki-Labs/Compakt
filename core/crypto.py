"""
Cryptography for the .pakt container.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Implements specification §5 (key derivation, authenticated encryption)
and §8 (Ed25519 archive signatures). Everything here is a thin, honest
wrapper over `cryptography`; no primitive is implemented by hand, and
none should ever be.

DESIGN NOTES THAT MATTER
------------------------

**Argon2id is the default, not PBKDF2.** PBKDF2 with SHA-256 is
trivially parallelised on a GPU: an attacker with commodity hardware
tries passwords orders of magnitude faster than the defender derives
them. Argon2id is memory-hard, which forces the attacker to buy RAM
rather than cores. PBKDF2 remains selectable because the format must be
implementable where no Argon2 binding exists, and an archive that
cannot be opened is worse than one protected slightly less well.

**Nonces are always random, never derived.** AES-GCM does not degrade
gracefully on nonce reuse — it collapses. Reusing a (key, nonce) pair
lets an attacker recover plaintext by XOR *and* recover the GHASH
authentication key, which permits forging archives that verify
correctly. This is why the format forbids ENCRYPTED together with
REPRODUCIBLE: byte-identical output would require a deterministic
nonce, and there is no safe way to have both.

**Tags are verified before plaintext is released.** :func:`open_sealed`
returns plaintext only after authentication succeeds; a wrong password
or a tampered archive raises instead. Nothing attacker-influenced
reaches a caller, let alone a disk, on a failed archive.

**Key material is not securely erased.** Python strings and bytes are
immutable and may be copied by the interpreter at will, so a promise of
zeroisation would be theatre. Keys are held in ``bytearray`` where it
costs nothing and :func:`wipe` clears what it can, but the honest
statement is that a process-memory attacker is outside this design's
threat model.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.container import (
    AeadId,
    CryptoHeader,
    KdfId,
    PaktCorruptError,
    PaktUnsupportedError,
    SignatureBlock,
)

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    _ARGON2_AVAILABLE = True
except ImportError:                                   # pragma: no cover
    Argon2id = None
    _ARGON2_AVAILABLE = False

__all__ = [
    "WrongPassword", "KEY_SIZE", "NONCE_SIZE", "TAG_SIZE", "SALT_SIZE",
    "argon2_available", "default_kdf",
    "new_salt", "new_nonce", "derive_key", "wipe",
    "encode_kdf_params", "decode_kdf_params",
    "make_crypto_header", "key_from_crypto_header",
    "index_aad", "block_aad", "seal", "open_sealed",
    "generate_signing_key", "sign_bytes", "verify_signature",
    "PBKDF2_MIN_ITERATIONS", "ARGON2_TIME_COST", "ARGON2_MEMORY_KIB",
    "ARGON2_PARALLELISM",
]


KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 16

#: Spec §5: writers MUST use at least this many PBKDF2 iterations.
PBKDF2_MIN_ITERATIONS = 600_000

#: Spec §5 recommended Argon2id parameters. 64 MiB per derivation is
#: imperceptible to a user opening one archive and expensive for an
#: attacker trying billions of candidates.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 65_536
ARGON2_PARALLELISM = 4

_INDEX_LABEL = b"pakt/1.0/index"
_BLOCK_LABEL = b"pakt/1.0/block"


class WrongPassword(PaktCorruptError):
    """
    Authentication failed while opening an encrypted region.

    Deliberately indistinguishable from tampering. GCM cannot tell a
    wrong key from altered ciphertext, and pretending otherwise would
    be a lie about what was actually verified.
    """


def argon2_available() -> bool:
    return _ARGON2_AVAILABLE


def default_kdf() -> KdfId:
    return KdfId.ARGON2ID if _ARGON2_AVAILABLE else KdfId.PBKDF2_HMAC_SHA256


# --------------------------------------------------------------------------
# Randomness
# --------------------------------------------------------------------------

def new_salt() -> bytes:
    """A fresh per-archive salt from the OS CSPRNG."""
    return os.urandom(SALT_SIZE)


def new_nonce() -> bytes:
    """
    A fresh GCM nonce from the OS CSPRNG.

    Random, never counter-derived. With 96-bit nonces the birthday
    bound makes collision negligible for any plausible archive, and a
    counter would reintroduce exactly the reuse hazard the format
    forbids REPRODUCIBLE+ENCRYPTED to avoid.
    """
    return os.urandom(NONCE_SIZE)


def wipe(buf: bytearray) -> None:
    """
    Best-effort clear of a mutable buffer.

    Honest limitation: this cannot reach copies the interpreter may
    have made. It is hygiene, not a guarantee.
    """
    for i in range(len(buf)):
        buf[i] = 0


# --------------------------------------------------------------------------
# KDF parameters -- the 16-byte kdf_params field
# --------------------------------------------------------------------------

def encode_kdf_params(kdf_id: KdfId, **kw) -> bytes:
    if kdf_id is KdfId.PBKDF2_HMAC_SHA256:
        iterations = int(kw.get("iterations", PBKDF2_MIN_ITERATIONS))
        if iterations < PBKDF2_MIN_ITERATIONS:
            raise ValueError(
                f"PBKDF2 iterations must be at least {PBKDF2_MIN_ITERATIONS}")
        return struct.pack("<I", iterations) + bytes(12)
    if kdf_id is KdfId.ARGON2ID:
        return struct.pack(
            "<III",
            int(kw.get("time_cost", ARGON2_TIME_COST)),
            int(kw.get("memory_kib", ARGON2_MEMORY_KIB)),
            int(kw.get("parallelism", ARGON2_PARALLELISM)),
        ) + bytes(4)
    raise PaktUnsupportedError(f"unknown KDF id {int(kdf_id)}")


def decode_kdf_params(kdf_id: KdfId, raw: bytes) -> dict:
    raw = raw.ljust(16, b"\x00")[:16]
    if kdf_id is KdfId.PBKDF2_HMAC_SHA256:
        (iterations,) = struct.unpack_from("<I", raw, 0)
        return {"iterations": iterations}
    if kdf_id is KdfId.ARGON2ID:
        time_cost, memory_kib, parallelism = struct.unpack_from("<III", raw, 0)
        return {"time_cost": time_cost, "memory_kib": memory_kib,
                "parallelism": parallelism}
    raise PaktUnsupportedError(f"unknown KDF id {int(kdf_id)}")


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------

def derive_key(password: str, salt: bytes, kdf_id: KdfId,
               params: dict) -> bytes:
    """Derive the 32-byte archive key from a password."""
    if not password:
        raise ValueError("password must not be empty")
    if len(salt) != SALT_SIZE:
        raise PaktCorruptError(
            f"salt must be {SALT_SIZE} bytes, got {len(salt)}")

    secret = password.encode("utf-8")

    if kdf_id is KdfId.ARGON2ID:
        if not _ARGON2_AVAILABLE:
            raise PaktUnsupportedError(
                "this archive uses Argon2id, but this build has no Argon2 "
                "support; install a cryptography release that provides it")
        kdf = Argon2id(
            salt=salt,
            length=KEY_SIZE,
            iterations=params.get("time_cost", ARGON2_TIME_COST),
            lanes=params.get("parallelism", ARGON2_PARALLELISM),
            memory_cost=params.get("memory_kib", ARGON2_MEMORY_KIB),
        )
        return kdf.derive(secret)

    if kdf_id is KdfId.PBKDF2_HMAC_SHA256:
        iterations = params.get("iterations", PBKDF2_MIN_ITERATIONS)
        if iterations < 1:
            raise PaktCorruptError("PBKDF2 iteration count is not positive")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE,
                         salt=salt, iterations=iterations)
        return kdf.derive(secret)

    raise PaktUnsupportedError(f"unknown KDF id {int(kdf_id)}")


def make_crypto_header(
    password: str,
    *,
    kdf_id: Optional[KdfId] = None,
    **params,
) -> tuple[CryptoHeader, bytes]:
    """
    Build a fresh crypto header and derive its key.

    The index nonce and tag are filled in later, once the index has
    actually been sealed.
    """
    kdf_id = kdf_id or default_kdf()
    salt = new_salt()
    encoded = encode_kdf_params(kdf_id, **params)
    key = derive_key(password, salt, kdf_id, decode_kdf_params(kdf_id, encoded))
    header = CryptoHeader(
        salt=salt, kdf_params=encoded, kdf_id=kdf_id,
        aead_id=AeadId.AES_256_GCM,
        index_nonce=bytes(NONCE_SIZE), index_tag=bytes(TAG_SIZE),
    )
    return header, key


def key_from_crypto_header(password: str, header: CryptoHeader) -> bytes:
    """Re-derive the archive key when opening."""
    if header.aead_id is not AeadId.AES_256_GCM:
        raise PaktUnsupportedError(
            f"archive uses AEAD id {int(header.aead_id)}, which this build "
            f"does not implement")
    return derive_key(password, header.salt, header.kdf_id,
                      decode_kdf_params(header.kdf_id, header.kdf_params))


# --------------------------------------------------------------------------
# Additional authenticated data -- spec §5.2
# --------------------------------------------------------------------------

def index_aad(salt: bytes) -> bytes:
    """Bind the index to this archive, and mark it as an index."""
    return _INDEX_LABEL + salt


def block_aad(salt: bytes, block_index: int) -> bytes:
    """Bind a block to this archive and to its position in the table."""
    return _BLOCK_LABEL + salt + struct.pack("<I", block_index)


# --------------------------------------------------------------------------
# Authenticated encryption
# --------------------------------------------------------------------------

def seal(key: bytes, nonce: bytes, plaintext: bytes,
         aad: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt and authenticate.

    Returns ``(ciphertext, tag)`` separately, because the format stores
    the tag in the index rather than appended to the payload. AES-GCM
    ciphertext is the same length as its plaintext, which is what lets
    an encrypted index occupy exactly the space reserved for a plain
    one.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
    combined = AESGCM(key).encrypt(nonce, plaintext, aad)
    return combined[:-TAG_SIZE], combined[-TAG_SIZE:]


def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                aad: bytes) -> bytes:
    """
    Authenticate, then decrypt.

    Spec §5.3: no plaintext is released until the tag verifies. AESGCM
    performs both in one operation and raises rather than returning
    unauthenticated output, so a failure here means nothing usable ever
    existed to leak.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise PaktCorruptError(
            f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(tag) != TAG_SIZE:
        raise PaktCorruptError(
            f"authentication tag must be {TAG_SIZE} bytes, got {len(tag)}")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag:
        raise WrongPassword(
            "authentication failed: the password is wrong, or the archive "
            "has been altered since it was written") from None


# --------------------------------------------------------------------------
# Signatures -- spec §8
# --------------------------------------------------------------------------

def generate_signing_key() -> tuple[bytes, bytes]:
    """Create an Ed25519 keypair as ``(private_seed, public_key)``."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                 NoEncryption())
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, public


def sign_bytes(private_seed: bytes, message: bytes) -> SignatureBlock:
    """Sign ``message``, returning a populated signature block."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    if len(private_seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    private = Ed25519PrivateKey.from_private_bytes(private_seed)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return SignatureBlock(public_key=public,
                          signature=private.sign(message), alg_id=0)


def verify_signature(block: SignatureBlock, message: bytes) -> None:
    """
    Verify an archive signature, raising on failure.

    A valid signature proves the archive was produced by the holder of
    that private key. It says nothing about whether the key is one the
    caller should trust — that judgement belongs to whoever is checking
    the public key against a key they already know.
    """
    if block.alg_id != 0:
        raise PaktUnsupportedError(
            f"unknown signature algorithm id {block.alg_id}")
    try:
        Ed25519PublicKey.from_public_bytes(block.public_key).verify(
            block.signature, message)
    except (InvalidSignature, ValueError):
        raise PaktCorruptError(
            "archive signature does not verify; the contents or the "
            "signature have been altered") from None
