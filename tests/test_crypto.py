"""
Tests for the .pakt crypto layer.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Two claims are load-bearing for the product and both are asserted
against real archive bytes rather than trusted:

- an encrypted archive leaks neither file contents **nor the file
  listing**, which is the concrete thing `.pakt` does that ZIP cannot;
- a wrong password and a tampered archive both fail cleanly, before any
  plaintext is produced.
"""

from __future__ import annotations

import os

import pytest

from core import crypto
from core.container import (
    HEADER_SIZE,
    Feature,
    Header,
    KdfId,
    PaktCorruptError,
    PaktFormatError,
    PaktUnsupportedError,
)
from core.crypto import WrongPassword
from core.pakt_reader import PasswordRequired, open_pakt
from core.reference_encoder import pack

SECRET = b"the quick brown fox guards the lazy secret\n" * 200
PASSWORD = "correct horse battery staple"


@pytest.fixture
def tree(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "invoice-2026.txt").write_bytes(SECRET)
    (src / "sub" / "payroll.csv").write_bytes(SECRET * 2)
    return src


# ==========================================================================
# Primitives
# ==========================================================================

def test_argon2id_is_the_default_kdf():
    """Memory-hard beats GPU-parallelisable for password protection."""
    if crypto.argon2_available():
        assert crypto.default_kdf() is KdfId.ARGON2ID


def test_key_derivation_is_deterministic_and_salted():
    salt = crypto.new_salt()
    params = {"time_cost": 1, "memory_kib": 8, "parallelism": 1}
    kdf = KdfId.PBKDF2_HMAC_SHA256
    p = {"iterations": crypto.PBKDF2_MIN_ITERATIONS}
    a = crypto.derive_key("pw", salt, kdf, p)
    b = crypto.derive_key("pw", salt, kdf, p)
    c = crypto.derive_key("pw", crypto.new_salt(), kdf, p)
    assert a == b
    assert a != c
    assert len(a) == crypto.KEY_SIZE


def test_empty_password_is_refused():
    with pytest.raises(ValueError):
        crypto.derive_key("", crypto.new_salt(), KdfId.ARGON2ID, {})


def test_pbkdf2_iteration_floor_is_enforced():
    with pytest.raises(ValueError, match="at least"):
        crypto.encode_kdf_params(KdfId.PBKDF2_HMAC_SHA256, iterations=1000)


def test_kdf_params_roundtrip():
    raw = crypto.encode_kdf_params(KdfId.ARGON2ID, time_cost=4,
                                   memory_kib=1024, parallelism=2)
    assert len(raw) == 16
    got = crypto.decode_kdf_params(KdfId.ARGON2ID, raw)
    assert got == {"time_cost": 4, "memory_kib": 1024, "parallelism": 2}


def test_nonces_are_unique():
    seen = {crypto.new_nonce() for _ in range(500)}
    assert len(seen) == 500


def test_seal_and_open_roundtrip():
    key = os.urandom(32)
    nonce = crypto.new_nonce()
    aad = crypto.block_aad(crypto.new_salt(), 7)
    ct, tag = crypto.seal(key, nonce, SECRET, aad)
    assert len(ct) == len(SECRET)          # GCM does not expand
    assert len(tag) == crypto.TAG_SIZE
    assert crypto.open_sealed(key, nonce, ct, tag, aad) == SECRET


def test_wrong_key_fails_authentication():
    key, nonce = os.urandom(32), crypto.new_nonce()
    aad = crypto.index_aad(crypto.new_salt())
    ct, tag = crypto.seal(key, nonce, SECRET, aad)
    with pytest.raises(WrongPassword):
        crypto.open_sealed(os.urandom(32), nonce, ct, tag, aad)


def test_altered_ciphertext_fails_authentication():
    key, nonce = os.urandom(32), crypto.new_nonce()
    aad = crypto.index_aad(crypto.new_salt())
    ct, tag = crypto.seal(key, nonce, SECRET, aad)
    broken = bytearray(ct)
    broken[10] ^= 0xFF
    with pytest.raises(WrongPassword):
        crypto.open_sealed(key, nonce, bytes(broken), tag, aad)


def test_aad_binds_a_block_to_its_position():
    """A block must not be movable to another slot in the table."""
    key, nonce, salt = os.urandom(32), crypto.new_nonce(), crypto.new_salt()
    ct, tag = crypto.seal(key, nonce, SECRET, crypto.block_aad(salt, 3))
    with pytest.raises(WrongPassword):
        crypto.open_sealed(key, nonce, ct, tag, crypto.block_aad(salt, 4))


def test_aad_binds_a_region_to_its_archive():
    """A block must not be transplantable into a different archive."""
    key, nonce = os.urandom(32), crypto.new_nonce()
    ct, tag = crypto.seal(key, nonce, SECRET,
                          crypto.block_aad(crypto.new_salt(), 0))
    with pytest.raises(WrongPassword):
        crypto.open_sealed(key, nonce, ct, tag,
                           crypto.block_aad(crypto.new_salt(), 0))


def test_index_and_block_labels_are_domain_separated():
    """An index must never be accepted as a block, or the reverse."""
    key, nonce, salt = os.urandom(32), crypto.new_nonce(), crypto.new_salt()
    ct, tag = crypto.seal(key, nonce, SECRET, crypto.index_aad(salt))
    with pytest.raises(WrongPassword):
        crypto.open_sealed(key, nonce, ct, tag, crypto.block_aad(salt, 0))


# ==========================================================================
# Encrypted archives
# ==========================================================================

def test_encrypted_archive_leaks_neither_content_nor_filenames(tmp_path, tree):
    """
    The concrete advantage over ZIP. WinZip AES encrypts file contents
    but leaves the central directory in the clear, so every filename,
    path, size and timestamp is readable without the password. `.pakt`
    encrypts the index itself.
    """
    arc = str(tmp_path / "secret.pakt")
    pack([str(tree)], arc, password=PASSWORD)
    raw = open(arc, "rb").read()

    assert SECRET[:64] not in raw
    assert b"invoice-2026" not in raw
    assert b"payroll" not in raw
    assert b".csv" not in raw


def test_encrypted_flag_is_recorded(tmp_path, tree):
    arc = str(tmp_path / "e.pakt")
    pack([str(tree)], arc, password=PASSWORD)
    header = Header.unpack(open(arc, "rb").read(HEADER_SIZE))
    assert header.feature_flags & Feature.ENCRYPTED


def test_encrypted_roundtrip(tmp_path, tree):
    arc = str(tmp_path / "e.pakt")
    pack([str(tree)], arc, password=PASSWORD)
    dest = tmp_path / "out"
    with open_pakt(arc, password=PASSWORD) as a:
        a.extract_all(dest)
    assert (dest / "src" / "invoice-2026.txt").read_bytes() == SECRET
    assert (dest / "src" / "sub" / "payroll.csv").read_bytes() == SECRET * 2


def test_listing_requires_the_password(tmp_path, tree):
    """Even the file listing is unavailable without the key."""
    arc = str(tmp_path / "e.pakt")
    pack([str(tree)], arc, password=PASSWORD)
    with pytest.raises(PasswordRequired):
        open_pakt(arc)


def test_wrong_password_says_so(tmp_path, tree):
    """
    Regression guard. This once reported "both index copies are
    unreadable", which tells a user their archive is corrupt when they
    simply mistyped.
    """
    arc = str(tmp_path / "e.pakt")
    pack([str(tree)], arc, password=PASSWORD)
    with pytest.raises(WrongPassword):
        open_pakt(arc, password="not the password")


def test_tampered_encrypted_block_is_caught(tmp_path, tree):
    arc = str(tmp_path / "e.pakt")
    pack([str(tree)], arc, password=PASSWORD)
    raw = bytearray(open(arc, "rb").read())
    header = Header.unpack(bytes(raw[:HEADER_SIZE]))
    raw[header.index_a_offset + header.index_a_length + 8] ^= 0xFF
    open(arc, "wb").write(bytes(raw))

    with open_pakt(arc, password=PASSWORD) as a:
        with pytest.raises(PaktCorruptError):
            for entry in a.entries:
                a.read(entry)


def test_encrypted_and_reproducible_is_refused_at_write(tmp_path, tree):
    """Spec §4.3: the combination would require a reused GCM nonce."""
    with pytest.raises(PaktFormatError, match="nonce"):
        pack([str(tree)], str(tmp_path / "x.pakt"),
             password=PASSWORD, reproducible=True)


def test_each_archive_uses_a_fresh_salt(tmp_path, tree):
    """Two archives of the same data under the same password differ."""
    a = str(tmp_path / "a.pakt")
    b = str(tmp_path / "b.pakt")
    pack([str(tree)], a, password=PASSWORD)
    pack([str(tree)], b, password=PASSWORD)
    assert open(a, "rb").read() != open(b, "rb").read()


# ==========================================================================
# Signatures
# ==========================================================================

def test_signature_verifies_and_names_the_signer(tmp_path, tree):
    seed, public = crypto.generate_signing_key()
    arc = str(tmp_path / "signed.pakt")
    pack([str(tree)], arc, sign_key=seed)
    with open_pakt(arc) as a:
        assert a.verify_signature() == public


def test_signed_flag_is_recorded(tmp_path, tree):
    seed, _ = crypto.generate_signing_key()
    arc = str(tmp_path / "s.pakt")
    pack([str(tree)], arc, sign_key=seed)
    header = Header.unpack(open(arc, "rb").read(HEADER_SIZE))
    assert header.feature_flags & Feature.SIGNED


def test_unsigned_archive_reports_no_signature(tmp_path, tree):
    arc = str(tmp_path / "plain.pakt")
    pack([str(tree)], arc)
    with open_pakt(arc) as a:
        with pytest.raises(PaktFormatError, match="no signature"):
            a.verify_signature()


def test_tampered_index_breaks_the_signature(tmp_path, tree):
    seed, _ = crypto.generate_signing_key()
    arc = str(tmp_path / "s.pakt")
    pack([str(tree)], arc, sign_key=seed)

    raw = bytearray(open(arc, "rb").read())
    header = Header.unpack(bytes(raw[:HEADER_SIZE]))
    raw[header.index_b_offset + 30] ^= 0xFF
    open(arc, "wb").write(bytes(raw))

    with open_pakt(arc) as a:
        with pytest.raises(PaktCorruptError):
            a.verify_signature(deep=False)


def test_shallow_verification_cannot_see_block_tampering(tmp_path, tree):
    """
    Documents a real limit rather than asserting a capability.

    The signature covers the header and the index, not the block data.
    Content authenticity comes from a chain: the signature authenticates
    the index, and the index carries a SHA-256 per entry. Only a deep
    verification walks that chain, which is why deep is the default.
    """
    seed, _ = crypto.generate_signing_key()
    arc = str(tmp_path / "s.pakt")
    pack([str(tree)], arc, sign_key=seed)

    raw = bytearray(open(arc, "rb").read())
    header = Header.unpack(bytes(raw[:HEADER_SIZE]))
    raw[header.index_a_offset + header.index_a_length + 5] ^= 0xFF
    open(arc, "wb").write(bytes(raw))

    with open_pakt(arc) as a:
        a.verify_signature(deep=False)                # signature alone: fine
        with pytest.raises(PaktCorruptError):
            a.verify_signature(deep=True)             # chain: caught


def test_deep_verification_is_the_default(tmp_path, tree):
    seed, _ = crypto.generate_signing_key()
    arc = str(tmp_path / "s.pakt")
    pack([str(tree)], arc, sign_key=seed)

    raw = bytearray(open(arc, "rb").read())
    header = Header.unpack(bytes(raw[:HEADER_SIZE]))
    raw[header.index_a_offset + header.index_a_length + 5] ^= 0xFF
    open(arc, "wb").write(bytes(raw))

    with open_pakt(arc) as a:
        with pytest.raises(PaktCorruptError):
            a.verify_signature()


def test_a_different_key_does_not_verify(tmp_path, tree):
    seed, _ = crypto.generate_signing_key()
    other_seed, other_public = crypto.generate_signing_key()
    arc = str(tmp_path / "s.pakt")
    pack([str(tree)], arc, sign_key=seed)
    with open_pakt(arc) as a:
        assert a.verify_signature() != other_public


# ==========================================================================
# Both at once
# ==========================================================================

def test_encrypted_and_signed_together(tmp_path, tree):
    seed, public = crypto.generate_signing_key()
    arc = str(tmp_path / "both.pakt")
    pack([str(tree)], arc, password=PASSWORD, sign_key=seed)

    header = Header.unpack(open(arc, "rb").read(HEADER_SIZE))
    assert header.feature_flags & Feature.ENCRYPTED
    assert header.feature_flags & Feature.SIGNED

    with open_pakt(arc, password=PASSWORD) as a:
        assert a.verify_signature() == public
        dest = tmp_path / "out"
        a.extract_all(dest)
        assert (dest / "src" / "invoice-2026.txt").read_bytes() == SECRET
