"""
Tests for the `pakt` command line interface.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

The CLI is the artifact the project's launch channels actually want, so
the things that matter are the ones a script depends on: specific exit
codes, parseable output, and passwords that do not end up in the
process list.
"""

from __future__ import annotations

import json
import os

import pytest

from cli.main import Exit, main

PAYLOAD = b"command line payload\n" * 300


@pytest.fixture
def project(tmp_path):
    src = tmp_path / "proj"
    (src / "src").mkdir(parents=True)
    (src / "README.md").write_bytes(b"# Project\n" * 200)
    (src / "src" / "app.py").write_bytes(b"def f():\n    return 1\n" * 100)
    (src / "data.csv").write_bytes(
        b"id,v\n" + b"".join(f"{i},{i * 3}\n".encode() for i in range(1500)))
    (src / "blob.bin").write_bytes(os.urandom(15000))
    return src


def run(*argv) -> int:
    return main([str(a) for a in argv])


def read_json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


# ==========================================================================
# Round-trip
# ==========================================================================

def test_create_list_extract(tmp_path, project, capsys):
    arc = tmp_path / "p.pakt"
    assert run("c", project, "-o", arc) == Exit.OK
    assert arc.exists()

    assert run("l", arc) == Exit.OK
    assert "README.md" in capsys.readouterr().out

    dest = tmp_path / "out"
    assert run("x", arc, "-d", dest) == Exit.OK
    assert (dest / "proj" / "README.md").read_bytes() == b"# Project\n" * 200
    assert (dest / "proj" / "src" / "app.py").exists()


def test_create_is_smaller_than_the_input(tmp_path, project, capsys):
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "--json")
    data = read_json(capsys)
    assert data["archive_bytes"] < data["input_bytes"]
    assert data["ratio"] < 1.0


@pytest.mark.parametrize("level", ["fast", "auto"])
def test_every_level_round_trips(tmp_path, project, level):
    arc = tmp_path / f"{level}.pakt"
    assert run("c", project, "-o", arc, "--level", level) == Exit.OK
    assert run("x", arc, "-d", tmp_path / level) == Exit.OK
    assert (tmp_path / level / "proj" / "README.md").exists()


def test_the_fast_shorthand_means_the_fast_level(tmp_path, project):
    """`--fast` is a second spelling of `--level fast`, so prove it packs
    the same bytes rather than merely being accepted."""
    a, b = tmp_path / "a.pakt", tmp_path / "b.pakt"
    assert run("c", project, "-o", a, "--fast", "--reproducible") == Exit.OK
    assert run("c", project, "-o", b, "--level", "fast",
               "--reproducible") == Exit.OK
    assert a.read_bytes() == b.read_bytes()


def test_a_withdrawn_level_is_refused_not_silently_remapped(tmp_path, project):
    """There were once `balanced` and `maximum`. A script still asking for
    one must fail loudly: quietly giving it something else would be worse
    than not accepting it at all."""
    for gone in ("balanced", "maximum"):
        # argparse rejects an unknown choice by exiting, not by returning,
        # which is the loudest available failure and the right one here.
        with pytest.raises(SystemExit) as exc:
            run("c", project, "-o", tmp_path / f"{gone}.pakt",
                "--level", gone)
        assert exc.value.code != 0


def test_reproducible_output_is_stable(tmp_path, project):
    a, b = tmp_path / "a.pakt", tmp_path / "b.pakt"
    run("c", project, "-o", a, "--reproducible", "-q")
    run("c", project, "-o", b, "--reproducible", "-q")
    assert a.read_bytes() == b.read_bytes()


# ==========================================================================
# Machine-readable output
# ==========================================================================

def test_json_on_create(tmp_path, project, capsys):
    run("c", project, "-o", tmp_path / "p.pakt", "--json")
    data = read_json(capsys)
    assert data["entries"] > 0
    assert data["encrypted"] is False
    assert data["signed"] is False


def test_json_on_list(tmp_path, project, capsys):
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "-q")
    run("l", arc, "--json")
    data = read_json(capsys)
    assert data["format"] == "pakt"
    assert any(e["path"].endswith("README.md") for e in data["entries"])


def test_json_on_formats(capsys):
    run("formats", "--json")
    data = read_json(capsys)
    assert data["pack"] == [".pakt"]
    assert ".zip" in data["tier1"]
    assert "ZSTD" in data["codecs"]


def test_json_error_is_parseable(tmp_path, capsys):
    """A script running with --json must be able to parse failures too."""
    bad = tmp_path / "x.doc"
    bad.write_bytes(b"not an archive")
    assert run("l", bad, "--json") == Exit.UNSUPPORTED
    data = read_json(capsys)
    assert data["ok"] is False
    assert data["error"] == "unsupported"


def test_quiet_prints_nothing_on_success(tmp_path, project, capsys):
    run("c", project, "-o", tmp_path / "p.pakt", "-q")
    assert capsys.readouterr().out.strip() == ""


# ==========================================================================
# Exit codes -- the part scripts depend on
# ==========================================================================

def test_unsupported_file(tmp_path):
    bad = tmp_path / "notes.doc"
    bad.write_bytes(b"definitely not an archive")
    assert run("l", bad) == Exit.UNSUPPORTED


def test_missing_file(tmp_path):
    assert run("l", tmp_path / "absent.pakt") == Exit.UNSUPPORTED


def test_password_required(tmp_path, project, monkeypatch):
    arc = tmp_path / "e.pakt"
    monkeypatch.setenv("PW", "s3cret")
    run("c", project, "-o", arc, "--password-env", "PW", "-q")
    assert run("l", arc) == Exit.WRONG_PASSWORD


def test_wrong_password_is_distinguished(tmp_path, project, monkeypatch,
                                         capsys):
    """
    Regression guard. This reported "supply a password" even when one
    had been supplied, because the .pakt handler was not forwarding it.
    """
    arc = tmp_path / "e.pakt"
    monkeypatch.setenv("PW", "s3cret")
    run("c", project, "-o", arc, "--password-env", "PW", "-q")
    capsys.readouterr()

    monkeypatch.setenv("PW", "not-the-password")
    assert run("l", arc, "--password-env", "PW") == Exit.WRONG_PASSWORD
    assert "wrong password" in capsys.readouterr().err


def test_encrypted_and_reproducible_is_refused(tmp_path, project, monkeypatch):
    monkeypatch.setenv("PW", "s3cret")
    code = run("c", project, "-o", tmp_path / "x.pakt",
               "--password-env", "PW", "--reproducible")
    assert code != Exit.OK


def test_extraction_size_cap_is_refused(tmp_path, project):
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "-q")
    assert run("x", arc, "-d", tmp_path / "out", "--max-size", 10) == Exit.REFUSED


def test_corrupt_archive_is_reported_as_corrupt(tmp_path, project):
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "-q")
    raw = bytearray(arc.read_bytes())
    from core.container import HEADER_SIZE, Header
    header = Header.unpack(bytes(raw[:HEADER_SIZE]))
    raw[header.index_a_offset + header.index_a_length + 4] ^= 0xFF
    arc.write_bytes(bytes(raw))
    assert run("verify", arc) == Exit.CORRUPT


# ==========================================================================
# Encryption and signing
# ==========================================================================

def test_encrypted_round_trip(tmp_path, project, monkeypatch):
    arc = tmp_path / "e.pakt"
    monkeypatch.setenv("PW", "s3cret")
    assert run("c", project, "-o", arc, "--password-env", "PW", "-q") == Exit.OK
    assert run("x", arc, "-d", tmp_path / "out",
               "--password-env", "PW", "-q") == Exit.OK
    assert (tmp_path / "out" / "proj" / "README.md").exists()


def test_password_file_is_accepted(tmp_path, project):
    pw = tmp_path / "pw.txt"
    pw.write_text("from-a-file\n", encoding="utf-8")
    arc = tmp_path / "e.pakt"
    assert run("c", project, "-o", arc, "--password-file", pw, "-q") == Exit.OK
    assert run("l", arc, "--password-file", pw, "-q") == Exit.OK


def test_literal_password_warns_about_argv(tmp_path, project, capsys):
    """argv is world-readable, so this path must say so."""
    run("c", project, "-o", tmp_path / "e.pakt", "-p", "on-the-command-line")
    assert "visible to other processes" in capsys.readouterr().err


def test_keygen_writes_a_key(tmp_path, capsys):
    out = tmp_path / "key.hex"
    assert run("keygen", "-o", out, "--json") == Exit.OK
    data = read_json(capsys)
    assert len(bytes.fromhex(data["public_key"])) == 32
    assert len(bytes.fromhex(out.read_text().strip())) == 32


def test_sign_and_verify(tmp_path, project, capsys):
    arc = tmp_path / "s.pakt"
    key = tmp_path / "key.hex"
    assert run("c", project, "-o", arc, "--sign", "--key-out", key,
               "--json") == Exit.OK
    public = read_json(capsys)["public_key"]

    assert run("verify", arc, "--json") == Exit.OK
    data = read_json(capsys)
    assert data["signed"] is True
    assert data["public_key"] == public


def test_verify_rejects_an_unexpected_signer(tmp_path, project):
    arc = tmp_path / "s.pakt"
    run("c", project, "-o", arc, "--sign", "-q")
    assert run("verify", arc, "--expect-key", "00" * 32) == Exit.CORRUPT


def test_signing_with_an_existing_key_is_reproducible(tmp_path, project,
                                                      capsys):
    key = tmp_path / "key.hex"
    run("keygen", "-o", key, "--json")
    public = read_json(capsys)["public_key"]

    run("c", project, "-o", tmp_path / "a.pakt", "--sign", "--key", key,
        "--json")
    assert read_json(capsys)["public_key"] == public


def test_unsigned_archive_still_verifies_its_hashes(tmp_path, project, capsys):
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "-q")
    assert run("verify", arc, "--json") == Exit.OK
    data = read_json(capsys)
    assert data["signed"] is False
    assert data["verified"] is True


# ==========================================================================
# Reporting
# ==========================================================================

def test_explain_reports_codec_and_reason(tmp_path, project, capsys):
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "-q")
    assert run("explain", arc, "--json") == Exit.OK
    data = read_json(capsys)
    entries = {e["path"]: e for e in data["entries"]}
    assert entries["proj/README.md"]["routing_class"] == "REPETITIVE_TEXT"
    assert entries["proj/blob.bin"]["codec"] == "STORE"


def test_explain_columns_do_not_collide(tmp_path, project, capsys):
    """MAXIMUM_ENTROPY_BINARY is 22 characters and once ran into CODEC."""
    arc = tmp_path / "p.pakt"
    run("c", project, "-o", arc, "-q")
    run("explain", arc)
    text = capsys.readouterr().out
    assert "MAXIMUM_ENTROPY_BINARYSTORE" not in text
    assert "MAXIMUM_ENTROPY_BINARY" in text


def test_formats_lists_real_extensions(capsys):
    """Internal names are not extensions; printing 'brotli' is a lie."""
    run("formats")
    text = capsys.readouterr().out
    assert ".br" in text and ".zst" in text and ".gz" in text
    assert ".brotli" not in text and ".zstd" not in text


def test_formats_names_the_missing_tier2_library(capsys):
    from core.decompressor import _libarchive
    run("formats")
    text = capsys.readouterr().out
    if _libarchive() is None:
        assert "libarchive" in text
        assert ".rar" in text


# ==========================================================================
# Cross-format
# ==========================================================================

def test_cli_extracts_a_zip(tmp_path):
    import zipfile
    z = tmp_path / "t.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", PAYLOAD)
        zf.writestr("dir/b.txt", PAYLOAD * 2)
    assert run("x", z, "-d", tmp_path / "out") == Exit.OK
    assert (tmp_path / "out" / "a.txt").read_bytes() == PAYLOAD


def test_cli_refuses_a_hostile_zip(tmp_path):
    import zipfile
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escaped.txt", b"pwned")
    assert run("x", z, "-d", tmp_path / "out") == Exit.REFUSED
    assert not (tmp_path / "escaped.txt").exists()
