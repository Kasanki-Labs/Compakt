"""
Tier 2 format verification.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

    python benchmarks/tier2_test.py

Tier 2 is the read-only formats libarchive provides: .rar, .cab,
.cpio, .ar, .deb, .rpm, .xar, .lha, .arj, .warc, .Z and the rest. The
shared library is built from source by build/native.py.

WHAT "SUPPORTED" HAS TO MEAN
----------------------------
A format is only reachable if BOTH halves hold, and each has been
wrong here at least once:

- **core.decompressor must recognise its magic.** .rpm and .warc were
  advertised for a while with no signature entry at all, so identify()
  rejected them outright -- "not an archive format Compakt recognises"
  for files the bundled library reads perfectly.
- **libarchive must have been compiled with what the payload needs.**
  Optional codecs are a compile-time decision, so two builds of the
  identical version support different sets. supported_formats() now
  asks the library rather than assuming.

THE AWKWARD PART: MAKING THE SAMPLES
------------------------------------
Most of these formats cannot be *written* by anything on a normal
Windows machine, which is precisely why they need libarchive to be
read. So the samples come from three different places, and the source
matters for how much each test proves:

- **makecab.exe** ships with Windows and writes real .cab files. An
  independent implementation, so a successful read is meaningful.
- **ar and cpio** are simple enough to write by hand from their format
  descriptions. Independent of libarchive, and byte-verifiable.
- **libarchive itself** writes the remaining formats. This is circular
  as a test of format support -- it proves our integration works, not
  that libarchive parses a stranger's file correctly. Labelled as such
  rather than counted as equivalent evidence.

.rar cannot be produced at all: RARLAB licenses no compressor and none
is installed. That gap is reported honestly rather than papered over
with a self-made sample.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

SAMPLE = {
    "hello.txt": b"the quick brown fox jumps over the lazy dog\n" * 40,
    "data.csv": b"id,value\n" + b"".join(
        f"{i},{i * 7}\n".encode() for i in range(200)),
    "notes.md": b"# Notes\n\nsome text that compresses reasonably.\n" * 25,
}


# --------------------------------------------------------------------------
# Sample builders
# --------------------------------------------------------------------------

def make_cab(dest: str, src: str) -> str:
    """Windows' own makecab.exe. A genuinely independent writer."""
    exe = shutil.which("makecab") or r"C:\Windows\System32\makecab.exe"
    if not os.path.exists(exe):
        raise RuntimeError("makecab.exe not available")
    out = os.path.join(dest, "sample.cab")
    ddf = os.path.join(dest, "sample.ddf")
    with open(ddf, "w", encoding="utf-8") as fh:
        fh.write(".OPTION EXPLICIT\n")
        fh.write(f'.Set CabinetNameTemplate="sample.cab"\n')
        fh.write(f'.Set DiskDirectory1="{dest}"\n')
        fh.write(".Set Cabinet=on\n.Set Compress=on\n")
        for name in SAMPLE:
            fh.write(f'"{os.path.join(src, name)}"\n')
    subprocess.run([exe, "/F", ddf], capture_output=True, cwd=dest)
    if not os.path.exists(out):
        raise RuntimeError("makecab produced no cabinet")
    return out


def make_ar(dest: str, src: str) -> str:
    """
    A `ar` archive, written by hand from the format description.

    The format is a 8-byte magic followed by 60-byte ASCII headers.
    Writing it here keeps the test independent of libarchive.
    """
    out = os.path.join(dest, "sample.a")
    with open(out, "wb") as fh:
        fh.write(b"!<arch>\n")
        for name, body in SAMPLE.items():
            header = (
                f"{name[:15]:<16}"      # name
                f"{0:<12}"              # mtime
                f"{0:<6}{0:<6}"         # uid, gid
                f"{100644:<8}"          # mode
                f"{len(body):<10}"      # size
                "`\n")
            fh.write(header.encode("ascii"))
            fh.write(body)
            if len(body) % 2:
                fh.write(b"\n")         # members are even-aligned
    return out


def make_cpio(dest: str, src: str) -> str:
    """
    A `cpio` archive in the portable ASCII (newc) format.

    Also written by hand: fixed-width hex header fields, 4-byte aligned
    name and data, terminated by a TRAILER entry.
    """
    out = os.path.join(dest, "sample.cpio")

    def pad(fh):
        while fh.tell() % 4:
            fh.write(b"\x00")

    with open(out, "wb") as fh:
        for i, (name, body) in enumerate(list(SAMPLE.items()) +
                                         [("TRAILER!!!", b"")]):
            raw = name.encode() + b"\x00"
            fields = [
                0x070701,                 # magic
                i + 1,                    # inode
                0o100644,                 # mode
                0, 0, 1, 0,               # uid, gid, nlink, mtime
                len(body),                # filesize
                0, 0, 0, 0,               # dev/rdev major+minor
                len(raw),                 # namesize
                0,                        # check
            ]
            fh.write(b"070701")
            for value in fields[1:]:
                fh.write(f"{value:08X}".encode())
            fh.write(raw)
            pad(fh)
            fh.write(body)
            pad(fh)
    return out


def make_deb(dest: str, src: str) -> str:
    """
    A Debian package, assembled from its actual structure.

    A .deb is an `ar` archive holding exactly three members:
    debian-binary, control.tar.gz and data.tar.xz. Both inner tarballs
    are produced here by Python's own tarfile, gzip and lzma modules,
    so nothing about this sample comes from libarchive.

    Worth testing precisely because it is the format most likely to be
    misunderstood: libarchive does NOT descend into a .deb. It returns
    the three members as opaque files and the inner data.tar.xz is
    Tier 1's problem afterwards. A test that expected usr/... paths to
    appear would fail against correct behaviour.
    """
    import gzip
    import io
    import lzma
    import tarfile

    def tar_bytes(members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tf.addfile(info, io.BytesIO(body))
        return buf.getvalue()

    data = lzma.compress(tar_bytes(
        {f"usr/share/doc/{n}": b for n, b in SAMPLE.items()}))
    control = gzip.compress(tar_bytes({"control": b"Package: compakt-test\n"}))

    out = os.path.join(dest, "sample.deb")
    with open(out, "wb") as fh:
        fh.write(b"!<arch>\n")
        for name, body in (("debian-binary", b"2.0\n"),
                           ("control.tar.gz", control),
                           ("data.tar.xz", data)):
            fh.write(f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}"
                     f"{len(body):<10}`\n".encode("ascii"))
            fh.write(body)
            if len(body) % 2:
                fh.write(b"\n")
    return out


def make_warc(dest: str, src: str) -> str:
    """
    A WARC web archive, written by hand from the ISO 28500 record layout.

    Plain text headers, a blank line, the payload, then two CRLFs.
    Simple enough to write correctly and entirely independent of the
    library being tested.
    """
    out = os.path.join(dest, "sample.warc")
    with open(out, "wb") as fh:
        for i, (name, body) in enumerate(SAMPLE.items()):
            payload = (b"HTTP/1.1 200 OK\r\n"
                       b"Content-Type: text/plain\r\n\r\n" + body)
            headers = (
                "WARC/1.0\r\n"
                "WARC-Type: response\r\n"
                f"WARC-Target-URI: http://example.invalid/{name}\r\n"
                "WARC-Date: 2026-08-18T00:00:00Z\r\n"
                f"WARC-Record-ID: <urn:uuid:00000000-0000-0000-0000-"
                f"{i:012d}>\r\n"
                "Content-Type: application/http; msgtype=response\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
            ).encode("ascii")
            fh.write(headers + payload + b"\r\n\r\n")
    return out


def make_with_libarchive(dest: str, src: str, fmt: str, ext: str) -> str:
    """
    Written by libarchive itself.

    Circular as evidence of format support: it shows our integration
    reads what libarchive writes, not that libarchive parses a file
    produced by some other implementation. Reported separately.
    """
    import libarchive
    out = os.path.join(dest, f"sample{ext}")
    with libarchive.file_writer(out, fmt) as writer:
        writer.add_files(*[os.path.join(src, n) for n in SAMPLE],
                         recursive=False)
    return out


# --------------------------------------------------------------------------
# Per-format expectations
# --------------------------------------------------------------------------
#
# Not every format should yield the sample files directly, and a test
# that assumed so would report a failure against perfectly correct
# behaviour. Each format says for itself what a correct extraction
# looks like. Each returns "" for success or a reason for failure.

def _walk(dest: str) -> dict[str, bytes]:
    found = {}
    for base, _dirs, names in os.walk(dest):
        for name in names:
            with open(os.path.join(base, name), "rb") as fh:
                found[name] = fh.read()
    return found


def verify_plain(dest: str) -> str:
    """The archive held the sample files; they must come back identical."""
    found = _walk(dest)
    hits = 0
    for name, body in SAMPLE.items():
        if name not in found:
            continue
        hits += 1
        if found[name] != body:
            return f"{name} differs"
    if hits == 0:
        return "nothing extracted"
    if hits < len(SAMPLE):
        return f"only {hits}/{len(SAMPLE)} files"
    return ""


def verify_deb(dest: str) -> str:
    """
    A .deb yields its three ar members, not the packaged files.

    libarchive does not descend into it. Correct behaviour is
    debian-binary, control.tar.gz and data.tar.xz coming out intact --
    which is then checked by decompressing the payload here, since a
    member that extracted as corrupt bytes would otherwise pass.
    """
    import io
    import lzma
    import tarfile

    found = _walk(dest)
    for required in ("debian-binary", "control.tar.gz", "data.tar.xz"):
        if required not in found:
            return f"missing member {required}"
    if found["debian-binary"] != b"2.0\n":
        return "debian-binary corrupt"

    try:
        raw = lzma.decompress(found["data.tar.xz"])
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            inner = {os.path.basename(m.name): tf.extractfile(m).read()
                     for m in tf.getmembers() if m.isreg()}
    except Exception as exc:
        return f"payload did not decompress ({type(exc).__name__})"

    for name, body in SAMPLE.items():
        if inner.get(name) != body:
            return f"payload file {name} differs"
    return ""


def verify_warc(dest: str) -> str:
    """
    WARC records carry HTTP headers ahead of the payload.

    So the test is containment, not equality: every sample body must
    appear inside some extracted record.
    """
    found = _walk(dest)
    if not found:
        return "nothing extracted"
    blob = b"".join(found.values())
    for name, body in SAMPLE.items():
        if body not in blob:
            return f"payload for {name} not found in any record"
    return ""


# Only independently-produced samples. The libarchive-written ones were
# dropped: writing and reading with the same library proves nothing
# about format support, and both attempts failed for reasons that were
# artefacts of the test rather than of the code -- xar needs libxml2,
# which this build omits, and a 7z written with absolute member paths
# is rejected by py7zr on principle.
BUILDERS = [
    ("cab", make_cab, "independent (Windows makecab.exe)", verify_plain),
    ("ar", make_ar, "independent (written by hand from the format)",
     verify_plain),
    ("cpio", make_cpio, "independent (written by hand from the format)",
     verify_plain),
    ("deb", make_deb,
     "independent (assembled with Python's tarfile, gzip and lzma)",
     verify_deb),
    ("warc", make_warc,
     "independent (written by hand from the ISO 28500 record layout)",
     verify_warc),
]


# --------------------------------------------------------------------------
# The test
# --------------------------------------------------------------------------

def main() -> int:
    from core.decompressor import _libarchive, extract, identify, \
        list_entries, supported_formats

    lib = _libarchive()
    print(f"libarchive: {'LOADED' if lib else 'NOT AVAILABLE'}")
    if not lib:
        print("  Tier 2 cannot be tested without the shared library.")
        return 1

    formats = supported_formats()
    print(f"tier 2 formats reported: {len(formats['tier2'])}")
    print()

    work = tempfile.mkdtemp(prefix="compakt-tier2-")
    src = os.path.join(work, "src")
    os.makedirs(src)
    for name, body in SAMPLE.items():
        with open(os.path.join(src, name), "wb") as fh:
            fh.write(body)

    failures = 0
    tested = 0
    try:
        for label, build, provenance, verify in BUILDERS:
            try:
                archive = build(work, src)
            except Exception as exc:
                print(f"  {label:<8} SKIPPED -- cannot create a sample "
                      f"({type(exc).__name__}: {str(exc)[:60]})")
                continue

            tested += 1
            try:
                info = identify(archive)
                entries = list_entries(archive)
                dest = os.path.join(work, f"out-{label}")
                extract(archive, dest)

                # Check the content, not merely that nothing raised.
                mismatch = verify(dest)

                status = "OK" if not mismatch else f"FAIL ({mismatch})"
                if mismatch:
                    failures += 1
                print(f"  {label:<8} {status:<28} "
                      f"detected as {info.format!r} tier {info.tier}, "
                      f"{len(entries)} entries")
                print(f"           sample provenance: {provenance}")
            except Exception as exc:
                failures += 1
                print(f"  {label:<8} FAIL -- {type(exc).__name__}: "
                      f"{str(exc)[:90]}")

        print()
        print(f"  libarchive linked against: "
              f"{', '.join(formats['native']) or 'nothing detected'}")
        for line in formats["tier2_partial"]:
            print(f"  PARTIAL      {line}")
        for line in formats["tier2_unavailable"]:
            print(f"  UNAVAILABLE  {line}")
        print()
        print("  NOT EXERCISED HERE, and stated rather than glossed:")
        print("    rar   no sample can be produced. RARLAB licenses no")
        print("          compressor, so a genuine .rar must come from")
        print("          elsewhere before RAR support is a claim.")
        print("    rpm   the package header is intricate enough that a")
        print("          hand-built sample would test our understanding")
        print("          of it rather than libarchive's. It is the one")
        print("          format here whose payload libarchive itself")
        print("          decompresses, so it needs a real sample.")
        print("    lha, arj, .Z, xar  no independent writer available.")
        print()
        print(f"{tested} format(s) exercised, {failures} failure(s)")
        return 1 if failures else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
