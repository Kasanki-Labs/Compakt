"""
Large-scale integrity test.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

    python benchmarks/scale_test.py --size 2

Unit tests exercise every code path on small inputs. This exercises the
paths that only appear at size, where the arithmetic that works on a
kilobyte can still be wrong on a gigabyte:

- **Multi-block files.** Anything over the 64 MiB cap spans consecutive
  blocks. That rule was added to the specification during
  implementation and had never been run against a real file.
- **Encryption at volume.** A separate GCM nonce and tag per block, and
  a key derived once. Hundreds of blocks means hundreds of nonces, and
  a nonce collision or an off-by-one in block indexing would corrupt
  data rather than raise.
- **Memory behaviour.** The reader is supposed to bound its allocation
  from the block table. A gigabyte-scale archive is where a mistake
  there stops being theoretical.

Every file is compared byte for byte on the way out. A test that only
checks extraction did not raise is not an integrity test.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

PASSWORD = "a long benchmark passphrase, chosen so the KDF does real work"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def build(root: str, target_bytes: int) -> dict[str, str]:
    """
    Build a corpus of the given size and return path -> sha256.

    Deliberately mixed: one file far larger than the block cap, many
    medium files, and a long tail of small ones. Each shape stresses a
    different part of the writer.
    """
    rng = random.Random(20260818)
    digests: dict[str, str] = {}
    written = 0

    def emit(rel: str, payload: bytes) -> None:
        nonlocal written
        full = os.path.join(root, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(payload)
        digests[rel] = hashlib.sha256(payload).hexdigest()
        written += len(payload)

    # One file well past the 64 MiB block cap, so it must span blocks.
    unit = ("the quick brown fox jumps over the lazy dog. "
            "compakt multi-block integrity probe. ").encode()
    big = (unit * ((200 * 1024 * 1024) // len(unit) + 1))[:200 * 1024 * 1024]
    emit("large/spanning.dat", big)

    # Medium files until the target is met.
    i = 0
    while written < target_bytes * 0.75:
        body = bytearray()
        while len(body) < 4 * 1024 * 1024:
            body += (f"record {i} {rng.randint(0, 10**9)} "
                     f"{'payload ' * rng.randint(1, 6)}\n").encode()
        emit(f"medium/chunk-{i:04d}.log", bytes(body))
        i += 1

    # A tail of small files, plus genuinely incompressible blobs so the
    # store-only path is exercised at size too.
    for j in range(3000):
        emit(f"small/item-{j:05d}.json",
             (f'{{"id": {j}, "v": "{rng.getrandbits(48):012x}"}}\n'
              ).encode() * rng.randint(1, 8))
    for j in range(24):
        emit(f"blobs/noise-{j:02d}.bin", rng.randbytes(2 * 1024 * 1024))

    return digests


def verify(root: str, digests: dict[str, str]) -> list[str]:
    problems = []
    for rel, expected in digests.items():
        full = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(full):
            problems.append(f"missing: {rel}")
            continue
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            while chunk := fh.read(1 << 20):
                h.update(chunk)
        if h.hexdigest() != expected:
            problems.append(f"content differs: {rel}")
    return problems


def run(size_gb: float, keep: bool) -> int:
    work = tempfile.mkdtemp(prefix="compakt-scale-")
    src = os.path.join(work, "corpus")
    os.makedirs(src)
    failures = 0

    try:
        print(f"building ~{size_gb} GB corpus ...")
        start = time.perf_counter()
        digests = build(src, int(size_gb * 1024 ** 3))
        total = sum(os.path.getsize(os.path.join(b, f))
                    for b, _d, fs in os.walk(src) for f in fs)
        print(f"  {len(digests):,} files, {human(total)} "
              f"in {time.perf_counter() - start:.0f}s")

        from core.compressor import EngineOptions, pack
        from core.crypto import generate_signing_key
        from core.pakt_reader import open_pakt
        from core.safety import ExtractLimits

        seed, public = generate_signing_key()
        cases = [
            ("plain", EngineOptions(workers=8)),
            ("encrypted", EngineOptions(workers=8, password=PASSWORD)),
            ("encrypted+signed",
             EngineOptions(workers=8, password=PASSWORD, sign_key=seed)),
        ]

        for label, options in cases:
            print(f"\n{label}")
            arc = os.path.join(work, f"{label}.pakt")

            start = time.perf_counter()
            pack([src], arc, options=options)
            pack_time = time.perf_counter() - start
            stored = os.path.getsize(arc)
            print(f"  packed   {human(stored)}  ratio {stored / total:.4f}  "
                  f"{pack_time:.0f}s  ({human(total / pack_time)}/s)")

            # An encrypted archive must not leak names or content.
            if options.password:
                with open(arc, "rb") as fh:
                    head = fh.read(4 * 1024 * 1024)
                leaks = [n for n in (b"spanning.dat", b"chunk-0001",
                                     b"item-00001", b"noise-00")
                         if n in head]
                print(f"  leaks    {'NONE' if not leaks else leaks}")
                if leaks:
                    failures += 1

            dest = os.path.join(work, f"out-{label}")
            password = PASSWORD if options.password else None
            start = time.perf_counter()
            with open_pakt(arc, password=password) as archive:
                blocks = len(archive.index.blocks)
                if options.sign_key is not None:
                    got = archive.verify_signature(deep=False)
                    print(f"  signed   {'verified' if got == public else 'MISMATCH'}")
                    if got != public:
                        failures += 1
                archive.extract_all(
                    dest, limits=ExtractLimits(max_ratio=1e12,
                                               max_total_bytes=1 << 42))
            unpack_time = time.perf_counter() - start
            print(f"  unpacked {blocks} blocks in {unpack_time:.0f}s "
                  f"({human(total / unpack_time)}/s)")

            problems = verify(os.path.join(dest, "corpus"), digests)
            if problems:
                failures += 1
                print(f"  VERIFY   {len(problems)} PROBLEM(S)")
                for p in problems[:8]:
                    print(f"             {p}")
            else:
                print(f"  verify   all {len(digests):,} files byte-identical")

            os.remove(arc)
            shutil.rmtree(dest, ignore_errors=True)

        print(f"\n{'FAILURES: ' + str(failures) if failures else 'ALL CLEAN'}")
        return 1 if failures else 0
    finally:
        if keep:
            print(f"work kept at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size", type=float, default=2.0,
                    help="approximate corpus size in GB")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    sys.exit(run(args.size, args.keep))
