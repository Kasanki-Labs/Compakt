"""
The Compakt benchmark harness.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

    python benchmarks/run.py                      # offline corpora
    python benchmarks/run.py --download           # add Silesia, enwik8
    python benchmarks/run.py --corpus jsonlogs    # just one
    python benchmarks/run.py --quick              # skip the slow settings

WHY THIS EXISTS
---------------
The top comment on every compression thread is someone running their
own benchmark. If a stranger tests against `7z -mx9` on their own data
and Compakt loses, and we had published only wins, the project's
credibility is gone in one exchange and does not come back.

So this harness reports LOSSES AS PROMINENTLY AS WINS, and the corpus
set deliberately includes cases we expect to lose -- Silesia and enwik8
are single large files, where solid blocks and deduplication have
nothing to work with.

FAIRNESS
--------
Comparisons are only meaningful if the settings match, so:

- Every compressor gets an identical thread budget. 7-Zip would
  otherwise use all sixteen cores while Compakt uses eight, and the
  timings would be meaningless.
- Compakt has two settings and both are reported: `auto`, the default,
  against `7z -mx9`, and `fast` against `7z -mx5`. There is no third
  setting to pair -- the old MAXIMUM was withdrawn after it measured
  LARGER than the default on two of these corpora.
- Decompression is timed too. A format that packs well and unpacks
  slowly has made a trade, and hiding half of it would be dishonest.
- Every number comes from one machine and one run. Timings vary; ratios
  do not. Ratios are the claim, timings are context.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import corpus as corpus_mod  # noqa: E402  (sits beside this file)

#: Matched thread budget. Anything else makes the timings a comparison
#: of core counts rather than of compressors.
THREADS = 8

SEVENZIP = next((p for p in (
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
    shutil.which("7z") or "",
) if p and os.path.exists(p)), None)


@dataclass
class Result:
    tool: str
    corpus: str
    ok: bool
    stored: int = 0
    pack_seconds: float = 0.0
    unpack_seconds: float = 0.0
    note: str = ""
    #: Fraction of a .pakt archive occupied by the two index copies.
    index_share: float = 0.0

    def ratio(self, original: int) -> float:
        return self.stored / original if original else 1.0


@dataclass
class Tool:
    name: str
    label: str
    pack: Callable[[str, str], None]
    unpack: Optional[Callable[[str, str], None]] = None
    ext: str = ".bin"
    slow: bool = False
    available: bool = True


# --------------------------------------------------------------------------
# Compakt
# --------------------------------------------------------------------------

def _compakt_pack(level_name: str, engine: bool):
    def run(src: str, out: str) -> None:
        from core.codecs import level_by_name
        level = level_by_name(level_name)
        if engine:
            from core.compressor import EngineOptions, pack
            pack([src], out, options=EngineOptions(level=level,
                                                   workers=THREADS))
        else:
            from core.reference_encoder import pack
            pack([src], out, level=level)
    return run


def _compakt_unpack(src: str, dest: str) -> None:
    from core.pakt_reader import open_pakt
    from core.safety import ExtractLimits
    with open_pakt(src) as archive:
        archive.extract_all(dest, limits=ExtractLimits(max_ratio=1e12))


# --------------------------------------------------------------------------
# External tools
# --------------------------------------------------------------------------

def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"{argv[0]} exited {result.returncode}: "
            f"{(result.stderr or result.stdout)[-200:]}")


def _sevenzip_pack(level: str, fmt: str = "7z"):
    def run(src: str, out: str) -> None:
        argv = [SEVENZIP, "a", f"-t{fmt}", level, f"-mmt={THREADS}",
                "-bso0", "-bsp0", "-y", out, src]
        _run(argv)
    return run


def _sevenzip_unpack(src: str, dest: str) -> None:
    _run([SEVENZIP, "x", f"-mmt={THREADS}", "-bso0", "-bsp0", "-y",
          f"-o{dest}", src])


def _tar_stream_pack(codec: str, level: int):
    """tar piped through a Python codec, matching what tar+zstd does."""
    def run(src: str, out: str) -> None:
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            tf.add(src, arcname=os.path.basename(src))
        raw = buf.getvalue()
        if codec == "zstd":
            import zstandard
            data = zstandard.ZstdCompressor(
                level=level, threads=THREADS).compress(raw)
        elif codec == "xz":
            import lzma
            data = lzma.compress(raw, preset=level)
        elif codec == "gzip":
            import gzip as gz
            data = gz.compress(raw, compresslevel=level)
        else:
            raise ValueError(codec)
        with open(out, "wb") as fh:
            fh.write(data)
    return run


def _tar_stream_unpack(codec: str):
    def run(src: str, dest: str) -> None:
        import io
        import tarfile
        with open(src, "rb") as fh:
            data = fh.read()
        if codec == "zstd":
            import zstandard
            raw = zstandard.ZstdDecompressor().decompress(
                data, max_output_size=1 << 32)
        elif codec == "xz":
            import lzma
            raw = lzma.decompress(data)
        else:
            import gzip as gz
            raw = gz.decompress(data)
        os.makedirs(dest, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            tf.extractall(dest, filter="data")
    return run


def build_tools(quick: bool) -> list[Tool]:
    tools = [
        Tool("compakt", "Compakt (auto)",
             _compakt_pack("auto", engine=True), _compakt_unpack,
             ".pakt"),
        Tool("compakt-fast", "Compakt (fast)",
             _compakt_pack("fast", engine=True), _compakt_unpack,
             ".pakt"),
        Tool("compakt-ref", "Compakt reference encoder",
             _compakt_pack("auto", engine=False), _compakt_unpack,
             ".pakt"),
    ]

    if SEVENZIP:
        tools += [
            Tool("7z-mx5", "7-Zip -mx5 (LZMA2)",
                 _sevenzip_pack("-mx5"), _sevenzip_unpack, ".7z"),
            Tool("7z-mx9", "7-Zip -mx9 (solid LZMA2)",
                 _sevenzip_pack("-mx9"), _sevenzip_unpack, ".7z", slow=True),
            Tool("zip", "ZIP deflate -mx9",
                 _sevenzip_pack("-mx9", fmt="zip"), _sevenzip_unpack, ".zip"),
        ]

    tools += [
        Tool("tar.zst", "tar + zstd -19",
             _tar_stream_pack("zstd", 19), _tar_stream_unpack("zstd"),
             ".tar.zst"),
        Tool("tar.xz", "tar + xz -9",
             _tar_stream_pack("xz", 9), _tar_stream_unpack("xz"),
             ".tar.xz", slow=True),
        Tool("tar.gz", "tar + gzip -9",
             _tar_stream_pack("gzip", 9), _tar_stream_unpack("gzip"),
             ".tar.gz"),
    ]

    if quick:
        tools = [t for t in tools if not t.slow]
    return tools


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------

def _verify(src: str, dest: str) -> str:
    """
    Compare every extracted file against the original.

    Timing an extraction only proves it did not raise. That is enough
    to catch a hard failure -- it is how the dictionary bug surfaced --
    but silent corruption would sail straight through a benchmark that
    unpacks and immediately deletes. A compression benchmark that does
    not check the data came back is measuring the wrong thing.

    Extracted trees are nested under the source folder's own name, so
    the original is located by matching the tail of the path.
    """
    originals = {}
    for base, _dirs, names in os.walk(src):
        for name in names:
            full = os.path.join(base, name)
            originals[os.path.relpath(full, src).replace(os.sep, "/")] = full

    seen = 0
    for base, _dirs, names in os.walk(dest):
        for name in names:
            got = os.path.join(base, name)
            rel = os.path.relpath(got, dest).replace(os.sep, "/")
            # Strip the leading folder each tool wraps the tree in.
            key = rel.split("/", 1)[1] if "/" in rel else rel
            original = originals.get(key) or originals.get(rel)
            if original is None:
                continue
            seen += 1
            if os.path.getsize(got) != os.path.getsize(original):
                return f"{key} differs in size"
            with open(got, "rb") as a, open(original, "rb") as b:
                if a.read() != b.read():
                    return f"{key} differs in content"

    if seen < len(originals):
        return f"only {seen} of {len(originals)} files were extracted"
    return ""


def bench(tool: Tool, src: str, work: str) -> Result:
    src = os.path.abspath(src)
    out = os.path.join(work, f"archive{tool.ext}")
    for stale in (out,):
        if os.path.exists(stale):
            os.remove(stale)

    try:
        start = time.perf_counter()
        tool.pack(src, out)
        pack_time = time.perf_counter() - start
    except Exception as exc:
        return Result(tool.name, "", False, note=f"pack failed: {exc}")

    if not os.path.exists(out):
        return Result(tool.name, "", False, note="no archive produced")
    stored = os.path.getsize(out)

    index_share = 0.0
    if tool.ext == ".pakt":
        # For .pakt, report how much of the archive is index rather than
        # payload. On many-small-file corpora it dominates, and a table
        # that hid it would be reporting the wrong number.
        try:
            from core.container import Header, HEADER_SIZE
            with open(out, "rb") as fh:
                header = Header.unpack(fh.read(HEADER_SIZE))
            index_share = (2 * header.index_a_length) / stored
        except Exception:
            pass

    unpack_time = 0.0
    if tool.unpack is not None:
        dest = os.path.join(work, "out")
        shutil.rmtree(dest, ignore_errors=True)
        try:
            start = time.perf_counter()
            tool.unpack(out, dest)
            unpack_time = time.perf_counter() - start
        except Exception as exc:
            return Result(tool.name, "", True, stored, pack_time,
                          note=f"unpack failed: {exc}")
        else:
            mismatch = _verify(src, dest)
            if mismatch:
                shutil.rmtree(dest, ignore_errors=True)
                return Result(tool.name, "", True, stored, pack_time,
                              unpack_time,
                              note=f"ROUND-TRIP MISMATCH: {mismatch}")
        finally:
            shutil.rmtree(dest, ignore_errors=True)

    os.remove(out)
    return Result(tool.name, "", True, stored, pack_time, unpack_time,
                  index_share=index_share)


def _warm(path: str) -> None:
    """
    Read the corpus once before timing anything.

    Without this the FIRST tool measured pays for a cold disk cache and
    every later tool reads from RAM. It produced a 115s run of one
    setting against a 12s run of a harder setting of the same encoder -- a slower setting
    finishing ten times faster, which is the signature of the
    measurement being wrong rather than the code.
    """
    for base, _dirs, names in os.walk(path):
        for name in names:
            try:
                with open(os.path.join(base, name), "rb") as fh:
                    while fh.read(1 << 20):
                        pass
            except OSError:
                pass


def run_corpus(name: str, tools: list[Tool], allow_download: bool) -> dict:
    path = corpus_mod.get(name, allow_download=allow_download)
    files, original = corpus_mod.measure(path)
    spec = corpus_mod.CORPORA[name]

    print(f"\n{name}  ({spec.kind})  {files:,} files, "
          f"{original / 1024 / 1024:.1f} MB")
    print(f"  {spec.tests}")

    _warm(path)

    results = []
    with tempfile.TemporaryDirectory(prefix="compakt-bench-") as work:
        for tool in tools:
            sys.stdout.write(f"    {tool.label:<28} ")
            sys.stdout.flush()
            result = bench(tool, path, work)
            result.corpus = name
            results.append(result)
            if result.ok and not result.note:
                print(f"{result.stored / 1024 / 1024:>8.2f} MB  "
                      f"ratio {result.ratio(original):.4f}  "
                      f"pack {result.pack_seconds:>6.1f}s  "
                      f"unpack {result.unpack_seconds:>5.1f}s")
            else:
                print(f"-- {result.note}")

    return {"corpus": name, "kind": spec.kind, "tests": spec.tests,
            "files": files, "bytes": original,
            "results": [r.__dict__ for r in results]}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def report(runs: list[dict], out_dir: str) -> None:
    lines = []
    add = lines.append

    add("# Compakt benchmark results")
    add("")
    add("Generated by `python benchmarks/run.py`. Every corpus is either")
    add("fetched from a public source, rebuilt from pinned dependencies, or")
    add("generated from a fixed seed, so these numbers are reproducible.")
    add("")
    add(f"Thread budget: {THREADS} for every tool. "
        f"7-Zip: {'found' if SEVENZIP else 'NOT INSTALLED'}.")
    add("")
    add("**Ratio is the claim; timings are context.** Ratios are")
    add("deterministic. Timings come from one machine and one run, and will")
    add("vary with hardware and load.")
    add("")

    wins, losses = [], []

    for run in runs:
        original = run["bytes"]
        ok = [r for r in run["results"] if r["ok"] and not r["note"]]
        if not ok:
            continue
        ok.sort(key=lambda r: r["stored"])

        add(f"## {run['corpus']}  ({run['kind']})")
        add("")
        add(f"{run['files']:,} files, {original / 1024 / 1024:.1f} MB. "
            f"{run['tests']}")
        add("")
        add("| Tool | Size | Ratio | vs Compakt | Index | Pack | Unpack |")
        add("|---|---:|---:|---:|---:|---:|---:|")

        baseline = next((r for r in ok if r["tool"] == "compakt"), None)
        for r in ok:
            delta = ""
            if baseline and r["tool"] != "compakt":
                diff = (r["stored"] - baseline["stored"]) / baseline["stored"]
                delta = f"{diff:+.1%}"
            share = (f"{r['index_share']:.0%}"
                     if r.get("index_share") else "-")
            add(f"| {r['tool']} | {r['stored'] / 1024 / 1024:.2f} MB | "
                f"{r['stored'] / original:.4f} | {delta} | {share} | "
                f"{r['pack_seconds']:.1f}s | {r['unpack_seconds']:.1f}s |")
        add("")

        rivals = [r for r in ok if not r["tool"].startswith("compakt")]
        if baseline and rivals:
            best = min(rivals, key=lambda r: r["stored"])
            margin = (best["stored"] - baseline["stored"]) / best["stored"]
            entry = (run["corpus"], best["tool"], margin)
            (wins if margin > 0 else losses).append(entry)

    add("## Summary")
    add("")
    if wins:
        add("### Where Compakt wins")
        add("")
        for name, rival, margin in sorted(wins, key=lambda w: -w[2]):
            add(f"- **{name}** — {margin:.1%} smaller than the best "
                f"alternative ({rival})")
        add("")
    if losses:
        add("### Where Compakt loses")
        add("")
        for name, rival, margin in sorted(losses, key=lambda w: w[2]):
            add(f"- **{name}** — {abs(margin):.1%} larger than {rival}")
        add("")
    else:
        add("### Where Compakt loses")
        add("")
        add("Nothing in this run. That is a statement about this corpus")
        add("set, not about compression in general -- add a corpus of")
        add("large single binaries and it will change.")
        add("")

    add("### Reading these honestly")
    add("")
    add("- `generated` corpora are synthetic and flatter every")
    add("  compressor. Treat their margins as an upper bound.")
    add("- `standard` corpora are single large files, where Compakt's")
    add("  structural advantages do not apply. Those are the numbers to")
    add("  quote against a sceptic.")
    add("- `compakt-ref` is the open reference encoder. The gap between")
    add("  it and `compakt` is what the proprietary routing engine buys.")

    os.makedirs(out_dir, exist_ok=True)
    md = os.path.join(out_dir, "RESULTS.md")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "results.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"threads": THREADS, "sevenzip": bool(SEVENZIP),
                   "runs": runs}, fh, indent=2)
    print(f"\nwrote {md}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", action="append", default=None)
    ap.add_argument("--download", action="store_true",
                    help="fetch Silesia and enwik8")
    ap.add_argument("--quick", action="store_true",
                    help="skip the slow maximum-effort settings")
    args = ap.parse_args()

    tools = build_tools(args.quick)
    names = args.corpus or [
        n for n, c in corpus_mod.CORPORA.items()
        if not c.optional or args.download]

    print(f"tools: {', '.join(t.name for t in tools)}")
    if not SEVENZIP:
        print("WARNING: 7-Zip not found; the most important comparison "
              "is missing")

    runs = []
    for name in names:
        try:
            runs.append(run_corpus(name, tools, args.download))
        except Exception as exc:
            print(f"\n{name}: SKIPPED ({exc})")

    if runs:
        report(runs, HERE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
