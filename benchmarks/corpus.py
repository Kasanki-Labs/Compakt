"""
Benchmark corpora.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

A benchmark is only worth as much as its corpus, so this module is
explicit about where every byte comes from and how anyone else can
obtain exactly the same bytes.

THREE KINDS, AND THEY PROVE DIFFERENT THINGS
--------------------------------------------

**Standard** corpora are fetched from public sources and verified by
SHA-256. Silesia and enwik8 are what the compression community actually
uses, and results on them are directly comparable with everyone else's.
They are also where Compakt is most likely to LOSE: Silesia is twelve
large single files, and a large single file gives solid blocks and
cross-file deduplication nothing to work with.

**Reproducible real-world** corpora are built from pinned dependencies.
`pip install -r requirements.txt` produces a byte-identical tree on any
machine, which makes it a genuine many-small-files corpus that is real
code rather than something we invented, and still exactly reproducible.

**Generated** corpora are deterministic and model specific shapes --
JSON logs, source files, wide CSV, incompressible blobs. They are
useful for isolating one behaviour at a time, and they FLATTER
COMPRESSORS: synthetic repetition is more regular than the real thing.
Any number from a generated corpus is labelled as such in the results,
and no headline claim should ever rest on one.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import random
import shutil
import sys
import urllib.request
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CACHE = os.path.join(HERE, "corpora")

#: Sanity ceiling for any single corpus. Nothing here should approach
#: it; exceeding it means a builder is walking into its own output.
MAX_CORPUS_FILES = 60_000
MAX_CORPUS_BYTES = 2 * 1024 ** 3

__all__ = ["Corpus", "CORPORA", "get", "available", "describe"]


@dataclass
class Corpus:
    name: str
    kind: str                      # standard | reproducible | generated
    note: str
    build: Callable[[str], None]
    #: What the corpus is meant to demonstrate, printed with the results
    #: so a reader knows why it is in the table at all.
    tests: str = ""
    url: str = ""
    optional: bool = False


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

def _download(url: str, dest: str, expect: str = "") -> str:
    """
    Fetch `url` to `dest`, verifying its digest when one is pinned.

    THE CHECK RUNS ON CACHE HITS, NOT ONLY ON FRESH DOWNLOADS. This
    used to return the moment the file existed, which meant the digest
    guarded only the first fetch: a cached corpus that had since been
    truncated, half-written or edited was measured without complaint.
    A benchmark run against silently wrong input is worse than one that
    fails outright, because the numbers still look publishable.

    A mismatch on a cached file is reported rather than repaired. The
    fetch path only ever promotes a verified download into place, so a
    bad cached file means it was altered afterwards -- and quietly
    refetching over it would hide that.
    """
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        if expect:
            digest = _sha256(dest)
            if digest != expect:
                raise RuntimeError(
                    f"cached corpus {os.path.basename(dest)} does not match "
                    f"its pinned digest\n  expected {expect}\n"
                    f"  got      {digest}\n"
                    f"  delete the file to fetch it again")
            print(f"    cached {os.path.basename(dest)}  sha256 verified")
        return dest

    print(f"    fetching {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "compakt-bench"})
    tmp = dest + ".part"
    with urllib.request.urlopen(req, timeout=180) as response, \
            open(tmp, "wb") as out:
        shutil.copyfileobj(response, out, 1 << 20)

    digest = _sha256(tmp)
    if expect and digest != expect:
        os.remove(tmp)
        raise RuntimeError(
            f"checksum mismatch for {url}\n"
            f"  expected {expect}\n  got      {digest}")
    if not expect:
        print(f"    sha256 {digest}  (record this to pin the corpus)")
    os.replace(tmp, dest)
    return dest


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Standard corpora
# --------------------------------------------------------------------------

SILESIA_URL = ("https://github.com/MiloszKrajewski/SilesiaCorpus/archive/"
               "refs/heads/master.zip")
ENWIK8_URL = "http://mattmahoney.net/dc/enwik8.zip"

#: Digests of the fetched archives, pinned so the published ratios are
#: known to have been measured against these exact bytes. Both matter
#: more than they look: SILESIA_URL is a third-party GitHub mirror whose
#: branch head can be rewritten at any time, and ENWIK8_URL is plain
#: HTTP with no transport integrity at all. Without a pin, either could
#: change underneath the numbers without anything noticing.
SILESIA_SHA256 = \
    "de094aa888ea8f3caaee9094e1452f57a0bfb08877096e82b9ff0eb89ecd790c"
ENWIK8_SHA256 = \
    "547994d9980ebed1288380d652999f38a14fe291a6247c157c3d33d4932534bc"


def _build_silesia(dest: str) -> None:
    """
    The Silesia corpus: twelve large files of deliberately varied type.

    The reference corpus for general-purpose compression. Included
    precisely because it is unfavourable to us -- single large files
    give solid blocks and dedup nothing to exploit, so this is where a
    loss against 7-Zip would show up.
    """
    archive = _download(SILESIA_URL, os.path.join(CACHE, "silesia.zip"),
                        expect=SILESIA_SHA256)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = os.path.basename(info.filename)
            # The mirror stores each corpus member individually zipped.
            if name.lower().endswith(".zip"):
                with zf.open(info) as inner_fh:
                    payload = inner_fh.read()
                with zipfile.ZipFile(io.BytesIO(payload)) as inner:
                    for sub in inner.infolist():
                        if sub.is_dir():
                            continue
                        out = os.path.join(dest, os.path.basename(sub.filename))
                        with inner.open(sub) as src, open(out, "wb") as dst:
                            shutil.copyfileobj(src, dst)
            elif "." not in name or name.lower().endswith(
                    (".txt", ".xml", ".pdf", ".bin")):
                out = os.path.join(dest, name)
                with zf.open(info) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)


def _build_enwik8(dest: str) -> None:
    """100 MB of Wikipedia XML. The standard single-file text benchmark."""
    archive = _download(ENWIK8_URL, os.path.join(CACHE, "enwik8.zip"),
                        expect=ENWIK8_SHA256)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            out = os.path.join(dest, os.path.basename(info.filename))
            with zf.open(info) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)


# --------------------------------------------------------------------------
# Reproducible real-world corpora
# --------------------------------------------------------------------------

def _build_sitepackages(dest: str) -> None:
    """
    The installed dependency tree: thousands of real small files.

    Real code rather than anything invented, and still exactly
    reproducible -- `pip install -r requirements.txt` with the pinned
    versions rebuilds the same tree anywhere. This is the shape Compakt
    is built for, and the shape Silesia cannot represent.

    __pycache__ is excluded: .pyc content varies with interpreter build
    and would make the corpus unreproducible.
    """
    src = os.path.join(REPO, ".venv", "Lib", "site-packages")
    if not os.path.isdir(src):
        src = os.path.join(REPO, ".venv", "lib")
    if not os.path.isdir(src):
        raise RuntimeError("no virtual environment found to copy")

    os.makedirs(dest, exist_ok=True)
    copied = 0
    for base, dirs, names in os.walk(src):
        dirs[:] = sorted(d for d in dirs
                         if d not in ("__pycache__", ".git"))
        for name in sorted(names):
            if name.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(base, name)
            rel = os.path.relpath(full, src)
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            try:
                shutil.copy2(full, out)
                copied += 1
            except OSError:
                continue
    if copied == 0:
        raise RuntimeError("copied nothing from site-packages")


def _build_source_tree(dest: str) -> None:
    """
    Compakt's own source: a small, very typical developer folder.

    `benchmarks` is walked, and the corpus cache lives INSIDE it. Left
    unguarded this copies the corpora into themselves, recursing until
    the disk fills -- it reached 342,858 files and 2.9 GB before being
    stopped. The cache is skipped explicitly, and by real path rather
    than by name, so a symlink or a relocated cache cannot slip past.
    """
    os.makedirs(dest, exist_ok=True)
    cache_real = os.path.realpath(CACHE)
    dest_real = os.path.realpath(dest)

    for sub in ("core", "app", "cli", "tests", "docs", "benchmarks"):
        src = os.path.join(REPO, sub)
        if not os.path.isdir(src):
            continue
        for base, dirs, names in os.walk(src):
            base_real = os.path.realpath(base)
            if base_real.startswith(cache_real) or                     base_real.startswith(dest_real):
                dirs[:] = []
                continue
            dirs[:] = sorted(
                d for d in dirs
                if d != "__pycache__"
                and not os.path.realpath(
                    os.path.join(base, d)).startswith(cache_real))
            for name in sorted(names):
                if name.endswith((".pyc", ".pyd", ".so")):
                    continue
                full = os.path.join(base, name)
                rel = os.path.relpath(full, REPO)
                out = os.path.join(dest, rel)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copy2(full, out)


# --------------------------------------------------------------------------
# Generated corpora
# --------------------------------------------------------------------------
# Seeded, so every run produces identical bytes. These model one shape
# each; they are not a substitute for real data and are labelled
# accordingly in the results.

_WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet "
          "kilo lima mike november oscar papa quebec romeo sierra tango "
          "uniform victor whiskey xray yankee zulu").split()


def _build_json_logs(dest: str) -> None:
    """8,000 small JSON documents. Structured, repetitive, many files."""
    rng = random.Random(20260818)
    os.makedirs(dest, exist_ok=True)
    for i in range(8000):
        doc = {
            "ts": 1_700_000_000 + i,
            "level": rng.choice(("info", "warn", "error", "debug")),
            "service": rng.choice(("packer", "indexer", "reader", "guard")),
            "msg": " ".join(rng.choice(_WORDS) for _ in range(rng.randint(4, 12))),
            "items": rng.randint(0, 5000),
            "ok": rng.random() > 0.1,
            "host": f"worker-{rng.randint(1, 24):02d}",
            "trace": f"{rng.getrandbits(64):016x}",
        }
        with open(os.path.join(dest, f"event-{i:05d}.json"), "wb") as fh:
            fh.write(json.dumps(doc, indent=2).encode())


def _build_source_like(dest: str) -> None:
    """1,200 small source files with heavy structural repetition."""
    rng = random.Random(4242)
    os.makedirs(dest, exist_ok=True)
    for i in range(1200):
        lines = [
            "from __future__ import annotations",
            "import os",
            "import sys",
            "",
            "",
            f"class Handler{i}:",
            '    """Generated handler."""',
            "",
            "    def __init__(self, config):",
            "        self.config = config",
            "        self.count = 0",
            "",
        ]
        for k in range(rng.randint(3, 9)):
            lines += [
                f"    def step_{k}(self, payload):",
                f'        """Step {k}."""',
                "        if not payload:",
                "            return None",
                f"        self.count += {k + 1}",
                f"        return payload * {k + 1}",
                "",
            ]
        with open(os.path.join(dest, f"module_{i:04d}.py"), "wb") as fh:
            fh.write("\n".join(lines).encode())


def _build_wide_csv(dest: str) -> None:
    """One wide numeric table. Columnar, highly regular."""
    rng = random.Random(99)
    os.makedirs(dest, exist_ok=True)
    cols = [f"metric_{i:02d}" for i in range(40)]
    with open(os.path.join(dest, "measurements.csv"), "wb") as fh:
        fh.write((",".join(["id", "region", "stamp"] + cols) + "\n").encode())
        for row in range(120_000):
            values = [str(row),
                      rng.choice(("north", "south", "east", "west")),
                      str(1_700_000_000 + row)]
            values += [f"{rng.uniform(0, 100):.3f}" for _ in cols]
            fh.write((",".join(values) + "\n").encode())


def _build_mixed(dest: str) -> None:
    """
    What a real folder looks like: text, code, data, and media that is
    already compressed and cannot be squeezed further.
    """
    rng = random.Random(7)
    os.makedirs(os.path.join(dest, "docs"), exist_ok=True)
    os.makedirs(os.path.join(dest, "assets"), exist_ok=True)
    os.makedirs(os.path.join(dest, "data"), exist_ok=True)

    for i in range(300):
        body = "\n\n".join(
            " ".join(rng.choice(_WORDS) for _ in range(rng.randint(30, 90)))
            for _ in range(rng.randint(4, 14)))
        with open(os.path.join(dest, "docs", f"note-{i:03d}.md"), "wb") as fh:
            fh.write(f"# Note {i}\n\n{body}\n".encode())

    # Already-compressed payloads: the store-only path has to earn its
    # keep here, and any compressor that tries to recompress them loses.
    for i in range(40):
        with open(os.path.join(dest, "assets", f"blob-{i:02d}.bin"), "wb") as fh:
            fh.write(rng.randbytes(256 * 1024))

    for i in range(120):
        rows = [f"{j},{rng.randint(0, 9999)},{rng.uniform(0, 1):.5f}"
                for j in range(500)]
        with open(os.path.join(dest, "data", f"table-{i:03d}.csv"), "wb") as fh:
            fh.write(("id,count,ratio\n" + "\n".join(rows) + "\n").encode())


def _build_duplicates(dest: str) -> None:
    """
    A tree with heavy duplication, as node_modules and backups have.

    Deduplication is free in .pakt because the hash is already required
    for integrity, so this measures a real structural advantage rather
    than a codec trick.
    """
    rng = random.Random(31337)
    os.makedirs(dest, exist_ok=True)
    payloads = []
    for i in range(60):
        text = "\n".join(
            " ".join(rng.choice(_WORDS) for _ in range(12))
            for _ in range(rng.randint(40, 200)))
        payloads.append(f"// module {i}\n{text}\n".encode())

    for copy in range(30):
        folder = os.path.join(dest, f"package-{copy:02d}", "lib")
        os.makedirs(folder, exist_ok=True)
        for i, payload in enumerate(payloads):
            with open(os.path.join(folder, f"mod-{i:02d}.js"), "wb") as fh:
                fh.write(payload)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

CORPORA: dict[str, Corpus] = {
    c.name: c for c in (
        Corpus("silesia", "standard",
               "Twelve large mixed files; the reference corpus.",
               _build_silesia,
               tests="General-purpose ratio on large single files. "
                     "UNFAVOURABLE to us: nothing for solid blocks or "
                     "dedup to exploit.",
               url=SILESIA_URL, optional=True),
        Corpus("enwik8", "standard",
               "100 MB of Wikipedia XML.",
               _build_enwik8,
               tests="Single large text file. Pure codec quality, no "
                     "structural advantage available.",
               url=ENWIK8_URL, optional=True),
        Corpus("sitepackages", "reproducible",
               "The pinned dependency tree: thousands of real files.",
               _build_sitepackages,
               tests="Many small real files of mixed type. The shape "
                     "solid blocks exist for."),
        Corpus("sourcetree", "reproducible",
               "Compakt's own source.",
               _build_source_tree,
               tests="A small, ordinary developer folder."),
        Corpus("jsonlogs", "generated",
               "8,000 small JSON documents.",
               _build_json_logs,
               tests="Many small structured files. Best case for solid "
                     "blocks; synthetic, so treat the margin as an "
                     "upper bound."),
        Corpus("sourcelike", "generated",
               "1,200 small generated source files.",
               _build_source_like,
               tests="Cross-file structural repetition."),
        Corpus("widecsv", "generated",
               "One wide numeric CSV.",
               _build_wide_csv,
               tests="Columnar regularity in a single large file."),
        Corpus("mixed", "generated",
               "Text, code, tables and incompressible blobs.",
               _build_mixed,
               tests="Realistic mixture. Tests whether already-"
                     "compressed data is correctly left alone."),
        Corpus("duplicates", "generated",
               "Thirty copies of the same sixty files.",
               _build_duplicates,
               tests="Whole-file deduplication."),
    )
}


def available() -> list[str]:
    return list(CORPORA)


def get(name: str, *, allow_download: bool = False) -> str:
    """Materialise a corpus and return its directory."""
    if name not in CORPORA:
        raise KeyError(f"unknown corpus {name!r}; have {sorted(CORPORA)}")
    spec = CORPORA[name]
    dest = os.path.join(CACHE, name)

    marker = os.path.join(CACHE, f".{name}.done")
    if os.path.isdir(dest) and os.path.exists(marker):
        return dest

    if spec.optional and not allow_download:
        raise RuntimeError(
            f"corpus {name!r} must be downloaded from {spec.url}\n"
            f"  re-run with --download to fetch it")

    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    print(f"  building corpus {name} ({spec.kind})")
    spec.build(dest)

    # A ceiling. A corpus builder that walks into its own output
    # recurses until the disk is full, and the failure looks like a
    # slow build rather than a bug until it is far too late.
    files, size = measure(dest)
    if files > MAX_CORPUS_FILES or size > MAX_CORPUS_BYTES:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(
            f"corpus {name!r} produced {files:,} files / "
            f"{size / 1024 ** 3:.1f} GB, past the sanity ceiling. "
            f"Its builder is almost certainly recursing into its own "
            f"output.")
    with open(marker, "w", encoding="utf-8") as fh:
        fh.write("ok\n")
    return dest


def measure(path: str) -> tuple[int, int]:
    """Return (file count, total bytes)."""
    files = total = 0
    for base, _dirs, names in os.walk(path):
        for name in names:
            try:
                total += os.path.getsize(os.path.join(base, name))
                files += 1
            except OSError:
                pass
    return files, total


def describe() -> None:
    print(f"{'CORPUS':<15}{'KIND':<14}NOTE")
    for spec in CORPORA.values():
        print(f"{spec.name:<15}{spec.kind:<14}{spec.note}")


if __name__ == "__main__":
    if "--list" in sys.argv:
        describe()
    else:
        allow = "--download" in sys.argv
        for name in CORPORA:
            try:
                path = get(name, allow_download=allow)
                files, size = measure(path)
                print(f"  {name:<15} {files:>7,} files  "
                      f"{size / 1024 / 1024:>9.1f} MB")
            except Exception as exc:
                print(f"  {name:<15} SKIPPED: {exc}")
