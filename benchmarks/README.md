# Benchmarks

Run them yourself. That is the entire point of this directory.

```
python benchmarks/run.py                 # offline corpora only
python benchmarks/run.py --download      # adds Silesia and enwik8
python benchmarks/run.py --quick         # skips the slow max settings
python benchmarks/run.py --corpus jsonlogs
python benchmarks/corpus.py --list       # what the corpora are
```

Results are written to `RESULTS.md` and `results.json` in this folder.

## Why this exists

Every compression thread on Hacker News ends the same way: someone runs
their own benchmark. If a stranger tests Compakt against `7z -mx9` on
their own data and it loses, and we had published only wins, the
project's credibility is spent in a single exchange and does not come
back.

So this harness reports losses as prominently as wins, and the corpus
set deliberately includes cases where Compakt is expected to lose.

## What the corpora are, and what each proves

| Corpus | Kind | What it tests |
|---|---|---|
| `silesia` | standard | The reference corpus. Twelve large single files. **Unfavourable to Compakt** — nothing for solid blocks or dedup to exploit. |
| `enwik8` | standard | 100 MB of Wikipedia XML. Pure codec quality on one large text file. |
| `sitepackages` | reproducible | The pinned dependency tree. Thousands of real small files of mixed type. |
| `sourcetree` | reproducible | Compakt's own source. An ordinary developer folder. |
| `jsonlogs` | generated | 8,000 small JSON documents. Best case for solid blocks. |
| `sourcelike` | generated | 1,200 generated source files. Cross-file structural repetition. |
| `widecsv` | generated | One wide numeric table. Columnar regularity. |
| `mixed` | generated | Text, code, tables and incompressible blobs together. |
| `duplicates` | generated | Thirty copies of sixty files. Whole-file deduplication. |

**Standard** corpora are downloaded from public sources. They are what
everyone else benchmarks against, so results are directly comparable.

**Reproducible** corpora are rebuilt from pinned inputs. Running
`pip install -r requirements.txt` with the same pinned versions produces
a byte-identical tree on any machine, which makes real code usable as a
reproducible corpus.

**Generated** corpora are built from a fixed seed. They isolate one
behaviour at a time and are byte-identical on every run — but synthetic
repetition is more regular than the real thing, so **they flatter every
compressor**. Treat their margins as an upper bound, and never quote one
as a headline figure.

## How the comparison is kept fair

- **Matched thread budget.** Every tool gets 8 threads. 7-Zip would
  otherwise use all available cores while Compakt used eight, turning
  the timings into a comparison of core counts.
- **Paired effort levels.** Compakt has two: `auto` (the default) is
  paired against `7z -mx9`, and `fast` against `7z -mx5`.
- **Decompression is timed too.** A format that packs well and unpacks
  slowly has made a trade, and reporting only half of it would be
  dishonest.
- **The reference encoder is included.** `compakt-ref` is the open
  encoder in this repository, with no proprietary engine. The gap
  between it and `compakt` is exactly what the routing engine buys, and
  publishing it means the open-core claim can be checked rather than
  believed.

## What these numbers are not

They come from one machine, one run. **Ratios are deterministic and are
the claim. Timings are context** and will vary with hardware, disk and
load.

No result here has been tuned for. If a corpus makes Compakt look bad,
it stays in the table.
