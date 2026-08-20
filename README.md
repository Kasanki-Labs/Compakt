# Compakt

**You deserve better compression.**

A local-first archiver that routes files to different codecs by
measuring what they actually contain, packs them into a custom
container with authenticated encryption, and never opens a socket.

> **Status: pre-alpha.** The format specification is frozen and the
> detector is implemented and tested. The compressor, extractor, GUI
> and CLI are not built yet. Nothing here is usable as a tool. Do not
> trust it with data you care about.

---

## What it is

Most archivers decide how to compress a file by looking at its name.
Compakt reads the bytes. A SQLite database renamed to `.txt` is routed
as a database, not as prose. An already-compressed blob with a
misleading extension is stored raw instead of being pointlessly
recompressed, because its measured entropy gives it away.

That routing feeds a container format, `.pakt`, designed around six
commitments:

- **Truncation is survivable.** The index is written at both ends.
- **Unknown archives fail loudly.** Feature flags are explicit and
  readers reject what they do not understand.
- **The file listing is not public.** With a password set, the index
  itself is encrypted — unlike ZIP, which leaks every filename.
- **Authentication precedes disclosure.** No plaintext reaches disk
  before its GCM tag verifies.
- **The container is relocatable.** A reader locates it from the
  footer, so an arbitrary prefix cannot break an archive.
- **There is no version 2 to wait for.** Everything structural is
  defined in 1.0.

## Local only

Compakt does not open network sockets, send telemetry, use cloud APIs,
or check for updates. Every library in the stack is a pure codec —
maths on bytes, nothing more.

That claim is checkable rather than merely asserted. The socket guard
lives in this repository, and the behaviour is observable from outside
the process:

- block Compakt in your OS firewall — it works identically
- run it in an air-gapped VM, or with the network cable out
- watch it with Wireshark, Resource Monitor, or Little Snitch

## Open core — not open source

Being precise about this up front, because the distinction matters.

| Component | Licence |
|---|---|
| `.pakt` format spec + reference decoder | Apache-2.0 |
| This repository — detector, extractor, crypto, socket guard, GUI, CLI, reference encoder | MPL-2.0 |
| The compression routing engine and trained dictionary corpus | proprietary, not published |

Everything that could hurt you is open and auditable. What is closed is
one file that decides which codec to call, which has no bearing on
whether Compakt is trustworthy or on your ability to read your own
archives — `core/reference_encoder.py` in this repository is a real,
working encoder that produces valid `.pakt` files.

**The format is free.** Implement `.pakt` in any language, for any
purpose, commercially or not, without asking. Every archive ever
written stays readable by anyone, forever, whatever happens to this
project. See [`LICENSING.md`](LICENSING.md) and
[`docs/pakt-format-spec.md`](docs/pakt-format-spec.md).

## Formats

**Packs:** `.pakt` only.

**Unpacks:** `.pakt`, `.zip`, `.7z`, `.tar` and its variants, `.gz`,
`.bz2`, `.xz`, `.zst`, `.br`, `.iso`, plus roughly forty more via
libarchive including `.rar`, `.cab`, `.lha`, `.cpio`, `.deb`, `.rpm`
and `.arj`.

Writing `.rar` is never offered. RARLAB licenses no compressor.

## Building from source

```
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest
```

Python 3.14 or newer. Every dependency ships a prebuilt wheel, so no C
compiler is needed to run or test. One is needed only to build a
release binary.

## Contributing

External code contributions are not being accepted at this time — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for why. Bug reports, benchmark
results (especially ones where Compakt loses), security findings and
independent `.pakt` implementations are all welcome.

## Benchmarks

Not published yet. When they are, they will include a reproducible
corpus and a results table showing **wins and losses**, with the script
so anyone can run it themselves. Any performance claim made before that
exists should be treated as marketing, including by us.

---

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)
