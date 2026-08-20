# Licensing

Compakt is **open core**, not open source. Three different licences
apply to three different things, and this file explains which is which
so nobody has to guess.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

## The short version

| What | Licence | Where |
|---|---|---|
| The `.pakt` format specification and reference decoder | Apache-2.0 | [`docs/LICENSE-SPEC`](docs/LICENSE-SPEC) |
| This application — GUI, CLI, detector, extractor, crypto, socket guard, reference encoder | MPL-2.0 | [`LICENSE`](LICENSE) |
| The compression routing engine and the trained dictionary corpus | Proprietary, all rights reserved | not in this repository |

## The `.pakt` format — Apache-2.0

`docs/pakt-format-spec.md` and the reference decoder are Apache-2.0.

Implement `.pakt` in any language, for any purpose, commercial or not.
Write a reader, write a writer, embed it in your own product. No
permission needed and no obligation to us. Apache-2.0 also carries an
explicit patent grant, which matters in compression specifically —
the field has a history of patent landmines.

This is deliberate. A format is worth what its adoption is worth, and
an archive nobody else can open is a hostage, not a feature. Every
`.pakt` file ever written stays readable by anyone, forever, whatever
happens to this project.

## The application — MPL-2.0

Everything in this repository is MPL-2.0.

MPL is **file-level copyleft**. If you modify one of these files and
distribute it, that file's source has to be made available under
MPL-2.0. But MPL section 3.3 expressly permits combining these files
with code under other licences — including proprietary code — inside a
larger work. That is exactly what Compakt itself does.

Practically: use it, ship it, fork it, embed it. Improvements to *our*
files come back; your own files stay yours.

## The compression engine — proprietary

`core/compressor.py` — the routing engine that decides which codec
handles which data, how files are grouped into solid blocks, when
dictionaries are trained, and which transforms apply — is not in this
repository and is not licensed for redistribution. Neither is the
trained dictionary corpus it uses.

**This repository still packs `.pakt` files.** `core/reference_encoder.py`
is a complete, working encoder that produces valid archives using
straightforward per-file routing. It is slower and it compresses
somewhat worse than the shipped engine. It is a real implementation,
not a stub, and it means this repository builds, runs and round-trips
on its own.

## Why the split is drawn here

Everything that could hurt you is open. Detection, extraction, the
crypto layer, the socket guard — all auditable, because a tool that
claims to be air-gapped and zero-knowledge should be checkable rather
than believed.

What is closed is one file that decides which codec to call. It has no
bearing on whether Compakt is trustworthy, and it does not affect your
ability to read your own archives.

If that trade is not acceptable to you, the format spec is Apache-2.0
and the reference encoder is MPL-2.0. Build your own.

## What no licence here grants

**Trademark.** "Compakt" and "Kasanki Labs" are not licensed. Fork the
code freely; call the result something else.

## Verifying the local-only claim

None of the above requires you to trust us. The socket guard is in
this repository, and the claim is checkable from outside the process:

- block Compakt in your OS firewall — it works identically
- run it in an air-gapped VM, or with the network cable out
- watch it with Wireshark, Resource Monitor or Little Snitch

See the `AIRGAP.md` procedure for a 30-second version.
