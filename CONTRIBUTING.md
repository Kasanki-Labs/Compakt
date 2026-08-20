# Contributing to Compakt

**Compakt is not accepting external code contributions at this time.**

This is not a comment on the quality of any offer. It is a licensing
constraint, and being straight about it up front is better than
leaving a pull request open for months.

## Why

Compakt is open core. This repository is MPL-2.0. The compression
routing engine and the trained dictionary corpus are proprietary and
live in a separate private repository, and the shipped binary combines
the two.

To keep shipping that combined binary — and to keep the option of
licensing Compakt commercially — the project has to hold 100% of the
copyright in the code it distributes. Accepting an outside
contribution without a Contributor Licence Agreement in place would
end that permanently, and it cannot be undone afterwards.

No CLA has been drafted yet, because there have been no contributors.

## What is genuinely useful right now

- **Bug reports.** Open an issue. Include the archive if you can share
  it, your OS, and what you expected to happen.
- **Benchmark results.** Especially ones where Compakt *loses*. The
  benchmark suite is public and reproducible for exactly this reason,
  and results that contradict ours are more valuable than results that
  agree with them.
- **Security findings.** See below.
- **Independent `.pakt` implementations.** The format specification is
  Apache-2.0 and deliberately free to implement. Build a reader, a
  writer, a library in another language — no permission needed, no
  strings. That is the whole point of licensing the spec separately.

## Security findings

Report privately rather than opening a public issue. Include steps to
reproduce and, if the finding involves an archive, the archive itself.

The entire security surface of Compakt is in this repository —
detection, extraction, the crypto layer, and the socket guard — and it
is here specifically so it can be audited. Findings against it are
welcome.

## If this changes

If external contributions are opened up later, a CLA will be added
here first and this file will say so. Until then, assume the answer to
"can I send a PR?" is no.

---

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)
