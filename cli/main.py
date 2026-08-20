"""
The `pakt` command line interface.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

The engine is a library either way, so this is argparse work rather
than a second product — but it is the artifact every one of the
project's named launch channels actually wants. r/DevOps, r/sysadmin,
r/selfhosted and Hacker News all want something scriptable in a CI job;
the window is for the WinRAR-replacement crowd, who arrive later.

DESIGN POINTS THAT MATTER FOR SCRIPTING

**Exit codes are specific.** A script needs to distinguish "wrong
password" from "this archive is a bomb" from "disk full". Every failure
mode gets its own code, listed in :class:`Exit`.

**Passwords are not taken on argv by default.** Command-line arguments
are visible to every other process on the machine via the process list,
so a password passed as ``-p hunter2`` leaks. ``-p`` therefore prompts
by default, with ``--password-env`` and ``--password-file`` provided for
genuine automation.

**``--json`` exists on every read command.** Parsing human-formatted
output is how brittle scripts get written.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from typing import Optional

__all__ = ["main", "Exit"]

PROGRAM = "pakt"
SLOGAN = "You deserve better compression."


class Exit:
    """Exit codes. Stable, and part of the interface."""

    OK = 0
    ERROR = 1                 # anything unclassified
    USAGE = 2                 # argparse territory
    WRONG_PASSWORD = 3        # or a tampered archive; GCM cannot tell
    REFUSED = 4               # traversal, bomb, symlink escape
    CORRUPT = 5               # checksum, hash or signature failure
    UNSUPPORTED = 6           # format or codec this build cannot handle


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

class Out:
    """Everything the CLI prints, in one place."""

    def __init__(self, *, quiet: bool = False, as_json: bool = False) -> None:
        self.quiet = quiet
        self.json = as_json

    def say(self, text: str = "") -> None:
        if not self.quiet and not self.json:
            print(text)

    def warn(self, text: str) -> None:
        if not self.json:
            print(f"{PROGRAM}: {text}", file=sys.stderr)

    def fail(self, text: str, *, code: str = "error") -> None:
        print(f"{PROGRAM}: error: {text}", file=sys.stderr)
        if self.json:
            # A script running with --json must be able to parse the
            # failure too, not just the success.
            print(json.dumps({"ok": False, "error": code,
                              "message": text}, indent=2))

    def emit(self, payload: dict) -> None:
        if self.json:
            print(json.dumps(payload, indent=2, default=str))


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------

def resolve_password(args, *, out: Out,
                     confirm: bool = False) -> Optional[str]:
    """
    Work out the password without leaking it into the process list.

    Precedence: --password-file, --password-env, then an interactive
    prompt. A literal value on ``-p`` is honoured but warned about,
    because argv is world-readable on every mainstream OS.
    """
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as fh:
            return fh.read().strip() or None

    if getattr(args, "password_env", None):
        value = os.environ.get(args.password_env)
        if not value:
            out.warn(f"environment variable {args.password_env} is unset")
            return None
        return value

    supplied = getattr(args, "password", None)
    if supplied is True:                       # bare -p, prompt for it
        import getpass
        first = getpass.getpass("Password: ")
        if not first:
            return None
        if confirm and getpass.getpass("Repeat password: ") != first:
            out.fail("passwords did not match")
            raise SystemExit(Exit.USAGE)
        return first
    if isinstance(supplied, str) and supplied:
        out.warn("a password given on the command line is visible to other "
                 "processes; prefer bare -p, --password-env or "
                 "--password-file")
        return supplied
    return None


class _PasswordAction(argparse.Action):
    """``-p`` with an optional value: bare means prompt."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, True if values is None else values)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_create(args, out: Out) -> int:
    from core.codecs import level_by_name

    password = resolve_password(args, out=out, confirm=True)
    sign_key = None
    public = None
    if args.sign:
        from core import crypto
        if args.key:
            with open(args.key, "rb") as fh:
                sign_key = bytes.fromhex(fh.read().decode("utf-8").strip())
            _, public = crypto.generate_signing_key()   # placeholder
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey)
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat)
            public = Ed25519PrivateKey.from_private_bytes(
                sign_key).public_key().public_bytes(Encoding.Raw,
                                                    PublicFormat.Raw)
        else:
            sign_key, public = crypto.generate_signing_key()

    pack, engine = _load_packer()
    out.say(f"{PROGRAM}: packing with the {engine}")

    try:
        result = pack(args.sources, args.output,
                      level=level_by_name(args.level),
                      reproducible=args.reproducible,
                      password=password, sign_key=sign_key)
    except Exception as exc:
        return _report(exc, out)

    if args.verbose:
        for item in result.items:
            if not item.size:
                continue
            note = "deduplicated" if item.deduped else item.codec.name.lower()
            out.say(f"  {item.path:<48} {human(item.size):>10}  {note}")

    out.say(result.summary())
    if public is not None:
        out.say(f"public key: {public.hex()}")
        if args.key_out:
            with open(args.key_out, "w", encoding="utf-8") as fh:
                fh.write(sign_key.hex())
            out.say(f"private key written to {args.key_out}")
        elif not args.key:
            out.warn("the private signing key was not saved; pass --key-out "
                     "to keep it")

    out.emit({
        "archive": result.archive_path,
        "entries": len(result.items),
        "input_bytes": result.total_input,
        "archive_bytes": result.archive_size,
        "ratio": round(result.ratio, 6),
        "deduplicated": result.deduped_files,
        "encrypted": password is not None,
        "signed": sign_key is not None,
        "public_key": public.hex() if public else None,
    })
    return Exit.OK


def cmd_extract(args, out: Out) -> int:
    from core.decompressor import extract, identify
    from core.safety import ExtractLimits

    try:
        info = identify(args.archive)
    except Exception as exc:
        return _report(exc, out)

    password = resolve_password(args, out=out)
    if info.encrypted and password is None and sys.stdin.isatty():
        import getpass
        password = getpass.getpass("Password: ") or None

    limits = ExtractLimits(allow_symlinks=args.allow_symlinks)
    if args.max_size:
        limits.max_total_bytes = args.max_size

    dest = args.directory or os.path.splitext(
        os.path.basename(args.archive))[0]
    try:
        result = extract(args.archive, dest, password=password, limits=limits)
    except Exception as exc:
        return _report(exc, out)

    for skipped in result.skipped:
        out.warn(f"skipped {skipped}")
    out.say(f"extracted {result.entries_written} entries "
            f"({human(result.bytes_written)}) into {result.destination}")
    out.emit({
        "archive": args.archive,
        "format": result.format,
        "destination": result.destination,
        "entries": result.entries_written,
        "bytes": result.bytes_written,
        "skipped": result.skipped,
    })
    return Exit.OK


def cmd_list(args, out: Out) -> int:
    from core.decompressor import identify, list_entries

    password = resolve_password(args, out=out)
    try:
        info = identify(args.archive)
        if info.encrypted and password is None and sys.stdin.isatty():
            import getpass
            password = getpass.getpass("Password: ") or None
        entries = list_entries(args.archive, password=password)
    except Exception as exc:
        return _report(exc, out)

    total = sum(e.size for e in entries)
    if not out.json:
        out.say(f"{args.archive}  [{info.format}"
                + (", encrypted" if info.encrypted else "") + "]")
        out.say()
        for e in entries:
            kind = "d" if e.is_dir else ("l" if e.is_symlink else "-")
            size = "" if e.is_dir else human(e.size)
            out.say(f"  {kind} {size:>10}  {e.path}")
        out.say()
        out.say(f"  {len(entries)} entries, {human(total)} uncompressed")

    out.emit({
        "archive": args.archive,
        "format": info.format,
        "encrypted": info.encrypted,
        "entries": [
            {"path": e.path, "size": e.size, "dir": e.is_dir,
             "symlink": e.is_symlink} for e in entries],
        "total_bytes": total,
    })
    return Exit.OK


def cmd_verify(args, out: Out) -> int:
    """Check integrity, and a signature if one is present."""
    from core.pakt_reader import open_pakt

    password = resolve_password(args, out=out)
    try:
        with open_pakt(args.archive, password=password) as archive:
            signed = archive.header.signed
            public = None
            if signed:
                public = archive.verify_signature(deep=True)
            else:
                # No signature, so verify the hash chain directly.
                for entry in archive.entries:
                    from core.container import EntryType
                    if entry.entry_type is not EntryType.DIRECTORY:
                        archive.read(entry)
            count = len(archive.entries)
    except Exception as exc:
        return _report(exc, out)

    if signed:
        out.say(f"signature valid, {count} entries verified")
        out.say(f"public key: {public.hex()}")
        if args.expect_key and args.expect_key.lower() != public.hex():
            out.fail("archive is signed by a different key than expected")
            return Exit.CORRUPT
    else:
        out.say(f"no signature; {count} entries verified against their "
                f"recorded hashes")

    out.emit({"archive": args.archive, "verified": True, "signed": signed,
              "entries": count,
              "public_key": public.hex() if public else None})
    return Exit.OK


def cmd_explain(args, out: Out) -> int:
    """Per-entry report of how the archive was built."""
    from core.pakt_reader import open_pakt

    password = resolve_password(args, out=out)
    try:
        with open_pakt(args.archive, password=password) as archive:
            blocks = archive.index.blocks
            rows = []
            for entry in archive.entries:
                block = (blocks[entry.block_index]
                         if entry.block_index < len(blocks) else None)
                rows.append({
                    "path": entry.path,
                    "size": entry.plain_size,
                    "routing_class": entry.routing_class.name,
                    "codec": block.codec.name if block else "-",
                    "deduplicated": entry.is_dedup_ref,
                    "block": (entry.block_index if block else None),
                })
            header = archive.header
            feature_names = [f.name for f in type(header.feature_flags)
                             if f.value and (header.feature_flags & f)]
    except Exception as exc:
        return _report(exc, out)

    if not out.json:
        out.say(f"{args.archive}")
        out.say(f"  format 1.0, {len(rows)} entries, {len(blocks)} blocks")
        out.say(f"  features: {', '.join(feature_names) or 'none'}")
        out.say()
        # MAXIMUM_ENTROPY_BINARY is 22 characters, so a 22-wide column
        # leaves no separator at all.
        out.say(f"  {'ENTRY':<44}{'SIZE':>10}  {'CLASS':<24}CODEC")
        for r in rows:
            note = "DEDUP" if r["deduplicated"] else r["codec"]
            out.say(f"  {r['path'][:43]:<44}{human(r['size']):>10}  "
                    f"{r['routing_class']:<24}{note}")

    out.emit({"archive": args.archive, "features": feature_names,
              "blocks": len(blocks), "entries": rows})
    return Exit.OK


#: Internal format names are not file extensions. Printing "brotli"
#: where a user expects ".br" is a small lie that costs support time.
_EXTENSIONS = {
    "pakt": ".pakt", "zip": ".zip", "7z": ".7z", "iso": ".iso",
    "tar": ".tar", "tar.gz": ".tar.gz", "tar.bz2": ".tar.bz2",
    "tar.xz": ".tar.xz", "tar.zstd": ".tar.zst",
    "gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "lzma": ".lzma",
    "zstd": ".zst", "brotli": ".br", "rar": ".rar", "cab": ".cab",
    "lha": ".lha", "cpio": ".cpio", "ar": ".ar", "deb": ".deb",
    "rpm": ".rpm", "xar": ".xar", "warc": ".warc", "arj": ".arj",
    "compress": ".Z",
}


def _ext(name: str) -> str:
    return _EXTENSIONS.get(name, "." + name)


def cmd_formats(args, out: Out) -> int:
    from core.codecs import available_codecs, bcj_available
    from core.decompressor import supported_formats

    formats = supported_formats()
    codecs = sorted(c.name for c in available_codecs())

    if not out.json:
        out.say("pack:")
        out.say("  .pakt")
        out.say()
        out.say("unpack, tier 1 (no native binaries):")
        out.say("  " + "  ".join(sorted(_ext(f) for f in formats["tier1"])))
        out.say()
        if formats["tier2"]:
            out.say("unpack, tier 2 (libarchive):")
            out.say("  " + "  ".join(sorted(_ext(f) for f in formats["tier2"])))
        else:
            out.say("unpack, tier 2: unavailable")
            out.say("  .rar .cab .lha .cpio .ar .deb .rpm .xar .warc .arj .Z")
            out.say("  need the libarchive shared library, which this build "
                    "does not carry.")

        # A format libarchive can name but this build cannot finish is
        # reported here rather than discovered by a user on a real file.
        if formats["tier2_partial"]:
            out.say()
            out.say("  partial -- the container opens, common payloads "
                    "do not:")
            for line in formats["tier2_partial"]:
                out.say(f"    {line}")
        if formats["tier2_unavailable"]:
            out.say()
            out.say("  not supported by this build:")
            for line in formats["tier2_unavailable"]:
                out.say(f"    {line}")
        if formats["native"]:
            out.say()
            out.say(f"  libarchive linked against: "
                    f"{', '.join(formats['native'])}")
        out.say()
        out.say(f"codecs: {', '.join(codecs)}"
                + ("  (+BCJ filter)" if bcj_available() else ""))

    out.emit({"pack": [".pakt"],
              "tier1": sorted(_ext(f) for f in formats["tier1"]),
              "tier2": sorted(_ext(f) for f in formats["tier2"]),
              "tier2_partial": formats["tier2_partial"],
              "tier2_unavailable": formats["tier2_unavailable"],
              "native": formats["native"],
              "codecs": codecs, "bcj": bcj_available()})
    return Exit.OK


def cmd_keygen(args, out: Out) -> int:
    from core import crypto
    seed, public = crypto.generate_signing_key()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(seed.hex())
        try:
            os.chmod(args.output, 0o600)
        except OSError:
            pass
        out.say(f"private key written to {args.output}")
    else:
        out.say(f"private key: {seed.hex()}")
    out.say(f"public key:  {public.hex()}")
    out.emit({"public_key": public.hex(),
              "private_key": None if args.output else seed.hex(),
              "written_to": args.output})
    return Exit.OK


# --------------------------------------------------------------------------
# Error mapping
# --------------------------------------------------------------------------

def _report(exc: Exception, out: Out) -> int:
    """Map an exception to a message and a specific exit code."""
    from core.container import (PaktCorruptError, PaktFormatError,
                                PaktUnsupportedError)
    from core.crypto import WrongPassword
    from core.decompressor import UnsupportedArchive
    from core.pakt_reader import PasswordRequired
    from core.safety import SecurityError

    if isinstance(exc, PasswordRequired):
        out.fail("this archive is encrypted; supply a password with -p",
                 code="password_required")
        return Exit.WRONG_PASSWORD
    if isinstance(exc, WrongPassword):
        out.fail("wrong password, or the archive has been altered "
                 "(authenticated encryption cannot tell these apart)",
                 code="wrong_password")
        return Exit.WRONG_PASSWORD
    if isinstance(exc, SecurityError):
        out.fail(str(exc), code="refused")
        return Exit.REFUSED
    if isinstance(exc, PaktCorruptError):
        out.fail(str(exc), code="corrupt")
        return Exit.CORRUPT
    if isinstance(exc, (PaktUnsupportedError, UnsupportedArchive)):
        out.fail(str(exc), code="unsupported")
        return Exit.UNSUPPORTED
    if isinstance(exc, PaktFormatError):
        out.fail(str(exc))
        return Exit.ERROR
    if isinstance(exc, (OSError, ValueError)):
        out.fail(str(exc))
        return Exit.ERROR
    raise exc


def _load_packer():
    try:
        from core.compressor import EngineOptions, pack as engine_pack

        def pack(sources, output, *, level, reproducible, password, sign_key):
            return engine_pack(sources, output, options=EngineOptions(
                level=level, reproducible=reproducible,
                password=password, sign_key=sign_key))
        return pack, "routing engine"
    except Exception:
        from core.reference_encoder import pack as ref_pack

        def pack(sources, output, *, level, reproducible, password, sign_key):
            return ref_pack(sources, output, level=level,
                            reproducible=reproducible, password=password,
                            sign_key=sign_key)
        return pack, "reference encoder"


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=f"Compakt — {SLOGAN}",
        epilog=("Exit codes: 0 ok, 1 error, 2 usage, 3 wrong password, "
                "4 refused on safety grounds, 5 corrupt, 6 unsupported."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version="pakt 1.0.0")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true",
                        help="print nothing but errors")
    common.add_argument("--json", action="store_true",
                        help="machine-readable output")

    pw = argparse.ArgumentParser(add_help=False)
    pw.add_argument("-p", "--password", nargs="?", action=_PasswordAction,
                    metavar="VALUE",
                    help="prompt for a password; a literal value is accepted "
                         "but visible to other processes")
    pw.add_argument("--password-env", metavar="VAR",
                    help="read the password from an environment variable")
    pw.add_argument("--password-file", metavar="PATH",
                    help="read the password from the first line of a file")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- create ---
    c = sub.add_parser("c", aliases=["create"], parents=[common, pw],
                       help="pack files into a .pakt archive")
    c.add_argument("sources", nargs="+")
    c.add_argument("-o", "--output", required=True, metavar="ARCHIVE")
    # Two settings, because there is exactly one question the data
    # cannot answer for itself: how much of the user's time we may
    # spend. Everything else -- codec, window, effort by block size --
    # is measured per block and is not the user's problem. There was a
    # third setting called "maximum"; measured across nine corpora it
    # bought 0.5% for two to three times the time and came out LARGER on
    # two of them, so it was removed rather than left as a trap.
    c.add_argument("--level", default="auto", choices=["auto", "fast"],
                   help="auto (default) measures each block and picks; "
                        "fast trades ratio for speed on bulk data")
    c.add_argument("--fast", dest="level", action="store_const", const="fast",
                   help="shorthand for --level fast")
    c.add_argument("--reproducible", action="store_true",
                   help="byte-identical output; cannot be combined with "
                        "encryption")
    c.add_argument("--sign", action="store_true",
                   help="sign the archive with Ed25519")
    c.add_argument("--key", metavar="PATH", help="existing private key to sign with")
    c.add_argument("--key-out", metavar="PATH", help="where to save a generated key")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(func=cmd_create)

    # --- extract ---
    x = sub.add_parser("x", aliases=["extract"], parents=[common, pw],
                       help="extract any supported archive")
    x.add_argument("archive")
    x.add_argument("-d", "--directory", metavar="DEST")
    x.add_argument("--allow-symlinks", action="store_true",
                   help="create symlinks (refused by default)")
    x.add_argument("--max-size", type=int, metavar="BYTES",
                   help="abort if extraction would exceed this total")
    x.set_defaults(func=cmd_extract)

    # --- list ---
    l = sub.add_parser("l", aliases=["list"], parents=[common, pw],
                       help="list an archive's contents")
    l.add_argument("archive")
    l.set_defaults(func=cmd_list)

    # --- verify ---
    v = sub.add_parser("verify", parents=[common, pw],
                       help="check integrity and any signature")
    v.add_argument("archive")
    v.add_argument("--expect-key", metavar="HEX",
                   help="fail unless signed by this public key")
    v.set_defaults(func=cmd_verify)

    # --- explain ---
    e = sub.add_parser("explain", parents=[common, pw],
                       help="report how each entry was compressed, and why")
    e.add_argument("archive")
    e.set_defaults(func=cmd_explain)

    # --- formats ---
    f = sub.add_parser("formats", parents=[common],
                       help="list what this build can read and write")
    f.set_defaults(func=cmd_formats)

    # --- keygen ---
    k = sub.add_parser("keygen", parents=[common],
                       help="generate an Ed25519 signing key")
    k.add_argument("-o", "--output", metavar="PATH")
    k.set_defaults(func=cmd_keygen)

    return parser


def _route_damage_warnings(out: Out) -> None:
    """
    Print a recovered-damage warning as OUR message, not Python's.

    The reader raises PaktDamageWarning because spec §2.1 obliges it to
    say so, but Python's default rendering leads with the file and line
    number of whichever internal module happened to open the archive.
    Someone whose download was cut short should be told their archive was
    damaged and opened anyway -- not shown a traceback fragment pointing
    into core/decompressor.py, which reads like a crash in the tool
    rather than a fault in their file.
    """
    from core.pakt_reader import PaktDamageWarning

    previous = warnings.showwarning

    def show(message, category, filename, lineno, file=None, line=None):
        if issubclass(category, PaktDamageWarning):
            # Straight to stderr, and NOT through Out.warn, which stays
            # silent under --json. Suppressing this one there would let a
            # script consume a recovered archive believing it was intact.
            # stdout keeps the JSON; stderr carries the fact.
            print(f"{PROGRAM}: warning: {message}", file=sys.stderr)
            return
        previous(message, category, filename, lineno, file, line)

    warnings.showwarning = show
    warnings.simplefilter("always", PaktDamageWarning)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Out(quiet=getattr(args, "quiet", False),
              as_json=getattr(args, "json", False))
    _route_damage_warnings(out)
    try:
        return args.func(args, out)
    except KeyboardInterrupt:
        out.warn("interrupted")
        return Exit.ERROR
    except BrokenPipeError:                           # `| head` and friends
        return Exit.OK
    except SystemExit:
        raise
    except Exception as exc:                          # pragma: no cover
        out.fail(f"{type(exc).__name__}: {exc}")
        return Exit.ERROR


if __name__ == "__main__":
    sys.exit(main())
