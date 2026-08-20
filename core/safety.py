"""
Extraction safety controls, shared by every archive format.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Archive utilities are attacked through their extractors far more often
than through their codecs, and the attacks are format-agnostic: zip-slip
works against tar, 7z and rar just as well as against zip. So the
policy lives here, once, and every handler in :mod:`core.decompressor`
plus the `.pakt` reader route through it.

Writing this twice would be the actual danger. Two implementations of a
security control drift apart, and the one that drifts is the one nobody
is looking at.

The controls:

- **Path traversal.** Targets are resolved against the extraction root
  at the moment of creation and rejected if they escape. Inspecting the
  stored string is not enough, because a symlink created earlier in the
  same extraction can change where a later path lands.
- **Symlink and hardlink escape.** Links resolving outside the root are
  refused; symlinks are opt-in, hardlinks are refused outright.
- **Decompression bombs.** Total output, per-entry ratio and entry
  count are capped, and a breach aborts rather than filling the disk
  and reporting failure afterwards.
- **Special files.** Device nodes, FIFOs and sockets are never created.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "SecurityError", "ExtractLimits", "safe_target", "check_link_target",
    "BombGuard", "sanitise_member_path",
]


class SecurityError(Exception):
    """An archive tried to do something an extractor must not allow."""


@dataclass
class ExtractLimits:
    """
    Caps enforced during extraction.

    Defaults are generous enough not to obstruct a legitimate archive
    while still stopping a bomb long before it fills a disk.
    """

    #: Total uncompressed bytes written across the whole extraction.
    #: THIS IS THE PRIMARY CONTROL. A decompression bomb is dangerous
    #: because of how much it produces, not because of its ratio.
    max_total_bytes: int = 64 * 1024 ** 3            # 64 GiB
    #: Uncompressed-to-stored ratio, evaluated per entry or per block.
    #:
    #: Deliberately loose, and a secondary check only. Ratio is a poor
    #: primary control because legitimate data reaches absurd ratios:
    #: a solid block of similar files easily exceeds 1000x, and 48 MiB
    #: of zeros from a sparse file or disk image reaches 250,000x. An
    #: aggressive cap here rejects exactly the data a good compressor
    #: handles best. Classic bombs run to 10^6 and beyond, so this
    #: still catches them while leaving real archives alone.
    max_ratio: float = 500_000.0
    #: Maximum number of entries.
    max_entries: int = 1_000_000
    #: Largest single entry.
    max_entry_bytes: int = 16 * 1024 ** 3            # 16 GiB
    #: Whether symlink entries may be created at all.
    allow_symlinks: bool = False


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

_WINDOWS_RESERVED = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})


def sanitise_member_path(raw: str) -> str:
    """
    Normalise an arbitrary archive member name into a safe relative path.

    Foreign formats are far laxer than `.pakt`: tar and zip both happily
    carry absolute paths, drive letters, backslashes, ``..`` components
    and NUL bytes, because nothing in either specification forbids them.
    Rather than reject an otherwise-fine archive over a cosmetic quirk,
    the name is normalised and then *proved* safe by
    :func:`safe_target`. Anything that cannot be normalised is rejected.
    """
    if not raw:
        raise SecurityError("archive member has an empty name")
    if "\x00" in raw:
        raise SecurityError("archive member name contains a NUL byte")

    name = raw.replace("\\", "/")

    # Strip a drive letter or UNC prefix.
    if len(name) > 1 and name[1] == ":":
        name = name[2:]
    name = name.lstrip("/")

    parts: list[str] = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            # Never resolve upward. Dropping the component keeps the
            # entry inside the root; safe_target still verifies.
            raise SecurityError(
                f"archive member {raw!r} contains a '..' component")
        if part.split(".")[0].lower() in _WINDOWS_RESERVED:
            raise SecurityError(
                f"archive member {raw!r} uses the reserved device name "
                f"{part!r}")
        parts.append(part)

    if not parts:
        raise SecurityError(f"archive member {raw!r} normalises to nothing")
    return "/".join(parts)


def _inside(root_real: str, candidate: str) -> bool:
    return candidate == root_real or candidate.startswith(root_real + os.sep)


def safe_target(root: str, member_path: str) -> str:
    """
    Resolve ``member_path`` under ``root`` and prove it stays inside.

    Call this immediately before creating each object, never once up
    front: resolution has to account for symlinks written earlier in the
    same extraction.
    """
    clean = sanitise_member_path(member_path)
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root_real, clean))
    if not _inside(root_real, candidate):
        raise SecurityError(
            f"entry {member_path!r} resolves to {candidate!r}, outside the "
            f"extraction root; refusing (path traversal)")
    return candidate


def check_link_target(root: str, link_path: str, target: str) -> None:
    """
    Verify a symlink cannot point outside the extraction root.

    Both absolute targets and relative ones that climb out are caught,
    because either would turn a later write into an arbitrary-file
    overwrite.
    """
    root_real = os.path.realpath(root)
    if os.path.isabs(target) or (len(target) > 1 and target[1] == ":"):
        raise SecurityError(
            f"symlink {link_path!r} points at the absolute path "
            f"{target!r}; refusing")
    resolved = os.path.realpath(
        os.path.join(os.path.dirname(link_path), target))
    if not _inside(root_real, resolved):
        raise SecurityError(
            f"symlink {link_path!r} would point at {resolved!r}, outside "
            f"the extraction root; refusing")


# --------------------------------------------------------------------------
# Bombs
# --------------------------------------------------------------------------

class BombGuard:
    """
    Running tally against :class:`ExtractLimits`.

    Where an archive declares its uncompressed sizes up front, call
    :meth:`declare` first so a bomb is refused from metadata alone and
    never gets inflated. :meth:`account` is the backstop for formats
    that do not declare, or that lie.
    """

    def __init__(self, limits: ExtractLimits) -> None:
        self.limits = limits
        self.total = 0
        self.entries = 0

    def declare_entry_count(self, n: int) -> None:
        if n > self.limits.max_entries:
            raise SecurityError(
                f"archive declares {n} entries, above the "
                f"{self.limits.max_entries} cap")

    def declare(self, uncompressed: int, compressed: int, name: str) -> None:
        """Check a declared entry before any of it is decoded."""
        if uncompressed > self.limits.max_entry_bytes:
            raise SecurityError(
                f"entry {name!r} declares {uncompressed} bytes, above the "
                f"{self.limits.max_entry_bytes} per-entry cap")
        if compressed > 0:
            ratio = uncompressed / compressed
            if ratio > self.limits.max_ratio:
                raise SecurityError(
                    f"entry {name!r} expands {ratio:.0f}x, above the "
                    f"{self.limits.max_ratio:.0f}x cap; refusing as a likely "
                    f"decompression bomb")

    def account(self, written: int, name: str) -> None:
        """Record bytes actually produced, and stop if the total blows."""
        self.entries += 1
        if self.entries > self.limits.max_entries:
            raise SecurityError(
                f"archive produced more than {self.limits.max_entries} "
                f"entries; aborting")
        if written > self.limits.max_entry_bytes:
            raise SecurityError(
                f"entry {name!r} produced {written} bytes, above the "
                f"{self.limits.max_entry_bytes} per-entry cap")
        self.total += written
        if self.total > self.limits.max_total_bytes:
            raise SecurityError(
                f"extraction exceeded the {self.limits.max_total_bytes} byte "
                f"total cap; aborting rather than filling the disk")
