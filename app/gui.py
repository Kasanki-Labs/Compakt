"""
The Compakt desktop window.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Dark, sharp-edged, and built on a spacing scale rather than on
arbitrary padding. The top-left carries the Kasanki Labs mark beside
the Compakt wordmark, which is bold text rather than a graphic — the
name is the logo.

THREADING
---------
All packing and extraction runs on a worker thread. Tk is not
thread-safe, so workers never touch a widget: they push messages onto a
queue and the window drains it from :meth:`_pump`, which runs on the Tk
event loop. That keeps the window responsive during a long job and
keeps every widget mutation on one thread.

The routing engine is imported if present and the reference encoder is
used otherwise, so this window works from a clean checkout of the
public repository with no proprietary component available.
"""

from __future__ import annotations

import os
import queue
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Optional

import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD

from app.components import (
    Caption,
    Divider,
    DropZone,
    GhostButton,
    InfoWindow,
    Label,
    MenuButton,
    OptionRow,
    PasswordDialog,
    PasswordField,
    PrimaryButton,
    ProgressPanel,
    QueueList,
    Tabs,
    asset_path,
    human_bytes,
)
from app.theme import C, SPACE, font
from core.codecs import AUTO, FAST

__all__ = ["CompaktWindow", "run"]

SLOGAN = "You deserve better compression."
MENU_ITEMS = ["Why use .pakt?", "How it works", "User Manual",
              "Settings", "About"]

#: Largest share of the window the content boxes may occupy.
#:
#: The window itself fills the screen; the BOXES do not. A drop zone
#: stretched to 1500px is a target you have to aim at rather than one
#: you can hit, and a queue that wide leaves each row mostly empty.
#: Past this share the surplus becomes margin instead.
BOX_SHARE = 0.5

#: The options column is a fixed measure -- it holds a known amount of
#: text and gains nothing from growing.
OPTIONS_WIDTH = 366

#: Below this the split stops making sense and the boxes simply take
#: what is left.
MIN_BOX_WIDTH = 400


def _load_packer():
    """
    Prefer the routing engine; fall back to the reference encoder.

    The public repository is self-sufficient by design. A missing
    engine means somewhat worse ratios, never a broken application.
    """
    try:
        from core.compressor import EngineOptions, pack as engine_pack

        def pack(sources, output, **kw):
            return engine_pack(sources, output, options=EngineOptions(
                level=kw.get("level", AUTO),
                reproducible=kw.get("reproducible", False),
                password=kw.get("password"),
                sign_key=kw.get("sign_key")))
        return pack, "routing engine"
    except Exception:
        from core.reference_encoder import pack as ref_pack

        def pack(sources, output, **kw):
            return ref_pack(sources, output,
                            level=kw.get("level", AUTO),
                            reproducible=kw.get("reproducible", False),
                            password=kw.get("password"),
                            sign_key=kw.get("sign_key"))
        return pack, "reference encoder"


@dataclass
class _Msg:
    kind: str                       # progress | item | done | error
    text: str = ""
    detail: str = ""
    fraction: float = 0.0
    rate: str = ""
    tone: str = "muted"


class CompaktWindow(ctk.CTk, TkinterDnD.DnDWrapper):
    """
    The main window.

    Composed from CustomTkinter's CTk and tkinterdnd2's DnDWrapper,
    because both want to be the root and only one can be. That
    composition was proved workable — including frozen — by
    ``spikes/dnd_spike.py`` before any of this was written.
    """

    def __init__(self) -> None:
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)

        self.title("Compakt")
        self.geometry("940x720")
        # The options column needs ~620px of its own, so a shorter
        # window would clip it. Better to refuse to get that small than
        # to hide controls.
        self.minsize(880, 780)
        self.configure(fg_color=C.ground)
        self._set_icon()

        self._pack_sources: list[str] = []
        self._unpack_targets: list[str] = []
        self._queue: "queue.Queue[_Msg]" = queue.Queue()
        self._busy = False
        self._syncing = False
        self._pack_fn, self._engine_name = _load_packer()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._gutter_rows: list = []
        self._build_header()
        self._build_tabs()
        self._build_status()
        self.bind("<Configure>", self._reflow)
        self.after(80, self._pump)

    def _reflow(self, event=None) -> None:
        """
        Size the content and centre it.

        The boxes take at most half the window. Whatever is left over
        after the boxes and the options column becomes an equal margin
        on each side, rather than a single gap on one edge -- symmetric
        margins read as a deliberate measure, one-sided space reads as
        a mistake.

        Runs on every resize because the split is proportional; the
        early return on an unchanged width keeps it from thrashing the
        geometry manager while a window is being dragged.
        """
        if event is not None and event.widget is not self:
            return
        width = self.winfo_width()
        if width <= 1:
            return

        usable = width - (2 * SPACE.page)
        box = int(usable * BOX_SHARE)
        # Never let the boxes crowd the options column off the edge.
        box = min(box, usable - OPTIONS_WIDTH - SPACE.xxl)
        box = max(box, MIN_BOX_WIDTH)

        content = box + SPACE.xxl + OPTIONS_WIDTH
        gutter = max(SPACE.page, (width - content) // 2)

        if (box, gutter) == getattr(self, "_metrics", None):
            return
        self._metrics = (box, gutter)
        self._box_width = box

        # The header, tabs and status bar share the content's measure,
        # so the whole window reads as one column rather than a centred
        # panel floating under a full-width header.
        for row in self._gutter_rows:
            row.grid_configure(padx=gutter)
        self._pack_tab.grid_columnconfigure(0, minsize=box)

    def _set_icon(self) -> None:
        """
        Give the window its own icon.

        Without this Windows falls back to the Python interpreter's
        icon, which is why an unexplained blue mark appeared in the
        title bar and the taskbar.
        """
        path = asset_path("compakt.ico")
        if not os.path.exists(path):
            return
        try:
            # `default=` sets the icon for the whole application, so
            # every Toplevel created later inherits it instead of
            # falling back to python.exe's. Windows does not propagate
            # a root window's icon to its children otherwise.
            self.iconbitmap(default=path)
        except Exception:
            pass
        try:
            self.iconbitmap(path)
        except Exception:
            pass

    # ---------------------------------------------------------------- chrome

    def _build_header(self) -> None:
        bar = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew",
                 padx=SPACE.page, pady=(SPACE.xl, 0))
        self._gutter_rows.append(bar)
        bar.grid_columnconfigure(2, weight=1)

        mark = self._load_mark()
        wordmark = ctk.CTkFrame(bar, corner_radius=0, fg_color="transparent")
        wordmark.grid(row=0, column=1, sticky="w")

        # The mark sits on the same row as the name, not centred against
        # the whole two-line block -- otherwise it floats between the
        # name and the slogan and lines up with neither.
        title = ctk.CTkFrame(wordmark, corner_radius=0,
                             fg_color="transparent")
        title.grid(row=0, column=0, sticky="w")
        if mark is not None:
            # Both are centred in the row, but a text label's box
            # includes ascender space the glyphs do not use, so a 34px
            # image centred against it rides a few pixels high.
            ctk.CTkLabel(title, image=mark, text="",
                         fg_color="transparent").grid(
                row=0, column=0, padx=(0, SPACE.md), pady=(5, 0))
        Label(title, "Compakt", size=27, weight="bold").grid(
            row=0, column=1, sticky="w")

        Label(wordmark, SLOGAN, size=12).grid(
            row=1, column=0, sticky="w", pady=(2, 0))

        MenuButton(bar, MENU_ITEMS, self._open_info).grid(
            row=0, column=3, sticky="e")

    def _load_mark(self):
        """
        The Kasanki Labs mark, shown beside the product name.

        The asset is pre-cropped to the artwork's own bounding box rather
        than being the studio's master file, which carries about half its
        canvas as empty padding -- drawn straight from that, a 34px box
        would hold roughly 17px of visible mark and the monogram inside
        the circle would not resolve at all.
        """
        try:
            from PIL import Image
            path = asset_path("kasanki-mark.png")
            if not os.path.exists(path):
                return None
            return ctk.CTkImage(Image.open(path), size=(34, 34))
        except Exception:
            # A missing mark must never stop the application starting.
            # Pillow being absent counts as missing: it was unpinned once
            # and the app ran for a whole build with no mark at all,
            # because this except swallowed the ImportError silently.
            return None

    def _build_tabs(self) -> None:
        self._tabs = Tabs(self, ["Pack Data", "Unpack Archive"],
                          on_change=lambda _n: None)
        self._tabs.grid(row=1, column=0, sticky="nsew",
                        padx=SPACE.page, pady=(SPACE.xl, 0))
        self._gutter_rows.append(self._tabs)
        self._build_pack_tab(self._tabs.tab("Pack Data"))
        self._build_unpack_tab(self._tabs.tab("Unpack Archive"))

    def _build_status(self) -> None:
        rule = Divider(self)
        rule.grid(row=2, column=0, sticky="ew",
                  padx=SPACE.page, pady=(SPACE.xl, 0))
        bar = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        bar.grid(row=3, column=0, sticky="ew",
                 padx=SPACE.page, pady=(SPACE.md, SPACE.lg))
        self._gutter_rows.extend([rule, bar])
        bar.grid_columnconfigure(0, weight=1)
        # No engine name here. "routing engine" is internal vocabulary
        # that tells a user nothing; it is available from `pakt formats`
        # for anyone who actually wants it.
        Label(bar, "Local only  ·  no network, no telemetry",
              size=11).grid(row=0, column=0, sticky="w")

    # -------------------------------------------------------------- pack tab

    def _build_pack_tab(self, tab) -> None:
        self._pack_tab = tab
        # Boxes, then options, then the spacer. The surplus belongs at
        # the outside edge -- putting it BETWEEN the two panels left a
        # 500px hole down the middle of the window and read as two
        # unrelated halves rather than one layout.
        tab.grid_columnconfigure(0, weight=0, minsize=MIN_BOX_WIDTH)
        tab.grid_columnconfigure(1, weight=1, minsize=OPTIONS_WIDTH)
        tab.grid_rowconfigure(1, weight=1)

        left = ctk.CTkFrame(tab, corner_radius=0, fg_color="transparent")
        left.grid(row=0, column=0, rowspan=2, sticky="nsew",
                  padx=(0, SPACE.xxl))
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(2, weight=1)

        self._pack_zone = DropZone(
            left, on_files=self._add_pack_sources,
            title="Drop files or folders",
            subtitle="or click to browse files")
        self._pack_zone.grid(row=0, column=0, sticky="ew")
        self._pack_zone.configure(height=158)
        self._pack_zone.grid_propagate(False)
        self._pack_zone.bind_drop_target(self._register_drop)

        head = ctk.CTkFrame(left, corner_radius=0, fg_color="transparent")
        head.grid(row=1, column=0, sticky="ew", pady=(SPACE.xl, SPACE.sm))
        head.grid_columnconfigure(0, weight=1)
        Caption(head, "Queue").grid(row=0, column=0, sticky="sw")
        GhostButton(head, "Clear", self._clear_pack, height=26,
                    width=64).grid(row=0, column=1, sticky="e")

        self._pack_queue = QueueList(left, empty_text="No sources selected",
                                     height=190)
        self._pack_queue.grid(row=2, column=0, sticky="nsew")

        # ---- options column ----
        column = ctk.CTkFrame(tab, corner_radius=0, fg_color="transparent")
        column.grid(row=0, column=1, rowspan=2, sticky="nsew")
        column.grid_columnconfigure(0, weight=1)
        column.grid_rowconfigure(0, weight=1)

        right = ctk.CTkFrame(column, corner_radius=0, fg_color="transparent")
        right.grid(row=0, column=0, sticky="new")
        right.grid_columnconfigure(0, weight=1)

        Caption(right, "Output").grid(row=0, column=0, sticky="ew")
        Label(right, "Compakt Archive", size=15, weight="bold").grid(
            row=1, column=0, sticky="ew", pady=(SPACE.xs, 0))
        Label(right, ".pakt", size=12, color=C.dim).grid(
            row=2, column=0, sticky="ew")
        ctk.CTkLabel(
            right, anchor="w", justify="left", wraplength=330, height=30,
            font=font(11), text_color=C.text, fg_color="transparent",
            text="Compakt unpacks zip, 7z, tar and more. "
                 "It packs .pakt only.").grid(
            row=3, column=0, sticky="ew", pady=(SPACE.xs, SPACE.md))

        # THE ONLY COMPRESSION CHOICE OFFERED, and deliberately the only
        # one. Which codec suits a block, how far back it should look and
        # how hard it should search are all measured per block, so there
        # is nothing there for a user to usefully decide. The one thing
        # measurement cannot settle is how much of their time we may
        # spend -- a 50 GB backup and a 10 MB folder want different
        # answers -- so that is the question the interface asks, and the
        # only one. A "maximum" setting used to exist; across nine
        # corpora it bought 0.5% for two to three times the time and came
        # out LARGER on two of them, so offering it would have been
        # offering a trap.
        self._opt_fast = OptionRow(
            right, text="Fast mode",
            note="Packs quicker. Archives come out slightly larger.",
            detail="Compakt normally measures each block of your data "
                   "and picks the best of three compressors for it, "
                   "sizing each one's search window to the block. That "
                   "is where the ratio comes from, and it costs "
                   "time.\n\n"
                   "Fast mode keeps all of that reasoning but tells each "
                   "compressor to search less hard. On a large backup it "
                   "is markedly quicker; the archive is a few percent "
                   "larger.\n\n"
                   "Leave it off unless you are packing something big "
                   "and waiting on it.")
        self._opt_fast.grid(row=4, column=0, sticky="ew", pady=(0, SPACE.md))

        self._opt_reproducible = OptionRow(
            right, text="Reproducible output",
            note="Identical input gives byte-identical archives.",
            disabled_note="Unavailable while encryption is on. A fixed "
                          "nonce would break AES-GCM.",
            command=self._sync_exclusive,
            detail="Timestamps are normalised and entries sorted, so the "
                   "same input always produces the same bytes \u2014 on any "
                   "machine, on any date. Useful in build pipelines, and "
                   "for proving two archives hold identical "
                   "contents.\n\n"
                   "Cannot be combined with encryption. That would "
                   "require a fixed AES-GCM nonce, and reusing one does "
                   "not weaken the cipher, it collapses it: an attacker "
                   "recovers the plaintext and can forge archives that "
                   "still verify.")
        self._opt_reproducible.grid(row=5, column=0, sticky="ew",
                                    pady=(0, SPACE.md))

        self._opt_sign = OptionRow(
            right, text="Sign archive",
            note="Ed25519. Generates a key and shows the public half.",
            detail="Signs the archive with a freshly generated Ed25519 "
                   "key and shows you the public half. Anyone holding "
                   "that public key can confirm the archive came from "
                   "you and has not been altered since.\n\n"
                   "The signature covers the index, and the index "
                   "carries a SHA-256 for every file \u2014 so verifying "
                   "it proves the contents too, not just the "
                   "listing.")
        self._opt_sign.grid(row=6, column=0, sticky="ew", pady=(0, SPACE.md))

        self._password = PasswordField(
            right, on_toggle=self._sync_exclusive,
            detail="Your password is stretched into a key with Argon2id, "
                   "which is memory-hard and therefore far more "
                   "expensive to attack than PBKDF2 \u2014 an attacker has "
                   "to buy memory rather than just more cores.\n\n"
                   "The archive is sealed with AES-256-GCM, and the file "
                   "listing is encrypted along with the contents, so "
                   "nobody can read your filenames without the "
                   "password. ZIP leaves that listing in the "
                   "clear.\n\n"
                   "There is no recovery if you forget it.")
        self._password.grid(row=7, column=0, sticky="ew", pady=(0, SPACE.sm))

        # Progress and the primary action stay OUTSIDE the scroll
        # region, pinned to the bottom. Having to scroll to find the
        # button that starts the job would be absurd.
        self._pack_progress = ProgressPanel(column)
        self._pack_progress.grid(row=1, column=0, sticky="ew",
                                 pady=(SPACE.md, SPACE.sm))

        self._pack_button = PrimaryButton(column, "Pack", self._start_pack,
                                          height=42)
        self._pack_button.grid(row=2, column=0, sticky="ew")

    def _sync_exclusive(self) -> None:
        """
        Reflect the format's own rule in the interface.

        ENCRYPTED and REPRODUCIBLE cannot both be set: byte-identical
        output would need a fixed GCM nonce, and reusing one does not
        weaken the cipher, it collapses it. Greying out is kinder than
        letting someone tick both and refusing the job afterwards.

        Guarded against reentrancy — each control's handler adjusts the
        other, so without this a single click can bounce indefinitely.
        """
        if self._syncing:
            return
        self._syncing = True
        try:
            encrypting = bool(self._password.enabled.get())
            reproducing = self._opt_reproducible.get()
            self._opt_reproducible.set_enabled(not encrypting)
            self._password.set_enabled(
                not reproducing,
                "Unavailable while reproducible output is on: a "
                "deterministic nonce would break AES-GCM."
                if reproducing else
                "Argon2id key derivation. The file listing is encrypted "
                "too, so nobody learns your filenames.")
        finally:
            self._syncing = False

    # ------------------------------------------------------------ unpack tab

    def _build_unpack_tab(self, tab) -> None:
        self._unpack_tab = tab
        tab.grid_columnconfigure(0, weight=1, minsize=MIN_BOX_WIDTH)
        tab.grid_rowconfigure(2, weight=1)

        self._unpack_zone = DropZone(
            tab, on_files=self._add_unpack_targets,
            title="Drop archives to unpack",
            subtitle="or click to browse files")
        self._unpack_zone.grid(row=0, column=0, sticky="ew")
        self._unpack_zone.configure(height=158)
        self._unpack_zone.grid_propagate(False)
        self._unpack_zone.bind_drop_target(self._register_drop)

        head = ctk.CTkFrame(tab, corner_radius=0, fg_color="transparent")
        head.grid(row=1, column=0, sticky="ew", pady=(SPACE.xl, SPACE.sm))
        head.grid_columnconfigure(0, weight=1)
        Caption(head, "Processing").grid(row=0, column=0, sticky="sw")
        GhostButton(head, "Clear", self._clear_unpack, height=26,
                    width=64).grid(row=0, column=1, sticky="e")

        self._unpack_queue = QueueList(tab, empty_text="No archives queued",
                                       height=190)
        self._unpack_queue.grid(row=2, column=0, sticky="nsew")

        foot = ctk.CTkFrame(tab, corner_radius=0, fg_color="transparent")
        foot.grid(row=3, column=0, sticky="ew", pady=(SPACE.xl, 0))
        foot.grid_columnconfigure(0, weight=1)

        self._unpack_progress = ProgressPanel(foot)
        self._unpack_progress.grid(row=0, column=0, sticky="ew",
                                   padx=(0, SPACE.xl))
        self._unpack_button = PrimaryButton(foot, "Unpack",
                                            self._start_unpack, height=40,
                                            width=170)
        self._unpack_button.grid(row=0, column=1, sticky="e")

    # --------------------------------------------------------- drag and drop

    def _register_drop(self, widget, on_drop, on_enter, on_leave) -> None:
        widget.drop_target_register(DND_FILES)
        widget.dnd_bind("<<Drop>>",
                        lambda e: on_drop(self._split_drop(e.data)))
        widget.dnd_bind("<<DropEnter>>", lambda _e: on_enter())
        widget.dnd_bind("<<DropLeave>>", lambda _e: on_leave())

    def _split_drop(self, data: str) -> list[str]:
        """Tk hands several dropped paths over as one brace-quoted string."""
        try:
            return [p for p in self.tk.splitlist(data) if p]
        except Exception:
            return [data] if data else []

    # ------------------------------------------------------------- queueing

    def _add_pack_sources(self, paths: list[str]) -> None:
        added = 0
        for p in paths:
            p = os.path.abspath(p)
            if not os.path.exists(p) or p in self._pack_sources:
                continue
            self._pack_sources.append(p)
            self._pack_queue.add(os.path.basename(p) or p,
                                 human_bytes(_tree_size(p)))
            added += 1
        if added:
            total = sum(_tree_size(p) for p in self._pack_sources)
            self._pack_zone.set_caption(
                f"{len(self._pack_sources)} selected",
                f"{human_bytes(total)}  ·  drop more, or press Pack")

    def _add_unpack_targets(self, paths: list[str]) -> None:
        from core.decompressor import UnsupportedArchive, identify
        for p in paths:
            p = os.path.abspath(p)
            if not os.path.isfile(p) or p in self._unpack_targets:
                continue
            try:
                info = identify(p)
            except UnsupportedArchive:
                self._unpack_queue.add(os.path.basename(p),
                                       "unsupported format", "bad")
                continue
            label = info.format + (" · encrypted" if info.encrypted else "")
            self._unpack_targets.append(p)
            self._unpack_queue.add(os.path.basename(p), label)
        if self._unpack_targets:
            self._unpack_zone.set_caption(
                f"{len(self._unpack_targets)} queued",
                "drop more, or press Unpack")

    def _clear_pack(self) -> None:
        if self._busy:
            return
        self._pack_sources.clear()
        self._pack_queue.clear()
        self._pack_zone.reset_caption()
        self._pack_progress.reset()

    def _clear_unpack(self) -> None:
        if self._busy:
            return
        self._unpack_targets.clear()
        self._unpack_queue.clear()
        self._unpack_zone.reset_caption()
        self._unpack_progress.reset()

    # ---------------------------------------------------------------- action

    def _start_pack(self) -> None:
        if self._busy:
            return
        if not self._pack_sources:
            self._pack_progress.update(status="Add something to pack first.",
                                       tone="warn")
            return

        password = self._password.value()
        if self._password.enabled.get() and not password:
            self._pack_progress.update(
                status="Encryption is on but no password was typed.",
                tone="warn")
            return

        from tkinter import filedialog
        default = os.path.basename(self._pack_sources[0]) or "archive"
        output = filedialog.asksaveasfilename(
            title="Save archive as", defaultextension=".pakt",
            initialfile=f"{default}.pakt",
            filetypes=[("Compakt archive", "*.pakt")])
        if not output:
            return

        sign_key = None
        if self._opt_sign.get():
            from core import crypto
            sign_key, public = crypto.generate_signing_key()
            self._pack_queue.add("signing key generated",
                                 public.hex()[:16] + "…", "good")

        self._set_busy(True)
        threading.Thread(
            target=self._pack_worker,
            args=(list(self._pack_sources), output, password,
                  self._opt_reproducible.get(), sign_key,
                  FAST if self._opt_fast.get() else AUTO),
            daemon=True).start()

    def _pack_worker(self, sources, output, password, reproducible,
                     sign_key, level) -> None:
        started = time.monotonic()
        try:
            self._queue.put(_Msg("progress", text="Scanning and hashing…",
                                 fraction=0.05))
            result = self._pack_fn(sources, output, password=password,
                                   reproducible=reproducible,
                                   sign_key=sign_key, level=level)
            elapsed = max(time.monotonic() - started, 1e-6)
            for item in result.items[:400]:
                if item.size:
                    self._queue.put(_Msg(
                        "item", text=item.path,
                        detail=("deduplicated" if item.deduped
                                else f"{human_bytes(item.size)} · "
                                     f"{item.codec.name.lower()}")))
            self._queue.put(_Msg(
                "done", text=result.summary(), detail=output,
                rate=human_bytes(result.total_input / elapsed) + "/s"))
        except Exception as exc:
            self._queue.put(_Msg("error", text=str(exc),
                                 detail=traceback.format_exc()))

    def _start_unpack(self) -> None:
        if self._busy:
            return
        if not self._unpack_targets:
            self._unpack_progress.update(status="Drop an archive first.",
                                         tone="warn")
            return
        from tkinter import filedialog
        dest = filedialog.askdirectory(title="Extract into")
        if not dest:
            return
        self._set_busy(True)
        threading.Thread(target=self._unpack_worker,
                         args=(list(self._unpack_targets), dest),
                         daemon=True).start()

    def _unpack_worker(self, targets, dest) -> None:
        from core.decompressor import extract, identify
        started = time.monotonic()
        total = 0
        try:
            for n, archive in enumerate(targets, 1):
                name = os.path.basename(archive)
                info = identify(archive)
                password = None

                if info.encrypted:
                    # Asked only because the archive said so.
                    password = self._ask_password(name, retry=False)
                    if password is None:
                        self._queue.put(_Msg("item", text=name,
                                             detail="skipped, no password",
                                             tone="warn"))
                        continue

                self._queue.put(_Msg("progress", text=f"Extracting {name}…",
                                     fraction=(n - 1) / len(targets)))
                out = os.path.join(dest, os.path.splitext(name)[0])

                attempts = 0
                while True:
                    try:
                        result = extract(archive, out, password=password)
                        break
                    except Exception as exc:
                        if _is_password_failure(exc) and attempts < 2:
                            attempts += 1
                            password = self._ask_password(name, retry=True)
                            if password is None:
                                raise
                            continue
                        raise

                total += result.bytes_written
                detail = (f"{result.entries_written} entries · "
                          f"{human_bytes(result.bytes_written)}")
                if result.skipped:
                    detail += f" · {len(result.skipped)} skipped"
                self._queue.put(_Msg("item", text=name, detail=detail,
                                     tone="good"))

            elapsed = max(time.monotonic() - started, 1e-6)
            self._queue.put(_Msg(
                "done", text=f"Extracted {len(targets)} archive(s)",
                detail=dest, rate=human_bytes(total / elapsed) + "/s"))
        except Exception as exc:
            self._queue.put(_Msg("error", text=str(exc),
                                 detail=traceback.format_exc()))

    def _ask_password(self, name: str, *, retry: bool) -> Optional[str]:
        """
        Prompt on the UI thread and block the worker until answered.

        Tk widgets may only be touched from the main thread, so the
        dialog is scheduled with `after` and the worker waits on an
        Event rather than constructing anything itself.
        """
        done = threading.Event()
        box: dict[str, Optional[str]] = {"value": None}

        def prompt() -> None:
            dialog = PasswordDialog(self, archive_name=name, retry=retry)
            self.wait_window(dialog)
            box["value"] = dialog.result
            done.set()

        self.after(0, prompt)
        done.wait()
        return box["value"]

    # ------------------------------------------------------------------ pump

    def _pump(self) -> None:
        """Drain worker messages on the Tk thread."""
        packing = self._tabs.get() == "Pack Data"
        try:
            while True:
                msg = self._queue.get_nowait()
                progress = (self._pack_progress if packing
                            else self._unpack_progress)
                listing = self._pack_queue if packing else self._unpack_queue

                if msg.kind == "progress":
                    progress.update(fraction=msg.fraction, status=msg.text)
                elif msg.kind == "item":
                    listing.add(msg.text, msg.detail, msg.tone)
                elif msg.kind == "done":
                    progress.update(fraction=1.0, status=msg.text,
                                    rate=msg.rate, tone="good")
                    listing.add(msg.detail, "written", "good")
                    self._set_busy(False)
                elif msg.kind == "error":
                    progress.update(fraction=0.0, status=msg.text, tone="bad")
                    listing.add(msg.text, "failed", "bad")
                    self._set_busy(False)
        except queue.Empty:
            pass
        self.after(80, self._pump)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        self._pack_button.configure(state=state,
                                    text="Packing…" if busy else "Pack")
        self._unpack_button.configure(state=state,
                                      text="Extracting…" if busy else "Unpack")

    # ------------------------------------------------------------------ menu

    def _open_info(self, choice: str) -> None:
        body = _INFO.get(choice)
        if body:
            InfoWindow(self, title=choice, body=body.strip())


def _tree_size(path: str) -> int:
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for base, _dirs, names in os.walk(path):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(base, n))
            except OSError:
                pass
    return total


def _is_password_failure(exc: Exception) -> bool:
    from core.crypto import WrongPassword
    if isinstance(exc, WrongPassword):
        return True
    text = str(exc).lower()
    return "password" in text or "passphrase" in text


_INFO = {
    "Settings": """
Compakt has no configuration file and no persistent settings, by design. Everything that changes behaviour sits on the Pack tab, where you can see it at the moment it applies.

There is nothing to configure about networking, because there is no networking.
""",
    "User Manual": """
# THE TERMINAL

Everything the window does, the pakt command does too.

pakt c notes/ report.pdf -o backup.pakt
pakt x backup.pakt -d restored/
pakt l backup.pakt

c creates, x extracts, l lists. There is also verify, explain, formats and keygen. Add -p to encrypt an archive or open an encrypted one -- it prompts for the password rather than taking it on the command line, where every other process on the machine could read it. Add --json to any read command for output a script can parse.

pakt --help lists everything.

If the shell reports that pakt is not found, the PATH option was cleared during installation. Run the installer again and leave "Add the pakt command to PATH" ticked.

# PACKING

Drop files or folders onto the Pack tab, or click to browse. Choose your options, press Pack, and pick where the .pakt file goes.

# Encrypt with AES-256-GCM

Seals the archive with a key derived from your password using Argon2id. The file listing is encrypted as well, so nobody can read your filenames without the password. There is no recovery if you forget it.

# Reproducible output

Identical input produces a byte-identical archive every time, on any machine. Useful for build pipelines, and for proving two archives hold the same thing.

This cannot be combined with encryption. Reproducibility needs a fixed nonce, and AES-GCM is destroyed by a reused one — so whichever you turn on greys out the other.

# Sign archive

Generates an Ed25519 key pair, signs the archive, and shows the public half. Anyone holding that public key can confirm the archive came from you and has not been altered since.

# UNPACKING

Drop any archive onto the Unpack tab. The format is identified from the file's contents rather than its name, so a .zip renamed to .txt still opens, and a file pretending to be an archive is refused instead of mangled.

If an archive is encrypted, Compakt asks for a password at that point, and only then.

Extraction refuses entries that would escape the destination folder, refuses symlinks unless you allow them, and stops rather than filling your disk if an archive expands implausibly.
""",
    "Why use .pakt?": """
# IT DECIDES BY MEASURING, NOT BY GUESSING

Every other archiver picks a compression method from the file extension. Compakt reads the bytes: magic numbers first, then entropy, printable ratio, line structure and delimiter regularity, with the extension consulted last and never allowed to overrule the content.

A database renamed to notes.txt is packed as a database. Already-compressed data with a misleading name is stored raw instead of being pointlessly recompressed and made bigger.

# IT COMPRESSES ACROSS FILES, NOT JUST WITHIN THEM

Files are grouped by type and compressed together in solid blocks, so repetition BETWEEN files is available to the codec rather than thrown away. On a folder of similar source files or logs this is the single largest win, and it is the reason .7z beats .zip.

Identical files are stored once. That costs nothing extra, because the hash needed to spot duplicates is already required for integrity checking.

# YOUR FILENAMES ARE NOT PUBLIC

This is the concrete thing .pakt does that ZIP cannot. Password-protected ZIP encrypts file contents and leaves the central directory in the clear, so anyone with the file can read every filename, folder path, size and timestamp without knowing the password.

.pakt encrypts the index itself. Without the password there is nothing to read — not the contents, not the listing.

# THE ENCRYPTION IS MODERN

Passwords are stretched with Argon2id, which is memory-hard: an attacker has to buy memory rather than simply add cores. PBKDF2, which most tools still use, parallelises cheaply on a GPU.

The archive is sealed with AES-256-GCM, which authenticates as well as encrypts. A tampered archive fails to open rather than quietly handing you altered data, and the tag is checked before a single byte reaches your disk.

# DAMAGE DOES NOT ALWAYS MEAN LOSS

The index is written at both ends of the file. Truncate the tail and the copy at the front survives; corrupt the front and the copy at the back does. Every block carries a CRC and every file a SHA-256, both verified on extraction, so corruption is reported rather than silently unpacked.

# ARCHIVES CAN BE REPRODUCIBLE AND SIGNED

The same input produces byte-identical output on any machine, on any date — useful in build pipelines, and for proving two archives hold the same thing. ZIP cannot do this because it embeds timestamps.

Archives can also be signed with Ed25519, so anyone holding your public key can confirm an archive came from you and has not been altered since.

# EXTRACTION IS DEFENSIVE BY DEFAULT

Archive tools are attacked through their extractors far more often than through their codecs. Compakt refuses entries that would escape the destination folder, refuses symlinks unless you allow them, never creates hardlinks or device nodes, and aborts rather than filling your disk if an archive expands implausibly.

Those rules apply to every format it opens, not only its own.

# THE FORMAT IS YOURS, NOT OURS

The .pakt specification and a reference decoder are published under Apache-2.0. Anyone may implement it, in any language, for any purpose, commercially or not, without asking permission.

Every archive you make stays readable by anyone, forever, whatever happens to this project. An archive format you cannot open without one particular vendor's software is a hostage, not a container.

# THERE IS NO VERSION 2 TO WAIT FOR

Everything the format will ever need structurally is defined in version 1.0, including space reserved for features not yet built. Archives written today will not be stranded by a later revision.

# WHAT IT DOES NOT DO

It does not write .rar — nobody can; RARLAB licenses no compressor.

It packs .pakt only, and opening one needs Compakt. Next to sending a zip that is a real limitation, and this page will not dress it up. An archive that also opened as a web page was considered and dropped: it would have produced a file shaped exactly like a known malware delivery technique, which is not a trade a security tool should make.

It will not always beat 7-Zip. Solid LZMA2 is very strong on large single files. Published benchmarks will show the losses alongside the wins, because a comparison that only reports wins is advertising.
""",
    "How it works": """
# MOST ARCHIVERS DECIDE BY FILENAME. COMPAKT MEASURES.

Every file is inspected before anything is compressed. Magic bytes first, then the content itself: entropy, printable ratio, line structure, delimiter regularity. The extension is consulted last, as a tiebreaker, and is never allowed to override what the bytes say.

A SQLite database renamed to notes.txt is packed as a database. Already-compressed data with a misleading name is stored raw rather than pointlessly recompressed.

# ROUTING

Prose and markup go to Brotli. Structured and tabular data go to Zstandard. Genomic data and executables go to LZMA. Anything already at maximum entropy is stored as-is, because compressing it again would only waste time and add bytes.

Files are then grouped by type and compressed together in solid blocks, so redundancy ACROSS files is available to the codec rather than thrown away. Identical files are stored once, which costs nothing, because the hash needed to spot them is already required for integrity.

# THE ARCHIVE

The index is written at both ends of the file, so damage to either end is survivable. Every block carries a CRC and every file a SHA-256, both verified on extraction. With a password set, the index itself is encrypted — unlike ZIP, which leaves every filename, path and size readable to anyone who has the file.

# LOCAL ONLY BABY

Compakt opens no sockets, sends no telemetry and has no update checker. Every library it uses is a pure codec: arithmetic on bytes.

You do not have to take that on trust. Block Compakt in your firewall and it behaves identically. Run it with the network unplugged. Watch it with a packet monitor. The claim is designed to be checked, which is the only kind of security claim worth making.
""",
    "About": """
Compakt
You deserve better compression.

* Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Open core. The .pakt format specification and reference decoder are Apache-2.0, so anyone may implement the format. The application is MPL-2.0. The compression routing engine and its trained dictionaries are proprietary.

Everything that could affect your safety is open and auditable: detection, extraction, the cryptography, and the socket guard. What is closed is the one file that decides which codec to call, which has no bearing on whether Compakt is trustworthy, or on your ability to read your own archives.
""",
}


def run() -> int:
    """Launch the application."""
    theme = asset_path("compakt-sharp.json")
    if os.path.exists(theme):
        ctk.set_default_color_theme(theme)
    ctk.set_appearance_mode("dark")
    CompaktWindow().mainloop()
    return 0
