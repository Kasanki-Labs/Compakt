"""
Interface components.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Built rather than borrowed, in the places where CustomTkinter's stock
controls look their age. Three in particular were replaced:

- **Tabs.** The stock segmented button inverts the active tab into a
  filled white pill, so the two tabs look like different kinds of
  object. These are flat text with a 2px underline on the active one:
  identical weight, one clear indicator.
- **The menu.** ``CTkOptionMenu`` is a dropdown widget wearing a menu's
  job, complete with an arrow block. Replaced with a plain icon button
  and a borderless popup.
- **The drop zone.** A 1px rectangle with ``[ + ]`` in it reads as a
  placeholder. This one is drawn on a canvas: real dashed strokes, a
  drawn glyph, and text positioned rather than packed.

Nothing here touches the filesystem or does any work. Widgets report
what the user did; the window decides what that means.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
from typing import Callable, Optional

import customtkinter as ctk

from app.theme import C, SPACE, font, tracked

__all__ = [
    "asset_path", "apply_icon", "human_bytes", "Tabs", "MenuButton",
    "DropZone",
    "QueueList", "OptionRow", "PasswordField", "ProgressPanel",
    "PasswordDialog", "InfoWindow", "Label", "PrimaryButton", "GhostButton",
    "Divider",
]


def apply_icon(window) -> None:
    """
    Give a Toplevel the Compakt icon.

    Windows does not pass the root window's icon to its children, so
    every dialog would otherwise show python.exe's. CustomTkinter also
    reconfigures the window shortly after creation, which undoes an
    icon set too early -- hence the deferred second attempt.
    """
    path = asset_path("compakt.ico")
    if not os.path.exists(path):
        return

    def _set():
        try:
            window.iconbitmap(path)
        except Exception:
            pass

    _set()
    try:
        window.after(220, _set)
    except Exception:
        pass


def asset_path(name: str) -> str:
    """Locate a bundled asset from source tree or frozen build."""
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "app", "assets", name)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------

def Label(master, text: str = "", *, size: int = 13, weight: str = "normal",
          color: str = C.text, lines: int = 1, **kw) -> ctk.CTkLabel:
    """
    A label sized to its text.

    CTkLabel defaults to a 28px box and requests 35px however small the
    type is, so a column of them accumulates a great deal of empty
    space. `lines` sets the height from the actual point size instead.
    """
    kw.setdefault("height", int(size * 1.45) * lines)
    return ctk.CTkLabel(master, text=text, font=font(size, weight),
                        text_color=color, fg_color="transparent",
                        anchor=kw.pop("anchor", "w"), **kw)


def Caption(master, text: str = "", **kw) -> ctk.CTkLabel:
    """A small tracked uppercase heading."""
    return ctk.CTkLabel(master, text=tracked(text), font=font(11, "bold"),
                        text_color=C.text, fg_color="transparent",
                        height=15, anchor="w", **kw)


def PrimaryButton(master, text: str, command, *, height: int = 38,
                  **kw) -> ctk.CTkButton:
    return ctk.CTkButton(master, text=text, command=command, height=height,
                         corner_radius=0, fg_color=C.accent,
                         hover_color="#E4E4E4", text_color=C.on_accent,
                         text_color_disabled=C.muted, border_width=0,
                         font=font(13, "bold"), **kw)


def GhostButton(master, text: str, command, *, height: int = 30,
                **kw) -> ctk.CTkButton:
    """Secondary action: a hairline outline, no fill until hover."""
    return ctk.CTkButton(master, text=text, command=command, height=height,
                         corner_radius=0, fg_color="transparent",
                         hover_color=C.raised, text_color=C.text,
                         border_width=1, border_color=C.edge,
                         font=font(12, "bold"), **kw)


def Divider(master, **kw) -> ctk.CTkFrame:
    return ctk.CTkFrame(master, height=1, corner_radius=0,
                        fg_color=C.hairline, **kw)


# --------------------------------------------------------------------------
# Tabs
# --------------------------------------------------------------------------

class Tabs(ctk.CTkFrame):
    """
    Flat tabs with an underline indicator.

    Both tabs are identical in weight and colour treatment; only the
    text brightness and a 2px rule below the active one differ. That is
    the whole point — a filled pill on one and a grey block on the other
    makes them look like two unrelated controls.
    """

    def __init__(self, master, names: list[str], *,
                 on_change: Optional[Callable[[str], None]] = None, **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        self._names = list(names)
        self._on_change = on_change
        self._active = self._names[0]
        self._buttons: dict[str, ctk.CTkButton] = {}
        self._rules: dict[str, ctk.CTkFrame] = {}
        self._panels: dict[str, ctk.CTkFrame] = {}

        strip = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        strip.grid(row=0, column=0, sticky="ew")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        for i, name in enumerate(self._names):
            cell = ctk.CTkFrame(strip, corner_radius=0, fg_color="transparent")
            cell.grid(row=0, column=i, sticky="w", padx=(0, SPACE.xl))
            # hover_color cannot be transparent, and a flat tab should
            # not grow a filled box on hover anyway. Matching the ground
            # makes the fill invisible; the feedback is the text colour,
            # handled below.
            btn = ctk.CTkButton(
                cell, text=tracked(name), width=1, height=30,
                corner_radius=0, fg_color="transparent",
                hover_color=C.ground, text_color=C.text,
                font=font(11, "bold"), border_width=0,
                command=lambda n=name: self.select(n))
            btn.grid(row=0, column=0, sticky="w")
            btn.bind("<Enter>", lambda _e, n=name: self._hover(n, True))
            btn.bind("<Leave>", lambda _e, n=name: self._hover(n, False))
            # A plain tk.Frame, not CTkFrame. CustomTkinter imposes its
            # own geometry on a frame and a 2px rule simply never
            # rendered, which is why the active tab had no underline.
            rule = tk.Frame(cell, height=3, bg=C.ground,
                            highlightthickness=0, bd=0)
            rule.grid(row=1, column=0, sticky="ew", pady=(7, 0))
            cell.grid_columnconfigure(0, weight=1)
            self._buttons[name] = btn
            self._rules[name] = rule

        Divider(self).grid(row=1, column=0, sticky="ew")

        self._body = ctk.CTkFrame(self, corner_radius=0,
                                  fg_color="transparent")
        self._body.grid(row=2, column=0, sticky="nsew", pady=(SPACE.xl, 0))
        self._body.grid_columnconfigure(0, weight=1)
        self._body.grid_rowconfigure(0, weight=1)

        for name in self._names:
            panel = ctk.CTkFrame(self._body, corner_radius=0,
                                 fg_color="transparent")
            panel.grid(row=0, column=0, sticky="nsew")
            self._panels[name] = panel

        self.select(self._active)

    def _hover(self, name: str, on: bool) -> None:
        # Both labels stay white; the underline alone marks the active
        # tab. Hover dims very slightly so the control still feels live.
        if name == self._active:
            return
        self._buttons[name].configure(text_color=C.accent if on else C.text)

    def tab(self, name: str) -> ctk.CTkFrame:
        return self._panels[name]

    def get(self) -> str:
        return self._active

    def select(self, name: str) -> None:
        self._active = name
        for other in self._names:
            active = other == name
            # Identical text colour on both. Only the rule moves.
            self._buttons[other].configure(text_color=C.text)
            self._rules[other].configure(
                bg=C.accent if active else C.ground)
        self._panels[name].tkraise()
        if self._on_change:
            self._on_change(name)

    # `set` mirrors CTkTabview so callers and tests read the same either way
    set = select


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

class MenuButton(ctk.CTkFrame):
    """
    An icon button that opens a borderless popup.

    A dropdown widget showing a selected value is the wrong metaphor for
    a menu — nothing here is "selected", these are actions.
    """

    def __init__(self, master, items: list[str],
                 on_choose: Callable[[str], None], **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        self._items = items
        self._on_choose = on_choose
        self._popup: Optional[tk.Toplevel] = None

        self._button = ctk.CTkButton(
            self, text="≡", width=46, height=40, corner_radius=0,
            fg_color="transparent", hover_color=C.raised,
            text_color=C.text, font=font(26), border_width=0,
            command=self.toggle)
        self._button.grid(row=0, column=0)

    def toggle(self) -> None:
        if self._popup is not None:
            self.close()
            return
        self.open()

    def open(self) -> None:
        root = self.winfo_toplevel()
        pop = tk.Toplevel(root)
        pop.overrideredirect(True)
        pop.configure(bg=C.hairline)
        pop.attributes("-topmost", True)

        inner = tk.Frame(pop, bg=C.surface, bd=0, highlightthickness=0)
        inner.pack(padx=1, pady=1)

        for name in self._items:
            row = tk.Label(inner, text=name, anchor="w", bg=C.surface,
                           fg=C.text, padx=SPACE.xl, pady=SPACE.md,
                           font=(font(12).cget("family"), 11, "bold"))
            row.pack(fill="x")
            row.bind("<Enter>", lambda _e, r=row: r.configure(bg=C.raised))
            row.bind("<Leave>", lambda _e, r=row: r.configure(bg=C.surface))
            row.bind("<Button-1>", lambda _e, n=name: self._choose(n))

        pop.update_idletasks()
        x = self._button.winfo_rootx() + self._button.winfo_width() \
            - pop.winfo_width()
        y = self._button.winfo_rooty() + self._button.winfo_height() + 4
        pop.geometry(f"+{x}+{y}")

        self._popup = pop
        self._button.configure(text_color=C.text)
        # Clicking anywhere else dismisses it, which is what a menu does.
        root.bind("<Button-1>", self._maybe_close, add="+")
        pop.bind("<Escape>", lambda _e: self.close())

    def _maybe_close(self, event) -> None:
        if self._popup is None:
            return
        if event.widget is self._button or str(event.widget).startswith(
                str(self._button)):
            return
        self.close()

    def _choose(self, name: str) -> None:
        self.close()
        self._on_choose(name)

    def close(self) -> None:
        if self._popup is not None:
            try:
                self._popup.destroy()
            except Exception:
                pass
            self._popup = None
        try:
            self._button.configure(text_color=C.text)
            self.winfo_toplevel().unbind("<Button-1>")
        except Exception:
            pass


# --------------------------------------------------------------------------
# Drop zone
# --------------------------------------------------------------------------

class DropZone(ctk.CTkFrame):
    """
    A drawn drop target.

    Everything is painted on a canvas: the dashed boundary, the glyph
    and the text. Tk's dash support gives a real dashed stroke rather
    than a solid 1px box pretending to be one, and drawing the text
    means it can be positioned precisely instead of packed into rows.
    """

    def __init__(self, master, *, on_files: Callable[[list[str]], None],
                 title: str, subtitle: str, **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        self._on_files = on_files
        self._title = self._current_title = title
        self._subtitle = self._current_subtitle = subtitle
        self._active = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._canvas = tk.Canvas(self, bg=C.ground, highlightthickness=0,
                                 bd=0, cursor="hand2")
        self._canvas.grid(row=0, column=0, sticky="nsew")
        self._canvas.bind("<Configure>", lambda _e: self._repaint())
        self._canvas.bind("<Button-1>", lambda _e: self._browse_files())
        self._canvas.bind("<Enter>", lambda _e: self._hover(True))
        self._canvas.bind("<Leave>", lambda _e: self._hover(False))
        self._hovering = False

    # -- painting ---------------------------------------------------------

    def _repaint(self) -> None:
        # NOT named _draw: CTkFrame defines its own
        # _draw(no_color_updates=...) and calls it
        # during construction, so shadowing it breaks
        # the widget before __init__ finishes.
        c = self._canvas
        c.delete("all")
        w = max(c.winfo_width(), 1)
        h = max(c.winfo_height(), 1)

        stroke = C.accent if self._active else (
            C.edge if not self._hovering else "#3E3E3E")
        fill = C.surface if (self._active or self._hovering) else C.ground

        c.create_rectangle(1, 1, w - 1, h - 1, fill=fill, outline="")
        c.create_rectangle(1, 1, w - 1, h - 1, outline=stroke, width=1,
                           dash=(4, 4))

        cx, cy = w / 2, h / 2
        glyph = C.accent
        # A drawn plus: two strokes, crisp at any size, no font needed.
        arm = 11
        c.create_line(cx - arm, cy - 30, cx + arm, cy - 30,
                      fill=glyph, width=2)
        c.create_line(cx, cy - 30 - arm, cx, cy - 30 + arm,
                      fill=glyph, width=2)

        family = font(13).cget("family")
        c.create_text(cx, cy + 4, text=self._current_title,
                      fill=C.text, font=(family, 13, "bold"))
        c.create_text(cx, cy + 25, text=self._current_subtitle,
                      fill=C.text, font=(family, 10))

    def _hover(self, on: bool) -> None:
        self._hovering = on
        self._repaint()

    # -- external wiring --------------------------------------------------

    def bind_drop_target(self, register: Callable) -> None:
        register(self._canvas, self._handle_drop, self._enter, self._leave)

    def _handle_drop(self, paths: list[str]) -> None:
        self._leave()
        if paths:
            self._on_files(paths)

    def _enter(self) -> None:
        self._active = True
        self._repaint()

    def _leave(self) -> None:
        self._active = False
        self._repaint()

    def _browse_files(self) -> None:
        """Cancel means cancel. Never chain into a second dialog."""
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(title="Choose files")
        if paths:
            self._on_files(list(paths))

    def _browse_folder(self) -> None:
        """
        Kept as an entry point, but nothing in the zone calls it.

        It had its own clickable text, which fired alongside the
        canvas-wide click binding and opened two dialogs from one
        press. Folders are added by dragging them in.
        """
        from tkinter import filedialog
        folder = filedialog.askdirectory(title="Choose a folder")
        if folder:
            self._on_files([folder])

    def set_caption(self, title: Optional[str] = None,
                    subtitle: Optional[str] = None) -> None:
        if title is not None:
            self._current_title = title
        if subtitle is not None:
            self._current_subtitle = subtitle
        self._repaint()

    def reset_caption(self) -> None:
        self.set_caption(self._title, self._subtitle)


# --------------------------------------------------------------------------
# Queue
# --------------------------------------------------------------------------

class QueueList(ctk.CTkScrollableFrame):
    """Rows on a raised surface, separated by space rather than lines."""

    def __init__(self, master, *, empty_text: str = "Nothing queued.", **kw):
        super().__init__(master, corner_radius=0, fg_color=C.surface,
                         scrollbar_button_color=C.edge,
                         scrollbar_button_hover_color=C.muted, **kw)
        self.grid_columnconfigure(0, weight=1)
        self._rows: list[ctk.CTkFrame] = []
        self._empty = Label(self, empty_text, size=12, weight="bold",
                            color=C.text, anchor="center")
        self._empty.grid(row=0, column=0, pady=SPACE.xl, sticky="ew")

    def clear(self) -> None:
        for row in self._rows:
            row.destroy()
        self._rows.clear()
        self._empty.grid(row=0, column=0, pady=SPACE.xl, sticky="ew")

    def add(self, primary: str, secondary: str = "",
            tone: str = "text") -> None:
        self._empty.grid_forget()
        row = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent",
                           height=26)
        row.grid(row=len(self._rows), column=0, sticky="ew")
        row.grid_columnconfigure(0, weight=1)

        color = {"text": C.text, "muted": C.text, "good": C.good,
                 "warn": C.warn, "bad": C.bad}.get(tone, C.text)
        Label(row, primary, size=12, weight="bold", color=color).grid(
            row=0, column=0, sticky="ew", padx=(SPACE.md, SPACE.sm),
            pady=SPACE.xs)
        if secondary:
            Label(row, secondary, size=11, weight="bold", color=C.text,
                  anchor="e").grid(
                row=0, column=1, sticky="e", padx=(0, SPACE.md))
        self._rows.append(row)
        self._scroll_to_end()

    def _scroll_to_end(self) -> None:
        try:
            self.update_idletasks()
            self._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def __len__(self) -> int:
        return len(self._rows)


# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------

class InfoDot(ctk.CTkFrame):
    """
    A small circled `i` that reveals a fuller explanation on hover.

    The one-line note under each option says WHAT the setting does.
    This says why it matters, and what it costs -- the material that
    would clutter the panel if it were always on screen, but which a
    user deciding whether to tick something actually wants.

    The glyph is drawn rather than typed. A circled-i character exists
    in Unicode but renders differently on every machine and is missing
    from some faces entirely; two canvas primitives look the same
    everywhere.
    """

    #: Offset from the icon to the bubble's top-left corner. Deliberately
    #: clear of the pointer: a bubble under the cursor would swallow the
    #: <Leave> event and then never close.
    _OFFSET = (18, 14)

    def __init__(self, master, text: str, *, width: int = 420, **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        self._text = text
        self._width = width
        self._bubble = None

        self._canvas = tk.Canvas(self, width=15, height=15, bd=0,
                                 highlightthickness=0, bg=C.ground,
                                 cursor="hand2")
        self._canvas.grid(row=0, column=0)
        self._paint(C.muted)

        for seq, fn in (("<Enter>", self._show), ("<Leave>", self._hide),
                        ("<Button-1>", self._toggle)):
            self._canvas.bind(seq, fn)

    def _paint(self, colour: str) -> None:
        c = self._canvas
        c.delete("all")
        c.create_oval(1, 1, 13, 13, outline=colour, width=1)
        c.create_text(7, 7, text="i", fill=colour,
                      font=(font(11).cget("family"), 8, "bold"))

    # -- bubble ----------------------------------------------------------

    def _show(self, _event=None) -> None:
        if self._bubble is not None:
            return
        self._paint(C.text)

        tip = tk.Toplevel(self)
        tip.overrideredirect(True)
        tip.configure(bg=C.edge)
        try:
            tip.attributes("-topmost", True)
        except Exception:
            pass

        inner = tk.Frame(tip, bg=C.surface, bd=0, highlightthickness=0)
        inner.pack(padx=1, pady=1)
        tk.Label(inner, text=self._text, bg=C.surface, fg=C.text,
                 justify="left", anchor="w", wraplength=self._width,
                 font=(font(11).cget("family"), 12),
                 padx=SPACE.lg, pady=SPACE.md).pack()

        tip.update_idletasks()
        x = self._canvas.winfo_rootx() + self._OFFSET[0]
        y = self._canvas.winfo_rooty() + self._OFFSET[1]

        # Keep it on screen: flip left or upward at the edges rather
        # than letting the text run off the display.
        if x + tip.winfo_width() > self.winfo_screenwidth() - 8:
            x = self._canvas.winfo_rootx() - tip.winfo_width() - 8
        if y + tip.winfo_height() > self.winfo_screenheight() - 8:
            y = self._canvas.winfo_rooty() - tip.winfo_height() - 8

        tip.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self._bubble = tip

    def _hide(self, _event=None) -> None:
        self._paint(C.muted)
        if self._bubble is not None:
            try:
                self._bubble.destroy()
            except Exception:
                pass
            self._bubble = None

    def _toggle(self, _event=None) -> None:
        self._hide() if self._bubble is not None else self._show()

    def destroy(self) -> None:
        self._hide()
        super().destroy()


class OptionRow(ctk.CTkFrame):
    """A checkbox with a note beneath it."""

    def __init__(self, master, *, text: str, note: str,
                 command: Optional[Callable] = None,
                 enabled: bool = True, disabled_note: str = "",
                 detail: str = "", **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        self.grid_columnconfigure(1, weight=1)

        self.variable = ctk.BooleanVar(value=False)
        self.checkbox = ctk.CTkCheckBox(
            self, text=text, variable=self.variable, corner_radius=0,
            height=20, checkbox_width=16, checkbox_height=16, border_width=1,
            border_color=C.edge, hover_color=C.accent, fg_color=C.accent,
            checkmark_color=C.on_accent, text_color=C.text,
            text_color_disabled=C.faint, font=font(13, "bold"),
            command=command)
        self.checkbox.grid(row=0, column=0, sticky="w")
        if detail:
            InfoDot(self, detail).grid(row=0, column=1, sticky="w",
                                       padx=(SPACE.sm, 0))

        # Descriptive text stays regular weight. Bold is reserved for
        # headings and labels, so that emphasis still means something.
        # Two lines of headroom: the longest notes wrap once at this
        # measure, and a clipped explanation is worse than a little air.
        self._note = ctk.CTkLabel(self, text=note, anchor="w", justify="left",
                                  font=font(11), text_color=C.text, height=32,
                                  fg_color="transparent", wraplength=320)
        self._note.grid(row=1, column=0, columnspan=2, sticky="ew",
                        padx=(SPACE.xl, 0), pady=(2, 0))

        self._enabled_note = note
        self._disabled_note = disabled_note or note
        if not enabled:
            self.set_enabled(False)

    def set_enabled(self, enabled: bool) -> None:
        self.checkbox.configure(state="normal" if enabled else "disabled")
        self._note.configure(
            text=self._enabled_note if enabled else self._disabled_note,
            text_color=C.text if enabled else C.faint)
        if not enabled:
            self.variable.set(False)

    def get(self) -> bool:
        return bool(self.variable.get())


class PasswordField(ctk.CTkFrame):
    """Enable-checkbox, entry, and a reveal toggle."""

    def __init__(self, master, *, on_toggle: Optional[Callable] = None,
                 detail: str = "", **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        # The entry takes the slack; the reveal button is a fixed
        # measure. Without an explicit minsize on column 1 the button
        # was being drawn over the entry's right edge.
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0, minsize=66)
        self._on_toggle = on_toggle

        self.enabled = ctk.BooleanVar(value=False)

        # The checkbox is built as a child of `holder`, not gridded into
        # it with `in_`. Managing a widget from a container that is not
        # its parent is legal Tk and behaves unpredictably -- here it
        # made the label disappear entirely.
        holder = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        holder.grid(row=0, column=0, columnspan=2, sticky="w")

        self._check = ctk.CTkCheckBox(
            holder, text="Encrypt with AES-256-GCM", variable=self.enabled,
            corner_radius=0, height=20, checkbox_width=16, checkbox_height=16,
            border_width=1, border_color=C.edge, fg_color=C.accent,
            hover_color=C.accent, checkmark_color=C.on_accent,
            text_color=C.text, text_color_disabled=C.faint,
            font=font(13, "bold"), command=self._changed)
        self._check.grid(row=0, column=0, sticky="w")
        if detail:
            InfoDot(holder, detail).grid(row=0, column=1, sticky="w",
                                         padx=(SPACE.sm, 0))

        self._entry = ctk.CTkEntry(
            self, placeholder_text="Password", show="•",
            corner_radius=0, height=32, border_width=1, border_color=C.edge,
            fg_color=C.raised, text_color=C.text,
            placeholder_text_color=C.muted, font=font(12), state="disabled")
        self._entry.grid(row=1, column=0, sticky="ew",
                         pady=(SPACE.sm, 0), padx=(SPACE.xl, SPACE.xs))

        self._reveal = GhostButton(self, "Show", self._toggle_reveal,
                                   height=32, width=62)
        self._reveal.configure(state="disabled")
        self._reveal.grid(row=1, column=1, sticky="ew", pady=(SPACE.sm, 0))

        self._note = ctk.CTkLabel(
            self, anchor="w", justify="left", font=font(11), height=32,
            text_color=C.text, fg_color="transparent", wraplength=320,
            text="Argon2id key derivation. The file listing is encrypted "
                 "too, so nobody learns your filenames.")
        self._note.grid(row=2, column=0, columnspan=2, sticky="ew",
                        padx=(SPACE.xl, 0), pady=(SPACE.sm, 0))

    def _changed(self, *, notify: bool = True) -> None:
        on = bool(self.enabled.get())
        self._entry.configure(state="normal" if on else "disabled")
        self._reveal.configure(state="normal" if on else "disabled")
        if not on:
            self._entry.delete(0, "end")
        # A programmatic change must not fire the user-action callback:
        # the window's handler calls back into set_enabled, and notifying
        # here recurses without end.
        if notify and self._on_toggle:
            self._on_toggle()

    def _toggle_reveal(self) -> None:
        hidden = self._entry.cget("show") != ""
        self._entry.configure(show="" if hidden else "•")
        self._reveal.configure(text="Hide" if hidden else "Show")

    def set_enabled(self, enabled: bool, reason: str = "") -> None:
        """Programmatic enable/disable. Never notifies; see _changed."""
        self._check.configure(state="normal" if enabled else "disabled")
        if not enabled and self.enabled.get():
            self.enabled.set(False)
            self._changed(notify=False)
        if reason:
            self._note.configure(
                text=reason, text_color=C.warn if not enabled else C.text)

    def value(self) -> Optional[str]:
        if not self.enabled.get():
            return None
        return self._entry.get() or None


# --------------------------------------------------------------------------
# Progress
# --------------------------------------------------------------------------

class ProgressPanel(ctk.CTkFrame):
    """A thin bar with a status line and a throughput reading."""

    def __init__(self, master, **kw):
        super().__init__(master, corner_radius=0, fg_color="transparent", **kw)
        self.grid_columnconfigure(0, weight=1)

        self._bar = ctk.CTkProgressBar(self, corner_radius=0, height=3,
                                       fg_color=C.raised,
                                       progress_color=C.accent,
                                       border_width=0)
        self._bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        self._bar.set(0)

        self._status = Label(self, "Ready", size=12, weight="bold")
        self._status.grid(row=1, column=0, sticky="ew", pady=(SPACE.sm, 0))

        self._rate = Label(self, "", size=12, weight="bold", color=C.text,
                           anchor="e")
        self._rate.grid(row=1, column=1, sticky="e", pady=(SPACE.sm, 0))

    def reset(self, status: str = "Ready") -> None:
        self._bar.set(0)
        self._status.configure(text=status, text_color=C.text)
        self._rate.configure(text="")

    def update(self, *, fraction: Optional[float] = None,
               status: Optional[str] = None, rate: Optional[str] = None,
               tone: str = "muted") -> None:
        if fraction is not None:
            self._bar.set(max(0.0, min(1.0, fraction)))
        if status is not None:
            color = {"muted": C.text, "text": C.text, "good": C.good,
                     "warn": C.warn, "bad": C.bad}.get(tone, C.muted)
            self._status.configure(text=status, text_color=color)
        if rate is not None:
            self._rate.configure(text=rate)


# --------------------------------------------------------------------------
# Dialogs
# --------------------------------------------------------------------------

class PasswordDialog(ctk.CTkToplevel):
    """Raised only when an archive's header signals encryption."""

    def __init__(self, master, *, archive_name: str, retry: bool = False):
        super().__init__(master)
        self.title("Password required")
        self.geometry("420x224")
        self.resizable(False, False)
        self.configure(fg_color=C.ground)
        self.result: Optional[str] = None
        self.grid_columnconfigure(0, weight=1)

        Label(self, "This archive is encrypted", size=15, weight="bold").grid(
            row=0, column=0, padx=SPACE.xl, pady=(SPACE.xl, 2), sticky="ew")
        Label(self, archive_name, size=12, weight="bold").grid(
            row=1, column=0, padx=SPACE.xl, sticky="ew")

        self._entry = ctk.CTkEntry(
            self, placeholder_text="Password", show="•", corner_radius=0,
            height=34, border_width=1, border_color=C.edge, fg_color=C.raised,
            text_color=C.text, placeholder_text_color=C.muted, font=font(12))
        self._entry.grid(row=2, column=0, padx=SPACE.xl,
                         pady=(SPACE.lg, SPACE.xs), sticky="ew")
        self._entry.bind("<Return>", lambda _e: self._accept())

        ctk.CTkLabel(
            self, anchor="w", justify="left", font=font(10),
            fg_color="transparent", wraplength=372,
            text_color=C.bad if retry else C.text,
            text=("That password did not work. Note this is also what a "
                  "modified archive looks like." if retry else
                  "The file listing is encrypted too, so nothing can be "
                  "shown until this is correct.")).grid(
            row=3, column=0, padx=SPACE.xl, sticky="ew")

        buttons = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        buttons.grid(row=4, column=0, padx=SPACE.xl,
                     pady=(SPACE.lg, SPACE.xl), sticky="e")
        GhostButton(buttons, "Cancel", self._cancel, height=32,
                    width=88).pack(side="left", padx=(0, SPACE.sm))
        PrimaryButton(buttons, "Unlock", self._accept, height=32,
                      width=88).pack(side="left")

        self.transient(master)
        apply_icon(self)
        self.after(60, self._grab)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _grab(self) -> None:
        try:
            self.grab_set()
            self._entry.focus_set()
        except Exception:
            pass

    def _accept(self) -> None:
        self.result = self._entry.get() or None
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


class InfoWindow(ctk.CTkToplevel):
    """Settings, manual and explanatory text."""

    def __init__(self, master, *, title: str, body: str):
        super().__init__(master)
        self.title(title)
        self.geometry("660x560")
        self.configure(fg_color=C.ground)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        Label(self, title, size=18, weight="bold").grid(
            row=0, column=0, padx=SPACE.page, pady=(SPACE.xl, SPACE.md),
            sticky="ew")
        Divider(self).grid(row=1, column=0, padx=SPACE.page, sticky="ew")

        wrap = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        wrap.grid(row=2, column=0, padx=SPACE.page,
                  pady=(SPACE.lg, SPACE.xl), sticky="nsew")
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)

        family = font(13).cget("family")
        box = tk.Text(wrap, wrap="word", bd=0, highlightthickness=0,
                      bg=C.ground, fg=C.text, font=(family, 11),
                      padx=0, pady=0, spacing1=2, spacing3=4,
                      insertwidth=0, cursor="arrow")
        box.grid(row=0, column=0, sticky="nsew")

        bar = ctk.CTkScrollbar(wrap, command=box.yview, corner_radius=0,
                               button_color=C.edge,
                               button_hover_color=C.muted,
                               fg_color="transparent", width=10)
        bar.grid(row=0, column=1, sticky="ns", padx=(SPACE.sm, 0))
        box.configure(yscrollcommand=bar.set)

        self._render(box, body, family)
        box.configure(state="disabled")
        self.textbox = box

        self.transient(master)
        apply_icon(self)

    @staticmethod
    def _render(box, body: str, family: str) -> None:
        """
        Write the body, bolding anything marked as a heading.

        Markers are explicit -- `#` for a section heading, `*` for a
        single emphasised line -- rather than inferred from shape. A
        rule like "all-caps means heading" holds until a sentence
        legitimately shouts, and then silently mis-styles it.
        """
        box.tag_config("heading", font=(family, 12, "bold"),
                       spacing1=10, spacing3=4)
        box.tag_config("strong", font=(family, 11, "bold"))

        for raw in body.strip().splitlines():
            line = raw.rstrip()
            marker = line[:2]
            if marker in ("# ", "* "):
                start = box.index("end-1c")
                box.insert("end", line[2:] + "\n")
                box.tag_add("heading" if marker == "# " else "strong",
                            start, box.index("end-1c"))
            else:
                box.insert("end", line + "\n")
