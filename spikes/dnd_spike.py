"""
Risk-reduction spike: CustomTkinter + tkinterdnd2 + PyInstaller.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

WHY THIS EXISTS
---------------
Drag-and-drop is central to both tabs of the Compakt UI, and the
CustomTkinter + tkinterdnd2 combination is known to be awkward in two
specific ways:

  1. tkinterdnd2 wants ``TkinterDnD.Tk`` as the root window.
     CustomTkinter wants ``customtkinter.CTk``. They cannot both be
     the root, so the two have to be composed by hand.

  2. tkdnd is a native Tcl extension shipped as loose binaries inside
     the tkinterdnd2 package. PyInstaller does not necessarily collect
     them, which produces the classic failure: works perfectly from
     source, dies the moment it is frozen.

Failure (2) would normally be discovered at packaging time, with the
entire GUI already built on top of the assumption that it works. This
spike surfaces both failures in about an hour instead.

USAGE
-----
    python spikes/dnd_spike.py --selftest    # headless, exits 0 or 1
    python spikes/dnd_spike.py               # interactive window

The self-test is what matters: it runs identically from source and
from a frozen binary, so the frozen build can be checked automatically
rather than by dragging a file onto a window by hand.
"""

from __future__ import annotations

import sys
import os
import traceback

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, fn):
    """Run one probe, record pass/fail, never raise."""
    try:
        detail = fn()
        RESULTS.append((name, True, detail or ""))
        return True
    except Exception as exc:
        RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        return False


def theme_path() -> str:
    """Locate the theme asset from source tree or frozen bundle."""
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "app", "assets", "compakt-sharp.json")


def build_root():
    """
    Compose CustomTkinter's CTk with tkinterdnd2's DnDWrapper.

    This is the load-bearing part of the whole spike. CTk provides the
    themed window; DnDWrapper provides drop_target_register and
    friends. TkinterDnD._require() is what actually loads the native
    tkdnd Tcl package into this interpreter, and it is the call that
    fails in a frozen build when the binaries were not collected.
    """
    import customtkinter as ctk
    from tkinterdnd2 import TkinterDnD

    class CompaktRoot(ctk.CTk, TkinterDnD.DnDWrapper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)

    return ctk, CompaktRoot


def selftest() -> int:
    ctk = None
    CompaktRoot = None
    root = None

    def _imports():
        nonlocal ctk, CompaktRoot
        ctk, CompaktRoot = build_root()
        import customtkinter
        return f"customtkinter {customtkinter.__version__}"

    if not check("import customtkinter + tkinterdnd2", _imports):
        return report()

    def _theme():
        p = theme_path()
        if not os.path.exists(p):
            raise FileNotFoundError(p)
        ctk.set_default_color_theme(p)
        ctk.set_appearance_mode("dark")
        return os.path.basename(p)

    check("load sharp theme", _theme)

    def _root():
        nonlocal root
        root = CompaktRoot()
        root.withdraw()          # never flash a window during the test
        return f"tkdnd {root.TkdndVersion}"

    if not check("construct CTk + DnDWrapper root", _root):
        return report()

    def _register():
        from tkinterdnd2 import DND_FILES
        frame = ctk.CTkFrame(root, corner_radius=0)
        frame.pack()
        frame.drop_target_register(DND_FILES)
        frame.dnd_bind("<<Drop>>", lambda e: None)
        return "DND_FILES registered on a CTkFrame"

    check("register drop target on a CTk widget", _register)

    def _sharp():
        btn = ctk.CTkButton(root, text="x")
        r = btn.cget("corner_radius")
        if r != 0:
            raise AssertionError(f"corner_radius is {r}, expected 0")
        return "CTkButton corner_radius=0 from theme"

    check("sharp edges applied globally", _sharp)

    try:
        if root is not None:
            root.destroy()
    except Exception:
        pass

    return report()


def report() -> int:
    mode = "FROZEN" if getattr(sys, "frozen", False) else "SOURCE"
    print(f"--- dnd spike self-test [{mode}] ---")
    failed = 0
    for name, ok, detail in RESULTS:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        if not ok:
            failed += 1
    print(f"--- {len(RESULTS) - failed}/{len(RESULTS)} passed ---")
    return 1 if failed else 0


def interactive() -> int:
    ctk, CompaktRoot = build_root()
    from tkinterdnd2 import DND_FILES

    ctk.set_default_color_theme(theme_path())
    ctk.set_appearance_mode("dark")

    root = CompaktRoot()
    root.title("Compakt - drag and drop spike")
    root.geometry("520x300")

    ctk.CTkLabel(root, text="Compakt", font=("Segoe UI", 22, "bold")).pack(pady=(24, 0))
    ctk.CTkLabel(root, text="You deserve better compression.",
                 text_color="#6E6E6E").pack(pady=(0, 18))

    zone = ctk.CTkFrame(root, corner_radius=0, border_width=1, height=120)
    zone.pack(fill="both", expand=True, padx=24, pady=(0, 12))
    zone.pack_propagate(False)

    label = ctk.CTkLabel(zone, text="drop files or folders here")
    label.pack(expand=True)

    def on_drop(event):
        items = root.tk.splitlist(event.data)
        label.configure(text="\n".join(os.path.basename(i) for i in items[:6])
                        or "(nothing)")
        print(f"dropped {len(items)} item(s):")
        for i in items:
            print("   ", i)

    zone.drop_target_register(DND_FILES)
    zone.dnd_bind("<<Drop>>", on_drop)

    ctk.CTkLabel(root, text=f"tkdnd {root.TkdndVersion}",
                 text_color="#6E6E6E").pack(pady=(0, 12))

    root.mainloop()
    return 0


if __name__ == "__main__":
    try:
        if "--selftest" in sys.argv:
            sys.exit(selftest())
        sys.exit(interactive())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
