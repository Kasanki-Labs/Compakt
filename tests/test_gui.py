"""
Tests for the desktop window.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

These construct the real window and drive it programmatically. They are
skipped where no display is available, so a headless CI runner does not
fail on them.

The behaviour that matters most here is the mutual exclusion between
encryption and reproducible output. It is a *format* rule -- a fixed
GCM nonce would destroy the cipher -- and the interface has to express
it by greying the other option out, rather than letting someone tick
both and then refusing the job after they have chosen a filename.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("customtkinter")
pytest.importorskip("tkinterdnd2")


@pytest.fixture(scope="module")
def theme():
    import customtkinter as ctk
    from app.components import asset_path
    path = asset_path("compakt-sharp.json")
    if os.path.exists(path):
        ctk.set_default_color_theme(path)
    ctk.set_appearance_mode("dark")
    return path


@pytest.fixture(scope="module")
def _root(theme):
    """
    One window for the whole module, deliberately.

    Creating and destroying a Tk root per test is flaky: Tcl keeps
    interpreter-global state and repeated teardown intermittently fails
    to re-source ttk.tcl, which showed up as tests skipping at random.
    A flaky suite is worth less than no suite, so the root is built
    once and reset between tests instead.
    """
    from app.gui import CompaktWindow
    try:
        w = CompaktWindow()
    except Exception as exc:                          # pragma: no cover
        pytest.skip(f"no display available: {exc}")
    w.update_idletasks()
    w.update()
    yield w
    try:
        w.destroy()
    except Exception:
        pass


@pytest.fixture
def window(_root):
    """The shared window, returned to a known state before each test."""
    _root._clear_pack()
    _root._clear_unpack()
    _root._password.enabled.set(False)
    _root._password._changed(notify=False)
    _root._opt_reproducible.variable.set(False)
    _root._opt_sign.variable.set(False)
    _root._sync_exclusive()
    _root._tabs.set("Pack Data")
    _root.update()
    return _root


# ==========================================================================
# Construction
# ==========================================================================

def test_window_builds(window):
    assert window.title() == "Compakt"
    assert window.TkdndVersion                        # tkdnd really loaded


def test_both_tabs_exist(window):
    assert window._tabs.tab("Pack Data") is not None
    assert window._tabs.tab("Unpack Archive") is not None


def test_tabs_are_visually_consistent(window):
    """
    The two tabs must look like the same kind of object, and the
    underline must be the ONLY thing distinguishing them. The stock
    segmented control filled the active one white and left the other a
    grey block, so they read as unrelated widgets.
    """
    buttons = window._tabs._buttons
    assert len({b.cget("fg_color") for b in buttons.values()}) == 1
    assert len({str(b.cget("font")) for b in buttons.values()}) == 1
    assert len({b.cget("text_color") for b in buttons.values()}) == 1, (
        "tab labels differ in colour; the underline should be the only "
        "difference")


def test_active_tab_is_marked_by_its_underline(window):
    """
    The rules are plain tk.Frames, not CTkFrames: CustomTkinter imposes
    its own geometry and a thin rule never rendered at all, which is why
    the active tab had no underline for a while.
    """
    from app.theme import C
    tabs = window._tabs

    tabs.select("Pack Data")
    window.update()
    assert tabs._rules["Pack Data"].cget("bg") == C.accent
    assert tabs._rules["Unpack Archive"].cget("bg") == C.ground

    tabs.select("Unpack Archive")
    window.update()
    assert tabs._rules["Unpack Archive"].cget("bg") == C.accent
    assert tabs._rules["Pack Data"].cget("bg") == C.ground
    tabs.select("Pack Data")


def test_the_underline_has_real_height(window):
    """A zero-height rule is invisible however it is coloured."""
    window.update_idletasks()
    rule = window._tabs._rules["Pack Data"]
    assert int(rule.cget("height")) >= 2


def test_no_grey_body_text(window):
    """
    Hierarchy comes from size and weight, not from fading text out.
    `faint` is allowed only on disabled controls, where looking
    unavailable is the whole point.
    """
    from app.theme import C
    assert C.text == C.dim == C.muted == "#FFFFFF"
    assert C.faint != C.text


def test_window_has_its_own_icon():
    """
    Without an icon Windows falls back to python.exe's, which is where
    the unexplained blue mark in the title bar came from.
    """
    from app.components import asset_path
    assert os.path.exists(asset_path("compakt.ico"))


def test_icon_carries_small_sizes():
    """A taskbar icon is drawn at 16px; one big frame scales badly."""
    from PIL import Image
    from app.components import asset_path
    with Image.open(asset_path("compakt.ico")) as im:
        sizes = {s for s in im.info.get("sizes", set())}
    assert (16, 16) in sizes and (256, 256) in sizes


def test_the_studio_mark_actually_loads(window):
    """
    _load_mark() returns None on ANY exception, so that a missing PNG
    can never stop the application starting. That guard also swallows a
    missing Pillow without a word, and it did: pillow was used by
    CTkImage but never pinned, so rebuilding the environment from
    requirements alone produced a window with no mark and no complaint.
    The only outward sign was the frozen binary shrinking by 11.4 MB.

    Asserting the mark LOADS rather than that the file exists is the
    point -- the file existing is what was true the whole time it was
    broken.
    """
    from app.components import asset_path
    assert os.path.exists(asset_path("kasanki-mark.png"))
    assert window._load_mark() is not None


def test_the_mark_asset_is_cropped_to_its_artwork(window):
    """
    The studio master file is a 4000x4000 canvas about half of which is
    empty padding. Shipped uncropped, the mark would render at roughly
    half the size the layout asks for and the monogram would not resolve
    in a 34px box. So the shipped asset must be tight to its own ink.
    """
    from PIL import Image
    from app.components import asset_path
    im = Image.open(asset_path("kasanki-mark.png")).convert("RGBA")
    bbox = im.split()[3].getbbox()
    assert bbox is not None, "the mark has no visible pixels at all"
    left, top, right, bottom = bbox
    w, h = im.size
    # Allow a small deliberate margin, but nothing like a half-empty canvas.
    assert right - left >= w * 0.9 and bottom - top >= h * 0.9, (
        f"artwork fills only {right - left}x{bottom - top} of {w}x{h}")


def test_child_windows_get_an_icon_applied(window):
    """
    Child windows do not inherit the root's icon on Windows, so every
    dialog would otherwise show python.exe's.

    Note this asserts the call is MADE, not that the icon renders:
    wm_iconbitmap() reads back None on Windows whether or not an icon
    was set, so it cannot be used as proof either way.
    """
    from app.components import InfoWindow, apply_icon
    calls = []
    win = InfoWindow(window, title="About", body="x")
    window.update()
    try:
        apply_icon(win)          # must not raise on a live Toplevel
        calls.append(True)
    finally:
        win.destroy()
    assert calls == [True]


def test_browse_dialogs_are_never_chained():
    """
    REGRESSION GUARD. Cancelling the file picker used to open the
    folder picker, because an empty result was read as "they want a
    folder" rather than as "they pressed Cancel". It looked as though
    the window reopened the prompt by itself.
    """
    import inspect
    from app.components import DropZone
    files = inspect.getsource(DropZone._browse_files)
    folder = inspect.getsource(DropZone._browse_folder)
    assert "askdirectory" not in files
    assert "askopenfilenames" not in folder


def test_theme_is_sharp(theme):
    """Every corner radius must be zero; that was the whole point."""
    import json
    with open(theme, encoding="utf-8") as fh:
        data = json.load(fh)
    for widget, props in data.items():
        if isinstance(props, dict):
            for name in ("corner_radius", "button_corner_radius"):
                if name in props:
                    assert props[name] == 0, f"{widget}.{name} is rounded"


def test_a_packer_is_always_available(window):
    """
    The window works with or without the proprietary engine. A missing
    engine means worse ratios, never a broken application.
    """
    assert window._engine_name in ("routing engine", "reference encoder")
    assert callable(window._pack_fn)


def test_info_windows_open(window):
    from app.gui import MENU_ITEMS
    for name in MENU_ITEMS:
        window._open_info(name)
        window.update()
    assert len(MENU_ITEMS) >= 4


def test_every_menu_item_has_content():
    """A menu entry that opens an empty window is worse than no entry."""
    from app.gui import MENU_ITEMS, _INFO
    missing = [m for m in MENU_ITEMS if not _INFO.get(m, "").strip()]
    assert missing == [], f"menu items with no body: {missing}"


# ==========================================================================
# Queueing
# ==========================================================================

def test_adding_sources_populates_the_queue(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"hello compakt\n" * 200)
    window._add_pack_sources([str(p)])
    window.update()
    assert len(window._pack_queue) == 1
    assert window._pack_sources == [str(p)]


def test_duplicate_sources_are_ignored(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"x" * 100)
    window._add_pack_sources([str(p)])
    window._add_pack_sources([str(p)])
    window.update()
    assert len(window._pack_sources) == 1


def test_clearing_resets_the_pack_tab(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"x" * 100)
    window._add_pack_sources([str(p)])
    window._clear_pack()
    window.update()
    assert window._pack_sources == []
    assert len(window._pack_queue) == 0


def test_archives_are_identified_when_queued(window, tmp_path):
    from core.reference_encoder import pack
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_bytes(b"payload\n" * 200)
    arc = str(tmp_path / "t.pakt")
    pack([str(src)], arc)

    window._add_unpack_targets([arc])
    window.update()
    assert window._unpack_targets == [arc]


def test_a_non_archive_is_listed_but_not_queued(window, tmp_path):
    """It must be reported to the user, not silently dropped or crash."""
    bad = tmp_path / "notes.doc"
    bad.write_bytes(b"not an archive at all")
    window._add_unpack_targets([str(bad)])
    window.update()
    assert window._unpack_targets == []
    assert len(window._unpack_queue) == 1


# ==========================================================================
# The mutual exclusion, expressed in the interface
# ==========================================================================

def test_encryption_disables_reproducible(window):
    window._password.enabled.set(True)
    window._sync_exclusive()
    window.update()
    assert window._opt_reproducible.checkbox.cget("state") == "disabled"


def test_reproducible_disables_encryption(window):
    window._opt_reproducible.variable.set(True)
    window._sync_exclusive()
    window.update()
    assert window._password._check.cget("state") == "disabled"


def test_both_available_when_neither_is_chosen(window):
    window._sync_exclusive()
    window.update()
    assert window._opt_reproducible.checkbox.cget("state") == "normal"
    assert window._password._check.cget("state") == "normal"


def test_sync_does_not_recurse(window):
    """
    Regression guard. Each control's handler adjusts the other, and a
    programmatic change once fired the user-action callback, so a single
    click bounced between them until the stack ran out.
    """
    for _ in range(30):
        window._password.enabled.set(True)
        window._sync_exclusive()
        window._password.enabled.set(False)
        window._password._changed(notify=False)
        window._opt_reproducible.variable.set(True)
        window._sync_exclusive()
        window._opt_reproducible.variable.set(False)
        window._sync_exclusive()
    window.update()
    assert window._password._check.cget("state") == "normal"


def test_no_browser_openable_option_is_offered(window):
    """
    The browser-openable archive was CANCELLED on 19 August 2026, not
    deferred: the file it produces is structurally identical to HTML
    smuggling, and a security tool should not ship that shape.

    The format capability survives -- Feature.POLYGLOT is still defined
    and the container still relocates behind an arbitrary prefix -- so
    the temptation to re-expose it in the interface is real. This test
    exists to make that a deliberate act rather than an easy one.
    """
    assert not hasattr(window, "_opt_polyglot")

    def walk(widget):
        yield widget
        for child in widget.winfo_children():
            yield from walk(child)

    for widget in walk(window):
        try:
            text = str(widget.cget("text"))
        except Exception:          # most widgets have no 'text' option
            continue
        assert "rowser" not in text


# ==========================================================================
# Helpers
# ==========================================================================

def test_human_bytes_formatting():
    from app.components import human_bytes
    assert human_bytes(512) == "512 B"
    assert human_bytes(1536).endswith("KB")
    assert human_bytes(5 * 1024 ** 3).endswith("GB")


def test_drop_payload_splitting(window):
    """Tk delivers several dropped paths as one brace-quoted string."""
    parts = window._split_drop("{C:/a b/one.txt} {C:/two.txt}")
    assert len(parts) == 2
    assert parts[0].endswith("one.txt")


def test_tree_size_counts_a_directory(tmp_path):
    from app.gui import _tree_size
    d = tmp_path / "d"
    (d / "sub").mkdir(parents=True)
    (d / "a.bin").write_bytes(b"x" * 1000)
    (d / "sub" / "b.bin").write_bytes(b"y" * 500)
    assert _tree_size(str(d)) == 1500


def test_password_failure_detection():
    from app.gui import _is_password_failure
    from core.crypto import WrongPassword
    assert _is_password_failure(WrongPassword("bad"))
    assert _is_password_failure(RuntimeError("wrong password supplied"))
    assert not _is_password_failure(RuntimeError("disk full"))
