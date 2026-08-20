"""
Design tokens.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

One place for colour, type and spacing, so the interface stays
consistent without every widget re-deciding what a gap is.

THE LOOK
--------
Near-black ground, separated by *elevation* rather than by outlines.
Earlier versions drew a 1px border around everything, which is what
makes a dark interface read as dated — modern dark UIs step the
background instead and keep hairlines for genuine dividers only.

Accent is white and used sparingly: one primary action per view, an
active-tab underline, and a focused input. Everything else is a shade
of grey, which is what lets the one white thing actually mean
something.
"""

from __future__ import annotations

import customtkinter as ctk

__all__ = ["C", "SPACE", "font", "FAMILY"]


class C:
    """Colour tokens."""

    # --- surfaces, lightest step last -----------------------------------
    ground = "#0A0A0A"          # window
    surface = "#111111"         # panels sitting on the ground
    raised = "#181818"          # inputs, list rows, hover states
    hover = "#1F1F1F"           # pointer feedback on a raised element

    # --- lines ----------------------------------------------------------
    hairline = "#222222"        # genuine dividers only
    edge = "#2E2E2E"            # input outlines, drop-zone dashes

    # --- text -----------------------------------------------------------
    # Every readable label is white. Grey secondary text is a large part
    # of what made this look dated, so hierarchy comes from SIZE and
    # WEIGHT instead of from fading things out.
    #
    # `faint` is the one exception and is semantic rather than
    # decorative: a disabled control has to LOOK disabled, or the
    # interface is lying about what can be clicked.
    text = "#FFFFFF"
    dim = "#FFFFFF"
    muted = "#FFFFFF"
    faint = "#4A4A4A"           # disabled only

    # --- accent ---------------------------------------------------------
    accent = "#FFFFFF"
    on_accent = "#0A0A0A"

    # --- state ----------------------------------------------------------
    good = "#6FCF80"
    warn = "#E0B341"
    bad = "#E06C60"


class SPACE:
    """
    A 4px spacing scale.

    Using a scale rather than arbitrary numbers is most of what makes a
    layout feel deliberate instead of assembled.
    """

    xs = 4
    sm = 8
    md = 12
    lg = 16
    xl = 24
    xxl = 32
    page = 28                   # window edge padding


#: Segoe UI Variable is the modern Windows UI face; Segoe UI is the
#: fallback everywhere it is absent.
FAMILY = "Segoe UI Variable Display"
FAMILY_FALLBACK = "Segoe UI"

_cache: dict[tuple, ctk.CTkFont] = {}


def font(size: int = 13, weight: str = "normal") -> ctk.CTkFont:
    """A cached font. Tk leaks font objects otherwise."""
    key = (size, weight)
    if key not in _cache:
        try:
            _cache[key] = ctk.CTkFont(family=FAMILY, size=size, weight=weight)
        except Exception:
            _cache[key] = ctk.CTkFont(family=FAMILY_FALLBACK, size=size,
                                      weight=weight)
    return _cache[key]


def tracked(text: str, gap: str = " ") -> str:
    """
    Fake letter-spacing for small uppercase labels.

    Tk has no tracking control, and tight uppercase at 10px reads as a
    solid block. A thin space between characters is the standard
    workaround and is what makes a small caps label look typeset rather
    than merely shouted.
    """
    return gap.join(text.upper())
