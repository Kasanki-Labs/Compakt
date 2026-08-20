"""
Compakt launcher.

Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)

Starts the desktop window. The socket guard is installed here, before
anything else is imported, so it is in place ahead of any code that
could conceivably want a socket.
"""

from __future__ import annotations

import sys


def main() -> int:
    from app.gui import run
    return run()


if __name__ == "__main__":
    sys.exit(main())
