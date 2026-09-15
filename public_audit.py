#!/usr/bin/env python3
"""Run the public audit while deferring report-derived blocking to ADR-0018.

`audit.main()` returns 1 when generated evidence contains a configured blocking
finding. The scheduled public workflow must still generate that evidence before
the separate risk gate can decide whether an exact finding is accepted risk.
This adapter converts only that normal report result from 1 to 0. Uncaught
exceptions still fail normally, and any future unexpected non-zero return code
is preserved rather than silently treated as a finding result.
"""

from __future__ import annotations

import audit


def main() -> int:
    result = audit.main()
    if result == 1:
        return 0
    return result


if __name__ == "__main__":
    raise SystemExit(main())
