#!/usr/bin/env python3
"""Run the public audit while deferring report-derived blocking to ADR-0018.

`audit.main()` returns 1 when generated evidence contains a configured blocking
finding. The scheduled public workflow must still generate that evidence before
the separate risk gate can decide whether an exact finding is accepted risk.
This adapter converts only the current normal report results 0 and 1 to process
success. Uncaught exceptions, unexpected non-zero codes, and unexpected return
types remain failures.
"""

from __future__ import annotations

import audit


def main() -> int:
    result = audit.main()
    if result in {0, 1}:
        return 0
    if isinstance(result, int) and not isinstance(result, bool):
        return result
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
