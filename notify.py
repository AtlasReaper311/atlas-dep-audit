#!/usr/bin/env python3
"""Post one consolidated supply-chain result through atlas-notify."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--critical", type=int, default=0)
    parser.add_argument("--high", type=int, default=0)
    parser.add_argument("--total", type=int, default=0)
    parser.add_argument("--policy-findings", type=int, default=0)
    parser.add_argument("--url", default="")
    args = parser.parse_args()

    token = os.getenv("NOTIFY_TOKEN", "")
    if not token:
        print("NOTIFY_TOKEN is not set. Skipping atlas-notify delivery.")
        return 0
    if args.critical > 0:
        level = "failure"
    elif args.high > 0 or args.policy_findings > 0:
        level = "warning"
    else:
        level = "info"
    message = (
        f"{args.total} known vulnerabilities, including {args.critical} critical and "
        f"{args.high} high; {args.policy_findings} supply-chain policy findings."
    )
    request = urllib.request.Request(
        "https://api.atlas-systems.uk/notify",
        data=json.dumps(
            {
                "source": "alert",
                "level": level,
                "title": "Estate supply-chain report",
                "message": message,
                "url": args.url,
                "persist_only": True,
            }
        ).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "atlas-dep-audit/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status >= 300:
            raise RuntimeError(f"atlas-notify returned {response.status}")
    print("Posted supply-chain summary to atlas-notify.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
