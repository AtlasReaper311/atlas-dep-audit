#!/usr/bin/env python3
"""Validate that the audit workflow matches the reviewed Gardener schedule."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_WORKFLOW = ROOT / ".github/workflows/audit.yml"


class ScheduleError(ValueError):
    """Raised when audit and controller scheduling no longer align."""


def load_policy(infra_root: Path) -> dict[str, Any]:
    path = infra_root / "policy/gardener-automation.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScheduleError(f"cannot read Gardener automation policy: {error}") from error
    if not isinstance(value, dict):
        raise ScheduleError("Gardener automation policy must be a JSON object")
    return value


def parse_weekly_cron(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d{1,2}) (\d{1,2}) \* \* ([0-6])", value)
    if not match:
        raise ScheduleError(f"unsupported weekly cron: {value}")
    minute, hour, weekday = (int(item) for item in match.groups())
    if minute > 59 or hour > 23:
        raise ScheduleError(f"invalid weekly cron: {value}")
    return weekday, hour, minute


def extract_workflow_cron(workflow: str) -> str:
    matches = re.findall(r'^\s*- cron: "([^"]+)"\s*$', workflow, flags=re.MULTILINE)
    if matches != ["41 8 * * 1"]:
        raise ScheduleError(
            f"audit workflow must contain exactly the Monday 08:41 cron, observed {matches!r}"
        )
    return matches[0]


def validate_schedule(*, workflow: str, policy: dict[str, Any]) -> dict[str, Any]:
    scheduling = policy.get("scheduling")
    bundle = policy.get("finding_bundle")
    if not isinstance(scheduling, dict) or not isinstance(bundle, dict):
        raise ScheduleError("Gardener policy is missing scheduling or Finding lifetime")

    audit_cron = extract_workflow_cron(workflow)
    if scheduling.get("audit_cron") != audit_cron:
        raise ScheduleError("audit workflow cron does not match Gardener authority")
    if scheduling.get("monday_ingest") is not True:
        raise ScheduleError("Gardener authority no longer requires Monday ingestion")
    if scheduling.get("daily_reconciliation") is not False:
        raise ScheduleError("daily reconciliation is incompatible with the weekly Finding producer")

    controller_cron = scheduling.get("controller_cron")
    if not isinstance(controller_cron, str):
        raise ScheduleError("controller cron is unavailable")
    audit_weekday, audit_hour, audit_minute = parse_weekly_cron(audit_cron)
    controller_weekday, controller_hour, controller_minute = parse_weekly_cron(controller_cron)
    if controller_weekday != audit_weekday:
        raise ScheduleError("audit and controller must run on the same weekday")

    audit_time = timedelta(hours=audit_hour, minutes=audit_minute)
    controller_time = timedelta(hours=controller_hour, minutes=controller_minute)
    delay = controller_time - audit_time
    if delay <= timedelta(0):
        raise ScheduleError("controller must run after the audit")

    maximum_age_hours = bundle.get("maximum_age_hours")
    if not isinstance(maximum_age_hours, int):
        raise ScheduleError("Finding maximum age is unavailable")
    if delay >= timedelta(hours=maximum_age_hours):
        raise ScheduleError("controller schedule falls outside the Finding lifetime")

    return {
        "schema_version": "atlas-dep-audit/gardener-schedule-validation/v1",
        "status": "valid",
        "audit_cron": audit_cron,
        "controller_cron": controller_cron,
        "controller_delay_minutes": int(delay.total_seconds() // 60),
        "finding_maximum_age_hours": maximum_age_hours,
        "provider_mutations": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--infra-root", required=True, type=Path)
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        report = validate_schedule(
            workflow=args.workflow.read_text(encoding="utf-8"),
            policy=load_policy(args.infra_root),
        )
    except (OSError, UnicodeError, ScheduleError) as error:
        print(f"Gardener schedule invalid: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if not args.quiet:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
