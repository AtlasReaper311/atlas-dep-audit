from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "validate_gardener_schedule.py"
SPEC = importlib.util.spec_from_file_location("validate_gardener_schedule", SCRIPT)
assert SPEC and SPEC.loader
VALIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATE)

WORKFLOW = '''name: Estate dependency and provenance audit
on:
  schedule:
    - cron: "41 8 * * 1"
  workflow_dispatch:
'''

POLICY = {
    "finding_bundle": {"maximum_age_hours": 36},
    "scheduling": {
        "controller_cron": "15 10 * * 1",
        "audit_cron": "41 8 * * 1",
        "monday_ingest": True,
        "daily_reconciliation": False,
    },
}


class GardenerScheduleTests(unittest.TestCase):
    def test_weekly_schedule_is_valid(self) -> None:
        report = VALIDATE.validate_schedule(workflow=WORKFLOW, policy=POLICY)
        self.assertEqual("valid", report["status"])
        self.assertEqual(94, report["controller_delay_minutes"])

    def test_rejects_daily_controller(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["scheduling"]["daily_reconciliation"] = True
        with self.assertRaisesRegex(VALIDATE.ScheduleError, "daily reconciliation"):
            VALIDATE.validate_schedule(workflow=WORKFLOW, policy=policy)

    def test_rejects_controller_before_audit(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["scheduling"]["controller_cron"] = "30 8 * * 1"
        with self.assertRaisesRegex(VALIDATE.ScheduleError, "after the audit"):
            VALIDATE.validate_schedule(workflow=WORKFLOW, policy=policy)

    def test_rejects_controller_outside_finding_lifetime(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["finding_bundle"]["maximum_age_hours"] = 1
        with self.assertRaisesRegex(VALIDATE.ScheduleError, "outside the Finding lifetime"):
            VALIDATE.validate_schedule(workflow=WORKFLOW, policy=policy)

    def test_rejects_workflow_cron_drift(self) -> None:
        workflow = WORKFLOW.replace("41 8 * * 1", "42 8 * * 1")
        with self.assertRaisesRegex(VALIDATE.ScheduleError, "Monday 08:41"):
            VALIDATE.validate_schedule(workflow=workflow, policy=POLICY)


if __name__ == "__main__":
    unittest.main()
