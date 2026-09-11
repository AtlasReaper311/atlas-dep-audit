from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "audit.yml"


def step_block(text: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = text.index(marker)
    end = text.find("\n      - name: ", start + len(marker))
    return text[start:] if end < 0 else text[start:end]


class ScheduledAuditWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_primary_checkout_fetches_history_for_ancestry_tests(self) -> None:
        block = step_block(self.text, "Check out audit repository")
        self.assertIn("fetch-depth: 0", block)

    def test_gardener_export_requires_a_real_audit_report(self) -> None:
        block = step_block(self.text, "Export canonical public Gardener Finding bundle")
        self.assertIn("steps.audit.outcome != 'cancelled'", block)
        self.assertIn("hashFiles('reports/report.json') != ''", block)
        self.assertIn("test -s reports/report.json", block)

    def test_artifact_upload_requires_generated_evidence(self) -> None:
        block = step_block(self.text, "Upload public audit evidence")
        self.assertIn("hashFiles('reports/**') != ''", block)
        self.assertIn("hashFiles('sbom/**') != ''", block)
        self.assertIn("hashFiles('provenance/**') != ''", block)
        self.assertIn("if-no-files-found: error", block)

    def test_blocking_findings_do_not_prevent_valid_handoff_publication(self) -> None:
        block = step_block(self.text, "Classify audit result")
        self.assertIn("AUDIT_OUTCOME: ${{ steps.audit.outcome }}", block)
        self.assertIn("EXPORT_OUTCOME: ${{ steps.gardener_export.outcome }}", block)
        self.assertIn("handoff_ready=true", block)
        self.assertIn("blocking=true", block)
        self.assertIn("needs.audit.outputs.handoff_ready == 'true'", self.text)

    def test_final_gate_preserves_blocking_audit_and_handoff_failures(self) -> None:
        block = step_block(self.text, "Preserve blocking result")
        self.assertIn("AUDIT_BLOCKING:", block)
        self.assertIn("HANDOFF_READY:", block)
        self.assertIn("HANDOFF_ENABLED:", block)
        self.assertIn("PUBLISH_RESULT:", block)
        self.assertIn("exit 1", block)


if __name__ == "__main__":
    unittest.main()
