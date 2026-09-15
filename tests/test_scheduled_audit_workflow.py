from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "audit.yml"
RISK_AUTHORITY_SHA = "cb7012668029e21ee8776a7740ffca2ccf1df135"
GARDENER_AUTHORITY_SHA = "eb634e5b19725ecc87902543058a4dd2a2e089c7"


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

    def test_gardener_and_risk_authorities_remain_separate(self) -> None:
        self.assertIn(f"GARDENER_AUTHORITY_SHA: {GARDENER_AUTHORITY_SHA}", self.text)
        self.assertIn(f"RISK_AUTHORITY_SHA: {RISK_AUTHORITY_SHA}", self.text)
        gardener = step_block(
            self.text,
            "Check out reviewed public authority and Finding contract",
        )
        risk = step_block(self.text, "Check out reviewed vulnerability risk authority")
        self.assertIn(f"ref: {GARDENER_AUTHORITY_SHA}", gardener)
        self.assertIn("path: .atlas-infra", gardener)
        self.assertIn(f"ref: {RISK_AUTHORITY_SHA}", risk)
        self.assertIn("path: .atlas-infra-risk", risk)

    def test_raw_audit_exit_is_deferred_only_after_report_exists(self) -> None:
        block = step_block(self.text, "Audit public estate repositories")
        self.assertIn("RAW_AUDIT_EXIT=$?", block)
        self.assertIn("test -s reports/report.json", block)
        self.assertIn("raw_exit=%s", block)

    def test_risk_gate_uses_completed_report_and_pinned_authority(self) -> None:
        block = step_block(
            self.text,
            "Evaluate bounded vulnerability risk dispositions",
        )
        self.assertIn("steps.audit.outcome == 'success'", block)
        self.assertIn("hashFiles('reports/report.json') != ''", block)
        self.assertIn("python3 vulnerability_risk_gate.py", block)
        self.assertIn('--infra-root "$ATLAS_RISK_INFRA_ROOT"', block)
        self.assertIn('--authority-sha "$RISK_AUTHORITY_SHA"', block)
        self.assertIn('cat reports/summary.md >> "$GITHUB_STEP_SUMMARY"', block)

    def test_gardener_export_requires_a_real_audit_report(self) -> None:
        block = step_block(self.text, "Export canonical public Gardener Finding bundle")
        self.assertIn("steps.audit.outcome != 'cancelled'", block)
        self.assertIn("hashFiles('reports/report.json') != ''", block)
        self.assertIn("test -s reports/report.json", block)
        self.assertIn('--infra-root "$ATLAS_INFRA_ROOT"', block)

    def test_artifact_upload_requires_generated_evidence(self) -> None:
        block = step_block(self.text, "Upload public audit evidence")
        self.assertIn("hashFiles('reports/**') != ''", block)
        self.assertIn("hashFiles('sbom/**') != ''", block)
        self.assertIn("hashFiles('provenance/**') != ''", block)
        self.assertIn("if-no-files-found: error", block)

    def test_blocking_classification_comes_from_risk_gate(self) -> None:
        block = step_block(self.text, "Classify audit result")
        self.assertIn("AUDIT_OUTCOME: ${{ steps.audit.outcome }}", block)
        self.assertIn("RISK_OUTCOME: ${{ steps.risk_gate.outcome }}", block)
        self.assertIn("RISK_BLOCKING: ${{ steps.risk_gate.outputs.blocking }}", block)
        self.assertIn("EXPORT_OUTCOME: ${{ steps.gardener_export.outcome }}", block)
        self.assertIn('if [ "$RISK_OUTCOME" != "success" ]', block)
        self.assertIn('if [ "$RISK_BLOCKING" = "true" ]', block)
        self.assertIn("handoff_ready=true", block)
        self.assertIn("needs.audit.outputs.handoff_ready == 'true'", self.text)

    def test_published_gardener_bundle_keeps_existing_authority(self) -> None:
        self.assertIn(
            f"GARDENER_AUTHORITY_SHA: {GARDENER_AUTHORITY_SHA}",
            self.text,
        )
        block = step_block(self.text, "Validate bounded handoff input")
        self.assertIn(
            'document.get("authority_commit") != "${{ env.GARDENER_AUTHORITY_SHA }}"',
            block,
        )

    def test_final_gate_preserves_blocking_audit_and_handoff_failures(self) -> None:
        block = step_block(self.text, "Preserve blocking result")
        self.assertIn("AUDIT_BLOCKING:", block)
        self.assertIn("HANDOFF_READY:", block)
        self.assertIn("HANDOFF_ENABLED:", block)
        self.assertIn("PUBLISH_RESULT:", block)
        self.assertIn("exit 1", block)


if __name__ == "__main__":
    unittest.main()
