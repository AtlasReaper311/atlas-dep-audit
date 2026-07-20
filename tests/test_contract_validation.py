from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import audit
import contract_validation


class ContractValidationTests(unittest.TestCase):
    def make_checkout(
        self,
        root: Path,
        *,
        idempotent: bool = True,
        schema_count: int = 8,
        positive_count: int | None = None,
        negative_count: int | None = None,
        fixtures_count: int | None = None,
        exit_code: int = 0,
    ) -> None:
        (root / "contracts" / "v1").mkdir(parents=True)
        scripts = root / "scripts"
        scripts.mkdir()
        positive = schema_count if positive_count is None else positive_count
        negative = schema_count if negative_count is None else negative_count
        fixtures = positive + negative if fixtures_count is None else fixtures_count
        report = {
            "schema_version": "atlas-control-plane/validation-report/v1",
            "contracts_root": "contracts/v1",
            "schemas_checked": schema_count,
            "fixtures_checked": fixtures,
            "positive_fixtures": positive,
            "negative_fixtures": negative,
            "errors": [],
            "idempotent": idempotent,
        }
        script = f"""\
import argparse
import json
import os
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--root')
parser.add_argument('--report', type=Path)
parser.add_argument('--quiet', action='store_true')
args = parser.parse_args()
report = {report!r}
sensitive = {{'GH_DIGEST_PAT', 'GITHUB_TOKEN', 'NOTIFY_TOKEN', 'CF_API_TOKEN'}}
if sensitive.intersection(os.environ):
    report['errors'] = ['credential environment leaked to validator']
args.report.write_text(json.dumps(report), encoding='utf-8')
sys.exit({exit_code})
"""
        (scripts / "validate_control_plane_contracts.py").write_text(
            script, encoding="utf-8"
        )

    def test_allowlisted_validator_passes_with_credentials_scrubbed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root)
            with mock.patch.dict(
                os.environ,
                {
                    "GH_DIGEST_PAT": "fixture-token",
                    "GITHUB_TOKEN": "fixture-token",
                    "NOTIFY_TOKEN": "fixture-token",
                    "CF_API_TOKEN": "fixture-token",
                },
            ):
                result = contract_validation.validate_checkout(
                    contract_validation.CONTRACT_OWNER, root
                )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("passed", result.status)
            self.assertEqual(8, result.schemas_checked)
            self.assertTrue(result.idempotent)

    def test_additive_contract_growth_passes_without_audit_code_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, schema_count=11)
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, root
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("passed", result.status)
            self.assertEqual(11, result.schemas_checked)
            self.assertEqual(11, result.positive_fixtures)
            self.assertEqual(11, result.negative_fixtures)

    def test_other_repository_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, exit_code=7)
            result = contract_validation.validate_checkout(
                "AtlasReaper311/example", root
            )
            self.assertIsNone(result)

    def test_missing_canonical_contracts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, Path(directory)
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("contracts/v1 directory is missing", result.error)

    def test_non_idempotent_report_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, idempotent=False)
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, root
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("idempotent", result.error)

    def test_empty_schema_set_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, schema_count=0)
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, root
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("checked no schemas", result.error)

    def test_missing_positive_fixture_coverage_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, schema_count=11, positive_count=10)
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, root
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("positive fixture", result.error)

    def test_missing_negative_fixture_coverage_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, schema_count=11, negative_count=10)
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, root
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("negative fixture", result.error)

    def test_inconsistent_fixture_totals_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root, schema_count=11, fixtures_count=21)
            result = contract_validation.validate_checkout(
                contract_validation.CONTRACT_OWNER, root
            )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("fixture totals are inconsistent", result.error)

    def test_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_checkout(root)
            with mock.patch(
                "contract_validation.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["python3"], 1),
            ):
                result = contract_validation.validate_checkout(
                    contract_validation.CONTRACT_OWNER,
                    root,
                    timeout_seconds=1,
                )
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual("failed", result.status)
            self.assertIn("exceeded 1 seconds", result.error)

    def test_provenance_contains_only_stable_validation_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "requirements.txt"
            manifest.write_text("example==1.0.0\n", encoding="utf-8")
            sbom = root / "sbom.json"
            sbom.write_text("{}\n", encoding="utf-8")
            output = root / "provenance.json"
            result = contract_validation.ContractValidationResult(
                repository=contract_validation.CONTRACT_OWNER,
                status="passed",
                schemas_checked=8,
                fixtures_checked=16,
                positive_fixtures=8,
                negative_fixtures=8,
                idempotent=True,
                error="",
            )
            audit.write_provenance(
                output,
                contract_validation.CONTRACT_OWNER,
                "1" * 40,
                [manifest],
                root,
                [],
                [],
                sbom,
                result,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            summary = payload["control_plane_contract_validation"]
            self.assertEqual("passed", summary["status"])
            self.assertNotIn("error", summary)
            self.assertNotIn(str(root), json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
