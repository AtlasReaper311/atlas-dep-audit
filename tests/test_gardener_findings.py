from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import gardener_findings


class GardenerFindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.infra = Path(os.environ["ATLAS_INFRA_ROOT"]).resolve()
        cls.rules = gardener_findings.load_object(
            cls.infra / "contracts/v1/fingerprint-rules.json",
            "fingerprint rules",
        )
        cls.coverage = gardener_findings.load_object(
            cls.infra / "policy/gardener-github-app-coverage.json",
            "coverage policy",
        )
        cls.repositories = gardener_findings.coverage_repositories(cls.coverage)
        cls.generated = datetime(2026, 7, 22, 9, 30, tzinfo=timezone.utc)

    def run_git(self, root: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def repository(
        self,
        root: Path,
        name: str,
        *,
        files: dict[str, bytes | str] | None = None,
    ) -> Path:
        repository = root / name
        repository.mkdir(parents=True)
        self.run_git(repository, "init", "-b", "main")
        self.run_git(repository, "config", "user.name", "Atlas Test")
        self.run_git(repository, "config", "user.email", "atlas@example.invalid")
        for relative, content in (files or {}).items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        self.run_git(repository, "add", "--all")
        self.run_git(repository, "commit", "-m", "fixture")
        head = self.run_git(repository, "rev-parse", "HEAD")
        self.run_git(repository, "update-ref", "refs/remotes/origin/main", head)
        return repository

    def empty_report(self) -> dict:
        return {
            "schema": "atlas-supply-chain-report/v1",
            "repositories_scanned": 20,
            "clean_repositories": 20,
            "vulnerabilities": [],
            "policy_findings": [],
            "secret_watch": {"findings": []},
        }

    def write_report(self, root: Path, report: dict | None = None) -> Path:
        path = root / "report.json"
        path.write_text(
            json.dumps(report or self.empty_report(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def prepare_estate(self, root: Path) -> Path:
        work = root / "work"
        work.mkdir()
        for full_name in self.repositories:
            name = full_name.split("/", 1)[1]
            self.repository(
                work,
                name,
                files={
                    ".gitignore": ".DS_Store\n__pycache__/\n*.py[cod]\n",
                    "README.md": f"# {name}\n",
                },
            )
        return work

    def build(self, root: Path, report: dict | None = None) -> dict:
        work = self.prepare_estate(root)
        report_path = self.write_report(root, report)
        return gardener_findings.build_bundle(
            report_path=report_path,
            work_dir=work,
            infra_root=self.infra,
            generated_at=self.generated,
            source_run_id="100",
            source_run_attempt=1,
            source_commit="1" * 40,
            run_url="https://github.com/AtlasReaper311/atlas-dep-audit/actions/runs/100",
        )

    def test_missing_macos_ignore_produces_canonical_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.repository(
                root,
                "example",
                files={"README.md": "# Example\n"},
            )
            findings = gardener_findings.housekeeping_findings(
                "AtlasReaper311/example",
                repository,
                detected_at="2026-07-22T09:30:00Z",
                run_url="https://github.com/AtlasReaper311/atlas-dep-audit/actions/runs/100",
                rules=self.rules,
            )
        self.assertEqual(1, len(findings))
        self.assertEqual("macos-metadata-ignore", findings[0]["rule_id"])
        self.assertTrue(findings[0]["remediation"]["eligible"])
        self.assertRegex(findings[0]["fingerprint"], r"^sha256:[0-9a-f]{64}$")

    def test_python_repository_produces_cache_ignore_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.repository(
                root,
                "python-example",
                files={
                    ".gitignore": ".DS_Store\n",
                    "app.py": "print('ok')\n",
                },
            )
            findings = gardener_findings.housekeeping_findings(
                "AtlasReaper311/python-example",
                repository,
                detected_at="2026-07-22T09:30:00Z",
                run_url="",
                rules=self.rules,
            )
        self.assertEqual(["python-cache-ignore"], [item["rule_id"] for item in findings])
        self.assertIn("*.py[cod]", findings[0]["evidence"]["summary"])
        self.assertIn("__pycache__/", findings[0]["evidence"]["summary"])

    def test_tracked_binary_artifact_remains_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.repository(
                root,
                "tracked-example",
                files={
                    ".gitignore": ".DS_Store\n__pycache__/\n*.py[cod]\n",
                    "app.py": "pass\n",
                    "__pycache__/app.pyc": b"\x00binary",
                },
            )
            self.run_git(repository, "add", "-f", "__pycache__/app.pyc")
            self.run_git(repository, "commit", "--amend", "--no-edit")
            head = self.run_git(repository, "rev-parse", "HEAD")
            self.run_git(repository, "update-ref", "refs/remotes/origin/main", head)
            findings = gardener_findings.housekeeping_findings(
                "AtlasReaper311/tracked-example",
                repository,
                detected_at="2026-07-22T09:30:00Z",
                run_url="",
                rules=self.rules,
            )
        self.assertEqual(["python-cache-ignore"], [item["rule_id"] for item in findings])
        self.assertIn("tracked cache artifact", findings[0]["evidence"]["summary"])

    def test_action_pin_is_review_only_and_unknown_rule_is_normalized(self) -> None:
        report = self.empty_report()
        report["policy_findings"] = [
            {
                "repo": self.repositories[0],
                "severity": "warning",
                "rule": "actions-pin",
                "path": ".github/workflows/ci.yml",
                "message": "Action is mutable.",
            },
            {
                "repo": self.repositories[0],
                "severity": "warning",
                "rule": "UNSAFE_RULE",
                "path": "path with spaces",
                "message": "Unsupported audit rule.",
            },
        ]
        findings = gardener_findings.report_findings(
            report,
            detected_at="2026-07-22T09:30:00Z",
            run_url="",
            rules=self.rules,
            covered=set(self.repositories),
        )
        self.assertEqual(
            ["missing-action-pin", "audit-policy"],
            [item["rule_id"] for item in findings],
        )
        self.assertTrue(findings[0]["remediation"]["eligible"])
        self.assertFalse(findings[1]["remediation"]["eligible"])
        self.assertEqual("repository", findings[1]["location"])

    def test_private_and_out_of_coverage_findings_are_not_exported(self) -> None:
        report = self.empty_report()
        report["policy_findings"] = [
            {
                "repo": "AtlasReaper311/private-example",
                "severity": "error",
                "rule": "clone",
                "path": "",
                "message": "Private identity must remain source-owned.",
            }
        ]
        findings = gardener_findings.report_findings(
            report,
            detected_at="2026-07-22T09:30:00Z",
            run_url="",
            rules=self.rules,
            covered=set(self.repositories),
        )
        self.assertEqual([], findings)

    def test_bundle_is_deterministic_and_contains_exact_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.build(root)
            second = gardener_findings.build_bundle(
                report_path=root / "report.json",
                work_dir=root / "work",
                infra_root=self.infra,
                generated_at=self.generated,
                source_run_id="100",
                source_run_attempt=1,
                source_commit="1" * 40,
                run_url="https://github.com/AtlasReaper311/atlas-dep-audit/actions/runs/100",
            )
        self.assertEqual(first, second)
        self.assertTrue(first["public_only"])
        self.assertEqual(20, len(first["repository_snapshots"]))
        self.assertEqual(
            self.repositories,
            [item["repository"] for item in first["repository_snapshots"]],
        )
        self.assertEqual([], first["findings"])
        self.assertRegex(first["bundle_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_duplicate_findings_are_deduplicated_by_fingerprint(self) -> None:
        report = self.empty_report()
        item = {
            "repo": self.repositories[0],
            "severity": "warning",
            "rule": "actions-pin",
            "path": ".github/workflows/ci.yml",
            "message": "Action is mutable.",
        }
        report["policy_findings"] = [item, copy.deepcopy(item)]
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.build(Path(directory), report)
        matches = [
            finding
            for finding in bundle["findings"]
            if finding["rule_id"] == "missing-action-pin"
        ]
        self.assertEqual(1, len(matches))

    def test_missing_covered_checkout_blocks_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = self.prepare_estate(root)
            missing = self.repositories[-1].split("/", 1)[1]
            shutil.rmtree(work / missing)
            report_path = self.write_report(root)
            with self.assertRaisesRegex(
                gardener_findings.FindingExportError,
                "checkout is unavailable",
            ):
                gardener_findings.build_bundle(
                    report_path=report_path,
                    work_dir=work,
                    infra_root=self.infra,
                    generated_at=self.generated,
                    source_run_id="100",
                    source_run_attempt=1,
                    source_commit="1" * 40,
                    run_url="",
                )

    def test_unknown_report_schema_fails_closed(self) -> None:
        report = self.empty_report()
        report["schema"] = "unknown"
        with self.assertRaisesRegex(
            gardener_findings.FindingExportError,
            "unsupported supply-chain report schema",
        ):
            gardener_findings.report_findings(
                report,
                detected_at="2026-07-22T09:30:00Z",
                run_url="",
                rules=self.rules,
                covered=set(self.repositories),
            )


if __name__ == "__main__":
    unittest.main()
