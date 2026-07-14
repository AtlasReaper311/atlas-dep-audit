from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import secret_watch

NOW = "2026-07-14T10:00:00Z"
EXAMPLE_REPOSITORY = "AtlasReaper311/example"
SIMPLE_PROXY = "AtlasReaper311/simple-proxy"
INFRA_ROOT = Path(
    os.environ.get(
        "ATLAS_INFRA_ROOT",
        str(Path(__file__).resolve().parents[2] / "atlas-infra"),
    )
)


def valid_policy() -> dict:
    return {
        "schema_version": secret_watch.POLICY_SCHEMA_VERSION,
        "owner": secret_watch.POLICY_OWNER,
        "github_metadata": {
            "mode": "optional",
            "token_secret_name": secret_watch.TOKEN_ENVIRONMENT_NAME,
        },
        "plaintext_scan": {
            "enabled": True,
            "max_file_bytes": 1024 * 1024,
            "fixture_globs": ["tests/fixtures/secret-watch/**"],
            "inline_suppression_marker": "secret-watch: ignore",
            "suppressions": [],
        },
        "secret_definitions": {
            "OPTIONAL_SECRET": {
                "owner": "fixture-owner",
                "purpose": "Optional fixture integration.",
                "lifecycle": "active",
                "provenance": "github-actions",
                "rotation": {
                    "required": False,
                    "max_age_days": None,
                    "last_rotated_at": None,
                },
                "replacement": None,
            },
            "REQUIRED_SECRET": {
                "owner": "fixture-owner",
                "purpose": "Required fixture integration.",
                "lifecycle": "active",
                "provenance": "github-actions",
                "rotation": {
                    "required": True,
                    "max_age_days": 90,
                    "last_rotated_at": "2026-07-01T00:00:00Z",
                },
                "replacement": None,
            },
            "OLD_SECRET": {
                "owner": "fixture-owner",
                "purpose": "Legacy fixture integration.",
                "lifecycle": "deprecated",
                "provenance": "github-actions",
                "rotation": {
                    "required": False,
                    "max_age_days": None,
                    "last_rotated_at": None,
                },
                "replacement": "Use REQUIRED_SECRET after the reviewed migration.",
            },
        },
        "repositories": [
            {
                "repository": EXAMPLE_REPOSITORY,
                "classification": {
                    "lifecycle": "active",
                    "scope": "internal",
                    "provenance": "original",
                },
                "assurance": {
                    "enabled": True,
                    "metadata_required": False,
                    "exclusion_reason": None,
                },
                "scopes": [
                    {
                        "store": "github-actions",
                        "environment": None,
                        "required_secret_names": ["REQUIRED_SECRET"],
                        "optional_secret_names": ["OPTIONAL_SECRET"],
                        "deprecated_secret_names": ["OLD_SECRET"],
                    }
                ],
            },
            {
                "repository": SIMPLE_PROXY,
                "classification": {
                    "lifecycle": "deprecated",
                    "scope": "internal",
                    "provenance": "external-derived",
                },
                "assurance": {
                    "enabled": False,
                    "metadata_required": False,
                    "exclusion_reason": "Deprecated external-derived fixture repository.",
                },
                "scopes": [],
            },
        ],
    }


class SecretWatchTests(unittest.TestCase):
    def write_policy(self, root: Path, policy: dict | None = None) -> Path:
        path = root / "policy.json"
        path.write_text(
            json.dumps(policy if policy is not None else valid_policy(), indent=2),
            encoding="utf-8",
        )
        return path

    def write_metadata(
        self,
        root: Path,
        names: list[str],
        *,
        repository: str = EXAMPLE_REPOSITORY,
        environment: str | None = None,
    ) -> Path:
        path = root / "metadata.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": secret_watch.METADATA_FIXTURE_SCHEMA_VERSION,
                    "repositories": [
                        {
                            "repository": repository,
                            "environment": environment,
                            "secret_names": names,
                        }
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def init_repository(self, root: Path, files: dict[str, bytes | str]) -> Path:
        root.mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "--", *sorted(files)], cwd=root, check=True)
        return root

    def run_report(
        self,
        root: Path,
        *,
        policy: dict | None = None,
        names: list[str] | None = None,
        repositories: dict[str, Path] | None = None,
        live_client=None,
    ) -> dict:
        policy_path = self.write_policy(root, policy)
        metadata = self.write_metadata(root, names) if names is not None else None
        return secret_watch.run_secret_watch(
            policy_path,
            repositories or {},
            metadata_fixture=metadata,
            live_client=live_client,
            detected_at=NOW,
        )

    def rules(self, report: dict) -> list[str]:
        return [finding["rule_id"] for finding in report["findings"]]

    def test_valid_declaration(self) -> None:
        self.assertEqual([], secret_watch.validate_policy(valid_policy()))
        self.assertEqual(
            secret_watch.POLICY_SCHEMA_VERSION,
            secret_watch.load_policy(INFRA_ROOT / "policy" / "secret-watch.json")[
                "schema_version"
            ],
        )

    def test_malformed_declaration_fails_closed(self) -> None:
        policy = valid_policy()
        policy["repositories"][0]["undeclared"] = True
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(Path(directory), policy=policy)
        self.assertTrue(report["blocking"])
        self.assertFalse(report["policy"]["valid"])
        self.assertIn("malformed-declaration", self.rules(report))

    def test_missing_owner_is_a_finding(self) -> None:
        policy = valid_policy()
        policy["secret_definitions"]["REQUIRED_SECRET"].pop("owner")
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), policy=policy, names=["REQUIRED_SECRET"]
            )
        self.assertIn("ownerless-secret-declaration", self.rules(report))

    def test_missing_purpose_is_a_finding(self) -> None:
        policy = valid_policy()
        policy["secret_definitions"]["REQUIRED_SECRET"].pop("purpose")
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), policy=policy, names=["REQUIRED_SECRET"]
            )
        self.assertIn("missing-secret-purpose", self.rules(report))

    def test_missing_required_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(Path(directory), names=[])
        self.assertIn("missing-required-secret", self.rules(report))

    def test_unexpected_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), names=["REQUIRED_SECRET", "UNDECLARED_SECRET"]
            )
        self.assertIn("unexpected-secret-name", self.rules(report))

    def test_deprecated_secret_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), names=["REQUIRED_SECRET", "OLD_SECRET"]
            )
        self.assertIn("deprecated-secret-present", self.rules(report))

    def test_optional_secret_absent_has_no_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(Path(directory), names=["REQUIRED_SECRET"])
        summaries = [finding["evidence"]["summary"] for finding in report["findings"]]
        self.assertFalse(any("OPTIONAL_SECRET" in summary for summary in summaries))

    def test_rotation_overdue(self) -> None:
        policy = valid_policy()
        rotation = policy["secret_definitions"]["REQUIRED_SECRET"]["rotation"]
        rotation["max_age_days"] = 30
        rotation["last_rotated_at"] = "2026-01-01T00:00:00Z"
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), policy=policy, names=["REQUIRED_SECRET"]
            )
        self.assertIn("rotation-overdue", self.rules(report))

    def test_rotation_not_overdue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(Path(directory), names=["REQUIRED_SECRET"])
        self.assertNotIn("rotation-overdue", self.rules(report))

    def test_missing_rotation_metadata(self) -> None:
        policy = valid_policy()
        policy["secret_definitions"]["REQUIRED_SECRET"]["rotation"]["max_age_days"] = (
            None
        )
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), policy=policy, names=["REQUIRED_SECRET"]
            )
        self.assertIn("missing-rotation-metadata", self.rules(report))

    def test_metadata_unavailable_is_unknown_not_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(Path(directory))
        self.assertEqual("disabled", report["metadata"]["status"])
        self.assertNotEqual("healthy", report["state"])
        self.assertIn("metadata-unavailable", self.rules(report))
        self.assertFalse(report["blocking"])

    def test_required_metadata_permission_failure_is_blocking(self) -> None:
        class DeniedClient:
            def list_secret_names(self, repository, environment):
                raise secret_watch.MetadataUnavailable("permission-denied")

        policy = valid_policy()
        policy["repositories"][0]["assurance"]["metadata_required"] = True
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), policy=policy, live_client=DeniedClient()
            )
        self.assertTrue(report["blocking"])
        self.assertEqual("unavailable", report["metadata"]["status"])

    def test_live_client_uses_names_only_get_endpoints(self) -> None:
        class RecordingClient(secret_watch.GitHubMetadataClient):
            def __init__(self):
                super().__init__("fixture-token")
                self.paths = []

            def _json_get(self, path):
                self.paths.append(path)
                if path == "/repos/AtlasReaper311/example":
                    return {"id": 123}
                return {"total_count": 0, "secrets": []}

        client = RecordingClient()
        self.assertEqual(
            frozenset(), client.list_secret_names(EXAMPLE_REPOSITORY, None)
        )
        self.assertEqual(
            frozenset(), client.list_secret_names(EXAMPLE_REPOSITORY, "production")
        )
        self.assertTrue(all("public-key" not in path for path in client.paths))
        self.assertTrue(
            all(
                "/actions/secrets" in path
                or path.endswith("/example")
                or "/environments/" in path
                for path in client.paths
            )
        )

    def test_plaintext_pattern_is_redacted_and_value_free(self) -> None:
        suspected_value = "ghp_" + "A" * 24
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(
                root / "example", {"settings.py": f"credential = '{suspected_value}'\n"}
            )
            report = self.run_report(
                root,
                names=["REQUIRED_SECRET"],
                repositories={EXAMPLE_REPOSITORY: repository},
            )
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn(suspected_value, rendered)
        self.assertIn("plaintext-credential-pattern", self.rules(report))
        plaintext = next(
            finding
            for finding in report["findings"]
            if finding["rule_id"] == "plaintext-credential-pattern"
        )
        self.assertTrue(plaintext["evidence"]["redacted"])
        self.assertEqual("settings.py:1", plaintext["location"])

    def test_false_positive_placeholder_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(
                root / "example",
                {"config.py": 'api_key = "fixture-placeholder-value"\n'},
            )
            report = self.run_report(
                root,
                names=["REQUIRED_SECRET"],
                repositories={EXAMPLE_REPOSITORY: repository},
            )
        self.assertNotIn("plaintext-credential-pattern", self.rules(report))

    def test_inline_suppression_works(self) -> None:
        suspected_value = "ghp_" + "B" * 24
        line = (
            f"credential = '{suspected_value}'  # secret-watch: ignore github-token\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(root / "example", {"config.py": line})
            report = self.run_report(
                root,
                names=["REQUIRED_SECRET"],
                repositories={EXAMPLE_REPOSITORY: repository},
            )
        self.assertNotIn("plaintext-credential-pattern", self.rules(report))

    def test_central_suppression_works(self) -> None:
        policy = valid_policy()
        policy["plaintext_scan"]["suppressions"] = [
            {
                "repository": EXAMPLE_REPOSITORY,
                "path": "config.py",
                "line": 1,
                "rule_id": "github-token",
                "owner": "fixture-owner",
                "reason": "Known constructed test pattern.",
                "expires_at": None,
            }
        ]
        suspected_value = "ghp_" + "C" * 24
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(
                root / "example", {"config.py": f"credential = '{suspected_value}'\n"}
            )
            report = self.run_report(
                root,
                policy=policy,
                names=["REQUIRED_SECRET"],
                repositories={EXAMPLE_REPOSITORY: repository},
            )
        self.assertNotIn("plaintext-credential-pattern", self.rules(report))

    def test_binary_files_are_skipped(self) -> None:
        suspected_value = ("ghp_" + "D" * 24).encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(
                root / "example", {"image.bin": b"\x00" + suspected_value}
            )
            report = self.run_report(
                root,
                names=["REQUIRED_SECRET"],
                repositories={EXAMPLE_REPOSITORY: repository},
            )
        self.assertEqual(1, report["plaintext_scan"]["binary_files_skipped"])
        self.assertNotIn("plaintext-credential-pattern", self.rules(report))

    def test_approved_fixture_files_are_skipped(self) -> None:
        suspected_value = "ghp_" + "E" * 24
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(
                root / "example",
                {"tests/fixtures/secret-watch/sample.txt": suspected_value},
            )
            report = self.run_report(
                root,
                names=["REQUIRED_SECRET"],
                repositories={EXAMPLE_REPOSITORY: repository},
            )
        self.assertEqual(1, report["plaintext_scan"]["fixture_files_skipped"])
        self.assertNotIn("plaintext-credential-pattern", self.rules(report))

    def test_simple_proxy_is_excluded(self) -> None:
        suspected_value = "ghp_" + "F" * 24
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.init_repository(
                root / "simple-proxy", {"config.py": suspected_value}
            )
            report = self.run_report(
                root,
                names=["REQUIRED_SECRET"],
                repositories={SIMPLE_PROXY: repository},
            )
        self.assertEqual(1, report["summary"]["repositories_excluded"])
        self.assertEqual(0, report["plaintext_scan"]["files_scanned"])
        self.assertFalse(
            any(
                finding["subject"]["repository"] == SIMPLE_PROXY
                for finding in report["findings"]
            )
        )

    def test_repository_classification_conflict(self) -> None:
        policy = valid_policy()
        policy["repositories"][1]["assurance"]["enabled"] = True
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(
                Path(directory), policy=policy, names=["REQUIRED_SECRET"]
            )
        self.assertIn("repository-classification-conflict", self.rules(report))

    def test_findings_validate_against_canonical_schema(self) -> None:
        module_path = INFRA_ROOT / "scripts" / "control_plane_contracts.py"
        spec = importlib.util.spec_from_file_location(
            "canonical_contracts", module_path
        )
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        contracts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contracts)
        schema = json.loads(
            (INFRA_ROOT / "contracts" / "v1" / "finding.schema.json").read_text(
                encoding="utf-8"
            )
        )
        rules = json.loads(
            (INFRA_ROOT / "contracts" / "v1" / "fingerprint-rules.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_report(Path(directory), names=[])
        self.assertTrue(report["findings"])
        for finding in report["findings"]:
            self.assertEqual([], contracts.validate_instance(finding, schema))
            self.assertEqual(
                [], contracts.semantic_errors("finding.schema.json", finding, rules)
            )

    def test_fingerprints_are_deterministic(self) -> None:
        first = secret_watch.make_finding(
            check_id="fixture-check",
            repository=EXAMPLE_REPOSITORY,
            category="secret-hygiene",
            severity="warning",
            rule_id="unexpected-secret-name",
            location=secret_watch.POLICY_LOCATION,
            summary="First redacted wording.",
            detected_at=NOW,
            runbook_ref=secret_watch.RUNBOOKS["missing-required-secret"],
        )
        second = copy.deepcopy(first)
        second["evidence"]["summary"] = "Different redacted wording."
        second["detected_at"] = "2026-07-15T10:00:00Z"
        second["fingerprint"] = secret_watch._fingerprint(second)
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_report_output_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = self.write_policy(root)
            metadata_path = self.write_metadata(root, ["REQUIRED_SECRET"])
            first = secret_watch.run_secret_watch(
                policy_path, {}, metadata_fixture=metadata_path, detected_at=NOW
            )
            second = secret_watch.run_secret_watch(
                policy_path, {}, metadata_fixture=metadata_path, detected_at=NOW
            )
            first_path = root / "first.json"
            second_path = root / "second.json"
            secret_watch.write_report(first_path, first)
            secret_watch.write_report(second_path, second)
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
