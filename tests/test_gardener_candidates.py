from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import gardener_candidates
import gardener_findings


class GardenerCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.infra = Path(os.environ["ATLAS_INFRA_ROOT"]).resolve()
        cls.rules = gardener_findings.load_object(
            cls.infra / "contracts/v1/fingerprint-rules.json", "fingerprint rules"
        )
        cls.schema = gardener_findings.load_object(
            cls.infra / "contracts/v1/finding.schema.json", "Finding schema"
        )
        cls.contracts = gardener_findings.load_contract_module(cls.infra)
        cls.repository = "AtlasReaper311/example"
        cls.detected_at = "2026-09-10T20:00:00Z"

    def write_json(self, path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def vulnerability(
        self,
        *,
        dependency: str,
        version: str,
        fixed: str | None,
        source_file: str,
        vulnerability_id: str = "GHSA-test-0001",
        severity: str = "high",
    ) -> dict:
        return {
            "repo": self.repository,
            "dependency": dependency,
            "version": version,
            "vulnerability_id": vulnerability_id,
            "severity": severity,
            "fixed_version": fixed,
            "source_file": source_file,
        }

    def report(self, *, vulnerabilities: list[dict] | None = None, policy: list[dict] | None = None) -> dict:
        return {
            "schema": "atlas-supply-chain-report/v1",
            "vulnerabilities": vulnerabilities or [],
            "policy_findings": policy or [],
        }

    def validate_findings(self, findings: list[dict]) -> None:
        for finding in findings:
            errors = self.contracts.validate_instance(finding, self.schema)
            self.assertEqual([], errors)

    def test_direct_npm_same_major_vulnerability_becomes_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_json(
                root / "package.json",
                {
                    "name": "fixture",
                    "dependencies": {"fast-uri": "^3.1.5"},
                },
            )
            self.write_json(
                root / "package-lock.json",
                {
                    "name": "fixture",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"fast-uri": "^3.1.5"}},
                        "node_modules/fast-uri": {"version": "3.1.5"},
                    },
                },
            )
            findings = gardener_candidates.dependency_findings(
                self.report(
                    vulnerabilities=[
                        self.vulnerability(
                            dependency="fast-uri",
                            version="3.1.5",
                            fixed="3.1.7",
                            source_file="package-lock.json",
                        )
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
            )
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertTrue(finding["remediation"]["eligible"])
        candidate = finding["remediation"]["candidate"]
        self.assertEqual("dependency-update", candidate["kind"])
        self.assertEqual("npm", candidate["ecosystem"])
        self.assertEqual("package.json", candidate["source_file"])
        self.assertEqual("3.1.7", candidate["target_version"])
        self.assertEqual("patch", candidate["update_class"])
        self.assertRegex(finding["location"], r"^package\.json:[1-9][0-9]*$")
        self.validate_findings(findings)

    def test_transitive_npm_vulnerability_remains_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_json(root / "package.json", {"name": "fixture", "dependencies": {}})
            self.write_json(
                root / "package-lock.json",
                {
                    "name": "fixture",
                    "lockfileVersion": 3,
                    "packages": {"node_modules/fast-uri": {"version": "3.1.5"}},
                },
            )
            findings = gardener_candidates.dependency_findings(
                self.report(
                    vulnerabilities=[
                        self.vulnerability(
                            dependency="fast-uri",
                            version="3.1.5",
                            fixed="3.1.7",
                            source_file="package-lock.json",
                        )
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
            )
        self.assertEqual(1, len(findings))
        self.assertFalse(findings[0]["remediation"]["eligible"])
        self.assertNotIn("candidate", findings[0]["remediation"])
        self.validate_findings(findings)

    def test_python_exact_pin_with_extras_becomes_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "uvicorn[standard]==0.52.4\n",
                encoding="utf-8",
            )
            findings = gardener_candidates.dependency_findings(
                self.report(
                    vulnerabilities=[
                        self.vulnerability(
                            dependency="uvicorn",
                            version="0.52.4",
                            fixed="0.53.1",
                            source_file="requirements.txt",
                        )
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
            )
        self.assertEqual(1, len(findings))
        candidate = findings[0]["remediation"]["candidate"]
        self.assertEqual("PyPI", candidate["ecosystem"])
        self.assertEqual("minor", candidate["update_class"])
        self.assertEqual("requirements.txt:1", findings[0]["location"])
        self.validate_findings(findings)

    def test_major_only_fixed_version_remains_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("example==1.9.0\n", encoding="utf-8")
            findings = gardener_candidates.dependency_findings(
                self.report(
                    vulnerabilities=[
                        self.vulnerability(
                            dependency="example",
                            version="1.9.0",
                            fixed="2.0.0",
                            source_file="requirements.txt",
                        )
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
            )
        self.assertFalse(findings[0]["remediation"]["eligible"])
        self.assertIn("same-major", findings[0]["remediation"]["reason"])

    def test_simple_docker_hub_tag_becomes_digest_candidate(self) -> None:
        digest = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
            findings = gardener_candidates.container_findings(
                self.report(
                    policy=[
                        {
                            "repo": self.repository,
                            "severity": "info",
                            "rule": "container-digest",
                            "path": "Dockerfile",
                            "message": (
                                gardener_candidates.CONTAINER_MESSAGE_PREFIX
                                + "python:3.12-slim"
                            ),
                        }
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
                resolver=lambda _: digest,
            )
        self.assertEqual(1, len(findings))
        candidate = findings[0]["remediation"]["candidate"]
        self.assertEqual("container-digest-pin", candidate["kind"])
        self.assertEqual(digest, candidate["target_digest"])
        self.assertEqual("Dockerfile:1", findings[0]["location"])
        self.validate_findings(findings)

    def test_named_build_stage_is_not_exported_as_container_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(
                "FROM node:24 AS build\nFROM nginx:1.28\n",
                encoding="utf-8",
            )
            findings = gardener_candidates.container_findings(
                self.report(
                    policy=[
                        {
                            "repo": self.repository,
                            "severity": "info",
                            "rule": "container-digest",
                            "path": "Dockerfile",
                            "message": gardener_candidates.CONTAINER_MESSAGE_PREFIX + "node:24",
                        }
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
                resolver=lambda _: "sha256:" + "b" * 64,
            )
        self.assertEqual([], findings)

    def test_non_docker_hub_registry_remains_observation_without_resolution(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("FROM ghcr.io/example/app:1.2.3\n", encoding="utf-8")
            findings = gardener_candidates.container_findings(
                self.report(
                    policy=[
                        {
                            "repo": self.repository,
                            "severity": "info",
                            "rule": "container-digest",
                            "path": "Dockerfile",
                            "message": gardener_candidates.CONTAINER_MESSAGE_PREFIX + "ghcr.io/example/app:1.2.3",
                        }
                    ]
                ),
                repositories={self.repository: root},
                covered={self.repository},
                detected_at=self.detected_at,
                run_url="",
                rules=self.rules,
                resolver=lambda reference: calls.append(reference) or "sha256:" + "c" * 64,
            )
        self.assertEqual([], calls)
        self.assertEqual(1, len(findings))
        self.assertFalse(findings[0]["remediation"]["eligible"])
        self.assertIn("Docker Hub", findings[0]["remediation"]["reason"])


if __name__ == "__main__":
    unittest.main()
