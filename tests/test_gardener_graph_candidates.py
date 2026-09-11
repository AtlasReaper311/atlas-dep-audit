from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import gardener_findings
import gardener_graph_candidates as graph


class GardenerGraphCandidateTests(unittest.TestCase):
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

    def write_json(self, path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def vulnerability(self, dependency: str, version: str, fixed: str | None, source: str, vuln_id: str) -> dict:
        return {
            "repo": self.repository,
            "dependency": dependency,
            "version": version,
            "fixed_version": fixed,
            "vulnerability_id": vuln_id,
            "severity": "high",
            "source_file": source,
        }

    def validate(self, finding: dict) -> None:
        self.assertEqual([], self.contracts.validate_instance(finding, self.schema))

    def test_transitive_lock_target_becomes_graph_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_json(root / "package.json", {
                "name": "fixture",
                "dependencies": {"parent": "^2.0.0"},
            })
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })

            def runner(work: Path, names: list[str]) -> None:
                self.assertEqual(["vuln"], names)
                lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
                lock["packages"]["node_modules/vuln"]["version"] = "1.0.1"
                self.write_json(work / "package-lock.json", lock)

            candidate = graph.build_npm_graph_candidate(
                self.repository,
                root,
                "package-lock.json",
                [self.vulnerability("vuln", "1.0.0", "1.0.1", "package-lock.json", "GHSA-vuln")],
                npm_runner=runner,
                vulnerability_checker=lambda *_: set(),
            )
        self.assertEqual("npm-lock-security-remediation", candidate["kind"])
        self.assertEqual([], candidate["direct_updates"])
        self.assertEqual("vuln", candidate["transitive_updates"][0]["dependency"])
        self.assertEqual("^1.0.0", candidate["transitive_updates"][0]["parents"][0]["specifier"])
        self.assertEqual(graph.NPM_VERSION, candidate["npm_version"])

    def test_exact_transitive_constraint_uses_direct_ancestor_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_json(root / "package.json", {
                "name": "fixture",
                "devDependencies": {"wrangler": "^4.127.0"},
            })
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"wrangler": "^4.127.0"}},
                    "node_modules/wrangler": {"version": "4.127.0", "dependencies": {"miniflare": "^5.0.0"}},
                    "node_modules/miniflare": {"version": "5.0.0", "dependencies": {"sharp": "0.35.2"}},
                    "node_modules/sharp": {"version": "0.35.2"},
                },
            })

            def runner(work: Path, names: list[str]) -> None:
                self.assertEqual(["wrangler"], names)
                lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
                lock["packages"]["node_modules/wrangler"]["version"] = "4.131.0"
                lock["packages"]["node_modules/miniflare"]["version"] = "5.1.0"
                lock["packages"]["node_modules/miniflare"]["dependencies"]["sharp"] = "0.35.4"
                lock["packages"]["node_modules/sharp"]["version"] = "0.35.4"
                self.write_json(work / "package-lock.json", lock)

            candidate = graph.build_npm_graph_candidate(
                self.repository,
                root,
                "package-lock.json",
                [self.vulnerability("sharp", "0.35.2", "0.35.4", "package-lock.json", "GHSA-sharp")],
                npm_runner=runner,
                vulnerability_checker=lambda *_: set(),
            )
        self.assertEqual([], candidate["transitive_updates"])
        direct = candidate["direct_updates"][0]
        self.assertEqual("wrangler", direct["dependency"])
        self.assertEqual("4.127.0", direct["current_version"])
        self.assertEqual("4.131.0", direct["target_version"])
        self.assertEqual("^4.127.0", direct["current_spec"])
        self.assertEqual("^4.127.0", direct["target_spec"])
        self.assertEqual(["GHSA-sharp"], direct["vulnerability_ids"])

    def test_post_regeneration_vulnerability_presence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_json(root / "package.json", {"name": "fixture", "dependencies": {"vuln": "^1.0.0"}})
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })

            def runner(work: Path, names: list[str]) -> None:
                lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
                lock["packages"]["node_modules/vuln"]["version"] = "1.0.1"
                self.write_json(work / "package-lock.json", lock)

            with self.assertRaisesRegex(graph.GraphCandidateError, "still reports"):
                graph.build_npm_graph_candidate(
                    self.repository,
                    root,
                    "package-lock.json",
                    [self.vulnerability("vuln", "1.0.0", "1.0.1", "package-lock.json", "GHSA-vuln")],
                    npm_runner=runner,
                    vulnerability_checker=lambda *_: {"GHSA-vuln"},
                )

    def test_no_published_python_fix_gets_explicit_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("chromadb==0.5.23\n", encoding="utf-8")
            findings = graph.dependency_findings(
                {"vulnerabilities": [self.vulnerability("chromadb", "0.5.23", None, "requirements.txt", "GHSA-chroma")]},
                repositories={self.repository: root},
                covered={self.repository},
                detected_at="2026-09-11T09:00:00Z",
                run_url="",
                rules=self.rules,
            )
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertFalse(finding["remediation"]["eligible"])
        self.assertEqual("awaiting-upstream-fix", finding["remediation"]["disposition"])
        self.validate(finding)

    def test_graph_finding_validates_against_accepted_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_json(root / "package.json", {"name": "fixture", "dependencies": {"parent": "^2.0.0"}})
            self.write_json(root / "package-lock.json", {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "^2.0.0"}},
                    "node_modules/parent": {"version": "2.0.0", "dependencies": {"vuln": "^1.0.0"}},
                    "node_modules/vuln": {"version": "1.0.0"},
                },
            })

            def runner(work: Path, names: list[str]) -> None:
                lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
                lock["packages"]["node_modules/vuln"]["version"] = "1.0.1"
                self.write_json(work / "package-lock.json", lock)

            findings = graph.dependency_findings(
                {"vulnerabilities": [self.vulnerability("vuln", "1.0.0", "1.0.1", "package-lock.json", "GHSA-vuln")]},
                repositories={self.repository: root},
                covered={self.repository},
                detected_at="2026-09-11T09:00:00Z",
                run_url="",
                rules=self.rules,
                npm_runner=runner,
                vulnerability_checker=lambda *_: set(),
            )
        self.assertEqual(1, len(findings))
        self.assertEqual("remediation-available", findings[0]["remediation"]["disposition"])
        self.validate(findings[0])


if __name__ == "__main__":
    unittest.main()
