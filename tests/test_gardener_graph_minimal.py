from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import gardener_graph_minimal as graph


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class GardenerGraphMinimalTests(unittest.TestCase):
    def write_json(self, path: Path, value: dict) -> bytes:
        data = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return data

    def vulnerability(self) -> dict:
        return {
            "repo": "AtlasReaper311/example",
            "dependency": "brace-expansion",
            "version": "5.0.7",
            "fixed_version": "5.0.9",
            "vulnerability_id": "GHSA-example",
            "severity": "high",
            "source_file": "package-lock.json",
        }

    def test_transitive_overlay_preserves_unrelated_lock_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_json(
                root / "package.json",
                {"name": "fixture", "devDependencies": {"minimatch": "^10.0.0"}},
            )
            original_lock = {
                "name": "fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {"devDependencies": {"minimatch": "^10.0.0"}},
                    "node_modules/minimatch": {
                        "version": "10.0.0",
                        "dependencies": {"brace-expansion": "^5.0.5"},
                    },
                    "node_modules/brace-expansion": {
                        "version": "5.0.7",
                        "resolved": "old",
                        "integrity": "old",
                    },
                    "node_modules/native-optional": {
                        "version": "1.0.0",
                        "optional": True,
                        "libc": ["glibc"],
                    },
                },
            }
            self.write_json(root / "package-lock.json", original_lock)

            expected_lock = json.loads(json.dumps(original_lock))
            expected_lock["packages"]["node_modules/brace-expansion"] = {
                "version": "5.0.9",
                "resolved": "new",
                "integrity": "new",
            }
            expected_bytes = (json.dumps(expected_lock, indent=2) + "\n").encode("utf-8")

            def noisy_npm(work: Path, names: list[str]) -> None:
                self.assertEqual(["brace-expansion"], names)
                lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
                lock["packages"]["node_modules/brace-expansion"] = {
                    "version": "5.0.9",
                    "resolved": "new",
                    "integrity": "new",
                }
                lock["packages"]["node_modules/native-optional"].pop("libc")
                self.write_json(work / "package-lock.json", lock)

            candidate = graph.build_npm_graph_candidate(
                "AtlasReaper311/example",
                root,
                "package-lock.json",
                [self.vulnerability()],
                npm_runner=noisy_npm,
                vulnerability_checker=lambda *_: set(),
            )

        self.assertEqual(digest(manifest), candidate["target_manifest_sha256"])
        self.assertEqual(digest(expected_bytes), candidate["target_lockfile_sha256"])
        self.assertEqual([], candidate["direct_updates"])
        self.assertEqual(
            "node_modules/brace-expansion",
            candidate["transitive_updates"][0]["package_path"],
        )


if __name__ == "__main__":
    unittest.main()
