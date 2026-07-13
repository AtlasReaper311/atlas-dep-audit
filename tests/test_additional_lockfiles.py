from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import audit


class AdditionalLockfileTests(unittest.TestCase):
    def test_poetry_lock_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "poetry.lock"
            lock.write_text(
                '[[package]]\nname = "httpx"\nversion = "0.28.1"\ncategory = "main"\n',
                encoding="utf-8",
            )
            components, findings = audit.poetry_lock_components(lock, root)
            self.assertEqual(findings, [])
            self.assertEqual(len(components), 1)
            self.assertEqual(components[0].purl, "pkg:pypi/httpx@0.28.1")

    def test_pipfile_lock_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "Pipfile.lock"
            lock.write_text(
                json.dumps(
                    {
                        "default": {"requests": {"version": "==2.32.4"}},
                        "develop": {"pytest": {"version": "==8.4.1"}},
                    }
                ),
                encoding="utf-8",
            )
            components, findings = audit.pipfile_lock_components(lock, root)
            self.assertEqual(findings, [])
            self.assertEqual({item.name for item in components}, {"requests", "pytest"})
            self.assertEqual(
                {item.scope for item in components}, {"required", "development"}
            )


if __name__ == "__main__":
    unittest.main()
