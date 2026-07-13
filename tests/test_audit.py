import json
import tempfile
import unittest
from pathlib import Path

import audit


class AuditTests(unittest.TestCase):
    def test_package_lock_v3(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "package-lock.json"
            lock.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "sample", "version": "1.0.0"},
                            "node_modules/example": {
                                "version": "2.3.4",
                                "license": "MIT",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            components, findings = audit.npm_components(lock, root)
            self.assertEqual([], findings)
            self.assertEqual(1, len(components))
            self.assertEqual("example", components[0].name)
            self.assertEqual("pkg:npm/example@2.3.4", components[0].purl)

    def test_requirements_flags_unpinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            requirements.write_text("fastapi==0.115.0\nhttpx>=0.27\n", encoding="utf-8")
            components, findings = audit.requirements_components(requirements, root, "owner/repo")
            self.assertEqual(1, len(components))
            self.assertEqual(1, len(findings))
            self.assertEqual("python-unpinned", findings[0].rule)

    def test_action_pinning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text(
                "steps:\n  - uses: actions/checkout@v4\n  - uses: owner/action@0123456789012345678901234567890123456789\n",
                encoding="utf-8",
            )
            actions, findings = audit.parse_actions(root, "owner/repo")
            self.assertEqual(2, len(actions))
            self.assertEqual(1, len(findings))

    def test_cvss_v31_score(self):
        score = audit.cvss_v3_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        self.assertEqual(9.8, score)
        self.assertEqual("critical", audit.severity_from_score(score))


if __name__ == "__main__":
    unittest.main()
