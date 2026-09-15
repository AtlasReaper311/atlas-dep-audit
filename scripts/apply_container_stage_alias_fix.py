#!/usr/bin/env python3
"""Apply the bounded Docker stage-alias parser fix for the maintenance branch."""

from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"expected exactly one replacement target in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    audit = Path("audit.py")
    old_parser = '''    for path in sorted(dockerfiles):
        relative = str(path.relative_to(repo_root))
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line.upper().startswith("FROM "):
                continue
            reference = line.split()[1]
            pinned = "@sha256:" in reference
            bases.append(
                {
                    "path": relative,
                    "reference": reference,
                    "digest_pinned": str(pinned).lower(),
                }
            )
            if not pinned:
                findings.append(
                    PolicyFinding(
                        repo,
                        "info",
                        "container-digest",
                        relative,
                        f"Container base is tag-pinned rather than digest-pinned: {reference}",
                    )
                )
'''
    new_parser = '''    for path in sorted(dockerfiles):
        relative = str(path.relative_to(repo_root))
        stage_aliases: set[str] = set()
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line.upper().startswith("FROM "):
                continue
            tokens = line.split()
            reference = tokens[1]
            internal_stage = reference in stage_aliases
            if len(tokens) >= 4 and tokens[2].upper() == "AS":
                stage_aliases.add(tokens[3])
            if internal_stage:
                continue
            pinned = "@sha256:" in reference
            bases.append(
                {
                    "path": relative,
                    "reference": reference,
                    "digest_pinned": str(pinned).lower(),
                }
            )
            if not pinned:
                findings.append(
                    PolicyFinding(
                        repo,
                        "info",
                        "container-digest",
                        relative,
                        f"Container base is tag-pinned rather than digest-pinned: {reference}",
                    )
                )
'''
    replace_once(audit, old_parser, new_parser)

    tests = Path("tests/test_audit.py")
    anchor = '''    def test_osv_query_uses_versioned_purl_without_duplicate_version(self):
'''
    regression = '''    def test_container_bases_ignore_internal_stage_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(
                "FROM python:3.14-slim AS base\\n"
                "FROM base AS dev\\n"
                "FROM base AS prod\\n",
                encoding="utf-8",
            )
            bases, findings = audit.parse_container_bases(root, "owner/repo")
            self.assertEqual(
                [
                    {
                        "path": "Dockerfile",
                        "reference": "python:3.14-slim",
                        "digest_pinned": "false",
                    }
                ],
                bases,
            )
            self.assertEqual(1, len(findings))
            self.assertEqual("container-digest", findings[0].rule)
            self.assertIn("python:3.14-slim", findings[0].message)

'''
    replace_once(tests, anchor, regression + anchor)


if __name__ == "__main__":
    main()
