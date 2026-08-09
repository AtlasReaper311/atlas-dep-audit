from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "workflow_pin_validation.py"
SPEC = importlib.util.spec_from_file_location("workflow_pin_validation", SCRIPT)
assert SPEC and SPEC.loader
VALIDATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATE
SPEC.loader.exec_module(VALIDATE)

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "private-repository-audit.yml"


def run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_ancestry_fixture(root: Path) -> dict[str, str]:
    """Build:

            A
            |
            B -------- C     main
             \
              D               feature-only
    """
    repo = root / "git-repo"
    repo.mkdir()
    run_git(repo, "init")
    run_git(repo, "config", "user.name", "atlas-dep-audit-tests")
    run_git(repo, "config", "user.email", "atlas-dep-audit-tests@example.com")
    run_git(repo, "checkout", "-b", "main")

    write(repo / "README.md", "A\n")
    run_git(repo, "add", "README.md")
    run_git(repo, "commit", "-m", "A")
    commit_a = run_git(repo, "rev-parse", "HEAD")

    write(repo / "README.md", "B\n")
    run_git(repo, "add", "README.md")
    run_git(repo, "commit", "-m", "B")
    commit_b = run_git(repo, "rev-parse", "HEAD")

    run_git(repo, "checkout", "-b", "feature-only")
    write(repo / "README.md", "D\n")
    run_git(repo, "add", "README.md")
    run_git(repo, "commit", "-m", "D")
    commit_d = run_git(repo, "rev-parse", "HEAD")

    run_git(repo, "checkout", "main")
    write(repo / "README.md", "C\n")
    run_git(repo, "add", "README.md")
    run_git(repo, "commit", "-m", "C")
    commit_c = run_git(repo, "rev-parse", "HEAD")

    return {
        "repo": str(repo),
        "A": commit_a,
        "B": commit_b,
        "C": commit_c,
        "D": commit_d,
    }


def workflow_with_pin(ref: str | None, *, include_repository: bool = True) -> str:
    lines = [
        "name: Fixture",
        "jobs:",
        "  audit:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Check out caller repository",
        "        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "        with:",
        "          path: target",
        "      - name: Check out pinned audit tooling",
        "        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "        with:",
    ]
    if include_repository:
        lines.append("          repository: AtlasReaper311/atlas-dep-audit")
    if ref is not None:
        lines.append(f"          ref: {ref}")
    lines.append("          path: .audit-tooling")
    lines.append("")
    return "\n".join(lines)


class WorkflowPinParserTests(unittest.TestCase):
    def test_parser_reads_self_tooling_and_ignores_caller_checkout(self) -> None:
        text = workflow_with_pin("fc565353c83f19d117ed3c3173d667429a672f66")
        steps = VALIDATE.parse_checkout_steps(text, Path("fixture.yml"))
        self.assertEqual(2, len(steps))
        self.assertIsNone(steps[0].repository)
        self.assertIsNone(steps[0].ref)
        self.assertEqual("AtlasReaper311/atlas-dep-audit", steps[1].repository)
        self.assertEqual(
            "fc565353c83f19d117ed3c3173d667429a672f66",
            steps[1].ref,
        )

    def test_parser_ignores_unrelated_repository_checkouts(self) -> None:
        text = """
jobs:
  audit:
    steps:
      - uses: actions/checkout@v4
        with:
          repository: AtlasReaper311/atlas-infra
          ref: 1c9e37055818a6141d46e92ecf15ec40922279b8
"""
        steps = VALIDATE.parse_checkout_steps(text, Path("fixture.yml"))
        self.assertEqual(1, len(steps))
        pins = [
            step
            for step in steps
            if step.repository == VALIDATE.SELF_REPOSITORY
        ]
        self.assertEqual([], pins)

    def test_parser_strips_quotes_and_inline_comments(self) -> None:
        text = """
jobs:
  audit:
    steps:
      - uses: actions/checkout@abc # comment
        with:
          repository: "AtlasReaper311/atlas-dep-audit" # repo
          ref: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' # pin
"""
        steps = VALIDATE.parse_checkout_steps(text, Path("fixture.yml"))
        self.assertEqual(1, len(steps))
        self.assertEqual("AtlasReaper311/atlas-dep-audit", steps[0].repository)
        self.assertEqual("a" * 40, steps[0].ref)


class WorkflowPinValidationTests(unittest.TestCase):
    def test_full_sha_on_main_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            workflows = repo / ".github" / "workflows"
            write(workflows / "private.yml", workflow_with_pin(fixture["C"]))
            pins = VALIDATE.validate_self_tooling_pins(
                workflows_dir=workflows,
                repo_root=repo,
                main_ref="main",
            )
            self.assertEqual(1, len(pins))
            self.assertEqual(fixture["C"], pins[0].ref)

    def test_feature_only_commit_is_rejected_even_when_object_exists(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            # Prove the off-main object is present in the local repository.
            self.assertEqual("commit", run_git(repo, "cat-file", "-t", fixture["D"]))
            workflows = repo / ".github" / "workflows"
            write(workflows / "private.yml", workflow_with_pin(fixture["D"]))
            with self.assertRaisesRegex(
                VALIDATE.PinValidationError,
                "not an ancestor of main",
            ):
                VALIDATE.validate_self_tooling_pins(
                    workflows_dir=workflows,
                    repo_root=repo,
                    main_ref="main",
                )

    def test_short_sha_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            workflows = repo / ".github" / "workflows"
            write(workflows / "private.yml", workflow_with_pin(fixture["C"][:12]))
            with self.assertRaisesRegex(
                VALIDATE.PinValidationError,
                "full 40-character commit SHA",
            ):
                VALIDATE.validate_self_tooling_pins(
                    workflows_dir=workflows,
                    repo_root=repo,
                    main_ref="main",
                )

    def test_branch_name_ref_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            workflows = repo / ".github" / "workflows"
            write(workflows / "private.yml", workflow_with_pin("main"))
            with self.assertRaisesRegex(
                VALIDATE.PinValidationError,
                "full 40-character commit SHA",
            ):
                VALIDATE.validate_self_tooling_pins(
                    workflows_dir=workflows,
                    repo_root=repo,
                    main_ref="main",
                )

    def test_tag_like_ref_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            workflows = repo / ".github" / "workflows"
            write(workflows / "private.yml", workflow_with_pin("v1.2.3"))
            with self.assertRaisesRegex(
                VALIDATE.PinValidationError,
                "full 40-character commit SHA",
            ):
                VALIDATE.validate_self_tooling_pins(
                    workflows_dir=workflows,
                    repo_root=repo,
                    main_ref="main",
                )

    def test_missing_self_tooling_ref_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            workflows = repo / ".github" / "workflows"
            write(workflows / "private.yml", workflow_with_pin(None))
            with self.assertRaisesRegex(
                VALIDATE.PinValidationError,
                "missing an immutable ref",
            ):
                VALIDATE.validate_self_tooling_pins(
                    workflows_dir=workflows,
                    repo_root=repo,
                    main_ref="main",
                )

    def test_ordinary_caller_checkout_is_ignored(self) -> None:
        text = """
jobs:
  audit:
    steps:
      - name: Check out caller repository
        uses: actions/checkout@v4
        with:
          path: target
"""
        steps = VALIDATE.parse_checkout_steps(text, Path("fixture.yml"))
        self.assertEqual(1, len(steps))
        self.assertIsNone(steps[0].repository)
        pins = [
            step
            for step in steps
            if step.repository == VALIDATE.SELF_REPOSITORY
        ]
        self.assertEqual([], pins)

    def test_no_applicable_self_tooling_checkout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            fixture = build_ancestry_fixture(Path(value))
            repo = Path(fixture["repo"])
            workflows = repo / ".github" / "workflows"
            write(
                workflows / "ci.yml",
                """
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: AtlasReaper311/atlas-infra
          ref: 1c9e37055818a6141d46e92ecf15ec40922279b8
""",
            )
            with self.assertRaisesRegex(
                VALIDATE.PinValidationError,
                "no AtlasReaper311/atlas-dep-audit self-tooling checkout pins found",
            ):
                VALIDATE.validate_self_tooling_pins(
                    workflows_dir=workflows,
                    repo_root=repo,
                    main_ref="main",
                )

    def test_current_private_repository_audit_passes_against_origin_main(self) -> None:
        pins = VALIDATE.validate_self_tooling_pins(
            workflows_dir=REPO_ROOT / ".github" / "workflows",
            repo_root=REPO_ROOT,
            main_ref="origin/main",
        )
        self.assertGreaterEqual(len(pins), 1)
        self.assertTrue(any(pin.path == PRIVATE_WORKFLOW for pin in pins))
        for pin in pins:
            self.assertRegex(pin.ref or "", r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
