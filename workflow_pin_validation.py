#!/usr/bin/env python3
"""Validate that atlas-dep-audit self-tooling checkout pins are main-reachable.

A tooling revision must be an immutable 40-character commit SHA and an ancestor
of the repository default branch. Existence on another branch, or mere
fetchability of the Git object, is not enough.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_WORKFLOWS = ROOT / ".github" / "workflows"
SELF_REPOSITORY = "AtlasReaper311/atlas-dep-audit"
CHECKOUT_USES_RE = re.compile(
    r"^(?P<prefix>\s*(?:-\s*)?)uses:\s*['\"]?(?P<uses>actions/checkout@[^'\"\s#]+)['\"]?\s*(?:#.*)?$"
)
MAPPING_RE = re.compile(r"^(\s*)([A-Za-z0-9_-]+):\s*(.*?)\s*$")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PinValidationError(ValueError):
    """Raised when a workflow self-tooling pin is missing or not main-reachable."""


@dataclass(frozen=True)
class CheckoutStep:
    path: Path
    line: int
    uses: str
    repository: str | None
    ref: str | None


def strip_yaml_scalar(value: str) -> str:
    text = value.split("#", 1)[0].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def parse_checkout_steps(text: str, path: Path) -> list[CheckoutStep]:
    """Parse the small GitHub Actions subset needed for checkout pin checks."""
    lines = text.splitlines()
    steps: list[CheckoutStep] = []

    for index, line in enumerate(lines):
        match = CHECKOUT_USES_RE.match(line)
        if not match:
            continue

        # Sibling keys align under the `uses` key, including the common
        # `- uses:` form where the dash shares the list-item line.
        uses_indent = line.index("uses:")
        uses = match.group("uses")
        repository: str | None = None
        ref: str | None = None
        in_with = False
        cursor = index + 1

        while cursor < len(lines):
            raw = lines[cursor]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                cursor += 1
                continue

            indent = len(raw) - len(raw.lstrip(" "))
            if indent < uses_indent:
                break

            mapping = MAPPING_RE.match(raw)
            if mapping is None:
                cursor += 1
                continue

            key_indent = len(mapping.group(1))
            key = mapping.group(2)
            value = strip_yaml_scalar(mapping.group(3))

            if not in_with:
                if key_indent != uses_indent:
                    break
                if key == "with":
                    in_with = True
                    cursor += 1
                    continue
                break

            if key_indent <= uses_indent:
                break
            if key == "repository":
                repository = value or None
            elif key == "ref":
                ref = value or None
            cursor += 1

        steps.append(
            CheckoutStep(
                path=path,
                line=index + 1,
                uses=uses,
                repository=repository,
                ref=ref,
            )
        )

    return steps


def discover_workflow_files(workflows_dir: Path) -> list[Path]:
    if not workflows_dir.is_dir():
        raise PinValidationError(f"workflows directory not found: {workflows_dir}")
    files = sorted(
        [
            *workflows_dir.glob("*.yml"),
            *workflows_dir.glob("*.yaml"),
        ]
    )
    if not files:
        raise PinValidationError(f"no workflow files found in {workflows_dir}")
    return files


def collect_self_tooling_pins(
    workflows_dir: Path,
) -> list[CheckoutStep]:
    pins: list[CheckoutStep] = []
    for path in discover_workflow_files(workflows_dir):
        text = path.read_text(encoding="utf-8")
        for step in parse_checkout_steps(text, path):
            if step.repository == SELF_REPOSITORY:
                pins.append(step)
    return pins


def is_full_commit_sha(value: str | None) -> bool:
    return isinstance(value, str) and FULL_SHA_RE.fullmatch(value) is not None


def git_is_ancestor(*, repo_root: Path, commit: str, main_ref: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", commit, main_ref],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    detail = (completed.stderr or completed.stdout or "git merge-base failed").strip()
    raise PinValidationError(
        f"cannot determine ancestry of {commit} against {main_ref}: {detail}"
    )


def validate_self_tooling_pins(
    *,
    workflows_dir: Path,
    repo_root: Path,
    main_ref: str,
) -> list[CheckoutStep]:
    pins = collect_self_tooling_pins(workflows_dir)
    if not pins:
        raise PinValidationError(
            "no AtlasReaper311/atlas-dep-audit self-tooling checkout pins found"
        )

    for pin in pins:
        location = f"{pin.path}:{pin.line}"
        if not pin.ref:
            raise PinValidationError(
                f"{location}: self-tooling checkout is missing an immutable ref"
            )
        if not is_full_commit_sha(pin.ref):
            raise PinValidationError(
                f"{location}: self-tooling ref must be a full 40-character commit "
                f"SHA, observed {pin.ref!r}"
            )
        if not git_is_ancestor(repo_root=repo_root, commit=pin.ref, main_ref=main_ref):
            raise PinValidationError(
                f"{location}: self-tooling ref {pin.ref} is not an ancestor of "
                f"{main_ref}"
            )
    return pins


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Git repository root used for ancestry checks",
    )
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        help="Directory containing GitHub Actions workflows",
    )
    parser.add_argument(
        "--main-ref",
        default="origin/main",
        help="Main branch ref that tooling pins must be ancestors of",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = args.repo_root.resolve()
    workflows_dir = (
        args.workflows_dir.resolve()
        if args.workflows_dir is not None
        else (repo_root / ".github" / "workflows")
    )
    try:
        pins = validate_self_tooling_pins(
            workflows_dir=workflows_dir,
            repo_root=repo_root,
            main_ref=args.main_ref,
        )
    except PinValidationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"validated {len(pins)} main-reachable self-tooling pin(s)")
    for pin in pins:
        print(f"- {pin.path}:{pin.line} -> {pin.ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
