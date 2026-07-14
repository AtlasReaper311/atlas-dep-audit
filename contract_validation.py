#!/usr/bin/env python3
"""Invoke the allowlisted atlas-infra contract validator safely."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

CONTRACT_OWNER = "AtlasReaper311/atlas-infra"
REPORT_SCHEMA = "atlas-control-plane/validation-report/v1"
EXPECTED_SCHEMA_COUNT = 8
SAFE_ENVIRONMENT_KEYS = (
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONIOENCODING",
    "SYSTEMROOT",
    "TMPDIR",
    "WINDIR",
)


@dataclass(frozen=True)
class ContractValidationResult:
    repository: str
    status: str
    schemas_checked: int
    fixtures_checked: int
    positive_fixtures: int
    negative_fixtures: int
    idempotent: bool
    error: str

    def provenance(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload["error"]:
            payload.pop("error")
        return payload


def scrubbed_environment() -> dict[str, str]:
    """Pass runtime basics only; never forward repository or provider tokens."""
    environment = {
        key: os.environ[key]
        for key in SAFE_ENVIRONMENT_KEYS
        if key in os.environ
    }
    environment.setdefault("LANG", "C.UTF-8")
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    return environment


def _failed(message: str) -> ContractValidationResult:
    return ContractValidationResult(
        repository=CONTRACT_OWNER,
        status="failed",
        schemas_checked=0,
        fixtures_checked=0,
        positive_fixtures=0,
        negative_fixtures=0,
        idempotent=False,
        error=message[:500],
    )


def _result_from_report(report: dict[str, Any]) -> ContractValidationResult:
    if report.get("schema_version") != REPORT_SCHEMA:
        return _failed("validator returned an unknown validation-report version")
    if report.get("errors"):
        first_error = str(report["errors"][0])
        return _failed(f"canonical validator reported errors: {first_error}")

    result = ContractValidationResult(
        repository=CONTRACT_OWNER,
        status="passed",
        schemas_checked=int(report.get("schemas_checked", 0)),
        fixtures_checked=int(report.get("fixtures_checked", 0)),
        positive_fixtures=int(report.get("positive_fixtures", 0)),
        negative_fixtures=int(report.get("negative_fixtures", 0)),
        idempotent=report.get("idempotent") is True,
        error="",
    )
    if result.schemas_checked != EXPECTED_SCHEMA_COUNT:
        return _failed(
            f"expected {EXPECTED_SCHEMA_COUNT} schemas, got {result.schemas_checked}"
        )
    if result.positive_fixtures < EXPECTED_SCHEMA_COUNT:
        return _failed("each contract requires a positive fixture")
    if result.negative_fixtures < EXPECTED_SCHEMA_COUNT:
        return _failed("each contract requires a negative fixture")
    if not result.idempotent:
        return _failed("canonical validator did not prove idempotent output")
    return result


def validate_checkout(
    repository: str,
    repository_root: Path,
    *,
    timeout_seconds: int = 60,
) -> ContractValidationResult | None:
    """Validate only the canonical contract owner; never execute other repos."""
    if repository != CONTRACT_OWNER:
        return None
    contract_root = repository_root / "contracts" / "v1"
    if not contract_root.is_dir():
        return _failed("canonical contracts/v1 directory is missing")

    validator = repository_root / "scripts" / "validate_control_plane_contracts.py"
    if not validator.is_file():
        return _failed("contracts/v1 exists but the canonical validator is missing")

    with tempfile.TemporaryDirectory(prefix="atlas-contract-validation-") as directory:
        report_path = Path(directory) / "report.json"
        command = [
            sys.executable,
            str(validator),
            "--root",
            str(repository_root),
            "--report",
            str(report_path),
            "--quiet",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=repository_root,
                env=scrubbed_environment(),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return _failed(f"canonical validator exceeded {timeout_seconds} seconds")
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "validator failed").strip()
            return _failed(f"canonical validator exited {completed.returncode}: {detail}")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as error:
            return _failed(f"canonical validator report is unreadable: {error}")
    if not isinstance(report, dict):
        return _failed("canonical validator report root is not an object")
    return _result_from_report(report)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contracts-root", type=Path, required=True)
    parser.add_argument("--repository", default=CONTRACT_OWNER)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    result = validate_checkout(args.repository, args.contracts_root.resolve())
    if result is None:
        payload: dict[str, Any] = {
            "repository": args.repository,
            "status": "not-applicable",
        }
        exit_code = 0
    else:
        payload = result.provenance()
        exit_code = 1 if result.status == "failed" else 0
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
