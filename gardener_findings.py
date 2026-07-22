#!/usr/bin/env python3
"""Build the attested public Finding bundle consumed by Atlas Gardener."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PRODUCER_VERSION = "1.1.0"
BUNDLE_SCHEMA = "atlas-control-plane/gardener-finding-bundle/v1"
FINDING_SCHEMA = "atlas-control-plane/finding/v1"
REPORT_SCHEMA = "atlas-supply-chain-report/v1"
OWNER = "AtlasReaper311"
RULE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LOCATION_RE = re.compile(
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+(?::[1-9][0-9]*)?$"
)
REPOSITORY_RE = re.compile(r"^AtlasReaper311/[A-Za-z0-9._-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class FindingExportError(ValueError):
    """Raised when the public remediation handoff is incomplete or malformed."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_value(value: Any, *, prefix: str = "sha256:") -> str:
    return prefix + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FindingExportError(f"cannot read valid {label}: {error}") from error
    if not isinstance(value, dict):
        raise FindingExportError(f"{label} must be a JSON object")
    return value


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git failed"
        raise FindingExportError(detail[:300])
    return completed.stdout.strip()


def load_contract_module(infra_root: Path):
    path = infra_root / "scripts/control_plane_contracts.py"
    spec = importlib.util.spec_from_file_location("atlas_control_plane_contracts", path)
    if spec is None or spec.loader is None:
        raise FindingExportError("cannot load canonical contract validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected(value: dict[str, Any], dotted: str) -> Any:
    current: Any = value
    for component in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(component)
    return current


def finding_fingerprint(finding: dict[str, Any], rules: dict[str, Any]) -> str:
    rule = rules.get("rules", {}).get("finding")
    if not isinstance(rule, dict):
        raise FindingExportError("canonical Finding fingerprint rule is missing")
    fields = rule.get("fields")
    prefix = rule.get("prefix")
    if not isinstance(fields, list) or not isinstance(prefix, str):
        raise FindingExportError("canonical Finding fingerprint rule is malformed")
    material = {field: selected(finding, field) for field in fields}
    return digest_value(material, prefix=prefix)


def safe_rule(value: Any) -> str:
    candidate = str(value or "audit-policy").lower()
    return candidate if RULE_RE.fullmatch(candidate) else "audit-policy"


def safe_location(value: Any) -> str:
    candidate = str(value or "repository")[:240]
    return candidate if LOCATION_RE.fullmatch(candidate) else "repository"


def active_ignore_rules(repository_root: Path) -> set[str]:
    path = repository_root / ".gitignore"
    if not path.exists():
        return set()
    data = path.read_bytes()
    if b"\x00" in data:
        raise FindingExportError("binary .gitignore cannot produce housekeeping Findings")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FindingExportError(
            "non-UTF-8 .gitignore cannot produce housekeeping Findings"
        ) from error
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def repository_has_python(repository_root: Path) -> bool:
    markers = {"pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"}
    for path in repository_root.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_file() and (path.name in markers or path.suffix == ".py"):
            return True
    return False


def tracked_artifacts(
    repository_root: Path,
    names: set[str],
    suffixes: set[str],
) -> list[str]:
    paths = git(repository_root, "ls-files", "-z").split("\x00")
    return sorted(
        path
        for path in paths
        if path
        and (
            Path(path).name in names
            or Path(path).suffix.lower() in suffixes
            or (bool(suffixes) and "__pycache__" in Path(path).parts)
        )
    )


def make_finding(
    *,
    repository: str,
    rule_id: str,
    check_id: str,
    category: str,
    severity: str,
    location: str,
    summary: str,
    eligible: bool,
    reason: str,
    detected_at: str,
    run_url: str,
    rules: dict[str, Any],
) -> dict[str, Any]:
    if not REPOSITORY_RE.fullmatch(repository):
        raise FindingExportError("Finding repository identity is invalid")
    if not RULE_RE.fullmatch(rule_id) or not RULE_RE.fullmatch(check_id):
        raise FindingExportError("Finding rule or check identity is invalid")
    finding: dict[str, Any] = {
        "schema_version": FINDING_SCHEMA,
        "source": {
            "producer": "atlas-dep-audit",
            "check_id": check_id,
            "producer_version": PRODUCER_VERSION,
        },
        "subject": {"repository": repository},
        "category": category,
        "severity": severity,
        "rule_id": rule_id,
        "location": safe_location(location),
        "evidence": {
            "summary": summary[:500],
            "references": [run_url] if run_url else [],
            "redacted": True,
        },
        "detected_at": detected_at,
        "fingerprint": "sha256:" + "0" * 64,
        "remediation": {"eligible": eligible, "reason": reason[:240]},
    }
    finding["fingerprint"] = finding_fingerprint(finding, rules)
    return finding


def housekeeping_findings(
    repository: str,
    repository_root: Path,
    *,
    detected_at: str,
    run_url: str,
    rules: dict[str, Any],
) -> list[dict[str, Any]]:
    ignores = active_ignore_rules(repository_root)
    findings: list[dict[str, Any]] = []
    metadata = tracked_artifacts(repository_root, {".DS_Store"}, set())
    if ".DS_Store" not in ignores or metadata:
        detail = "Missing .DS_Store ignore rule."
        if metadata:
            detail += f" {len(metadata)} tracked metadata file(s) also require review."
        findings.append(
            make_finding(
                repository=repository,
                rule_id="macos-metadata-ignore",
                check_id="macos-metadata-ignore",
                category="policy",
                severity="warning",
                location=".gitignore",
                summary=detail,
                eligible=True,
                reason=(
                    "Deterministic housekeeping fixer is allowlisted; "
                    "tracked binary deletion remains review-only."
                ),
                detected_at=detected_at,
                run_url=run_url,
                rules=rules,
            )
        )
    if repository_has_python(repository_root):
        missing = [
            rule for rule in ("*.py[cod]", "__pycache__/") if rule not in ignores
        ]
        caches = tracked_artifacts(
            repository_root,
            set(),
            {".pyc", ".pyo", ".pyd"},
        )
        if missing or caches:
            detail = "Missing Python cache ignore rule(s): " + ", ".join(
                missing or ["none"]
            )
            if caches:
                detail += f"; {len(caches)} tracked cache artifact(s) require review."
            findings.append(
                make_finding(
                    repository=repository,
                    rule_id="python-cache-ignore",
                    check_id="python-cache-ignore",
                    category="policy",
                    severity="warning",
                    location=".gitignore",
                    summary=detail,
                    eligible=True,
                    reason=(
                        "Deterministic housekeeping fixer is allowlisted; "
                        "tracked binary deletion remains review-only."
                    ),
                    detected_at=detected_at,
                    run_url=run_url,
                    rules=rules,
                )
            )
    return findings


def report_findings(
    report: dict[str, Any],
    *,
    detected_at: str,
    run_url: str,
    rules: dict[str, Any],
    covered: set[str],
) -> list[dict[str, Any]]:
    if report.get("schema") != REPORT_SCHEMA:
        raise FindingExportError("unsupported supply-chain report schema")
    policy_values = report.get("policy_findings")
    vulnerability_values = report.get("vulnerabilities")
    if not isinstance(policy_values, list) or not isinstance(
        vulnerability_values,
        list,
    ):
        raise FindingExportError("supply-chain report finding collections are malformed")

    findings: list[dict[str, Any]] = []
    for item in policy_values:
        if not isinstance(item, dict) or item.get("repo") not in covered:
            continue
        repository = str(item["repo"])
        source_rule = safe_rule(item.get("rule"))
        if source_rule == "actions-pin":
            rule_id = "missing-action-pin"
            eligible = True
            reason = (
                "Action pin proposals remain review-only and require an approved "
                "immutable pin map."
            )
        else:
            rule_id = source_rule
            eligible = False
            reason = "No deterministic Gardener fixer is approved for this audit rule."
        severity = (
            "failure"
            if str(item.get("severity", "")).lower() == "error"
            else "warning"
        )
        findings.append(
            make_finding(
                repository=repository,
                rule_id=rule_id,
                check_id=rule_id,
                category="policy",
                severity=severity,
                location=safe_location(item.get("path")),
                summary=str(item.get("message") or "Supply-chain policy finding."),
                eligible=eligible,
                reason=reason,
                detected_at=detected_at,
                run_url=run_url,
                rules=rules,
            )
        )
    for item in vulnerability_values:
        if not isinstance(item, dict) or item.get("repo") not in covered:
            continue
        severity_value = str(item.get("severity") or "unknown").lower()
        if severity_value == "critical":
            severity = "critical"
        elif severity_value == "high":
            severity = "failure"
        else:
            severity = "warning"
        summary = (
            f"{item.get('vulnerability_id', 'unknown')} affects "
            f"{item.get('dependency', 'unknown')} "
            f"{item.get('version', 'unknown')}."
        )
        findings.append(
            make_finding(
                repository=str(item["repo"]),
                rule_id="dependency-vulnerability",
                check_id="dependency-vulnerability",
                category="security",
                severity=severity,
                location=safe_location(item.get("source_file")),
                summary=summary,
                eligible=False,
                reason=(
                    "Dependency and lockfile changes are outside the initial "
                    "automatic-remediation policy."
                ),
                detected_at=detected_at,
                run_url=run_url,
                rules=rules,
            )
        )
    return findings


def coverage_repositories(coverage: dict[str, Any]) -> list[str]:
    if coverage.get("schema_version") != "atlas-gardener/github-app-coverage/v1":
        raise FindingExportError("unsupported Gardener coverage policy")
    repositories = [coverage.get("canary", {}).get("repository")]
    if coverage.get("canary", {}).get("status") != "verified":
        raise FindingExportError("Gardener canary is not verified")
    for batch in coverage.get("batches", []):
        if not isinstance(batch, dict) or batch.get("status") != "verified":
            raise FindingExportError("Gardener coverage contains an unverified batch")
        repositories.extend(batch.get("repositories", []))
    if len(repositories) != 20 or len(set(repositories)) != 20:
        raise FindingExportError(
            "Gardener coverage must contain 20 unique repositories"
        )
    if any(
        not isinstance(value, str) or not REPOSITORY_RE.fullmatch(value)
        for value in repositories
    ):
        raise FindingExportError(
            "Gardener coverage contains an invalid repository identity"
        )
    return sorted(repositories)


def repository_snapshot(
    repository: str,
    repository_root: Path,
) -> dict[str, str]:
    commit = git(repository_root, "rev-parse", "HEAD")
    remote_commit = git(repository_root, "rev-parse", "refs/remotes/origin/main")
    if not SHA_RE.fullmatch(commit) or remote_commit != commit:
        raise FindingExportError(
            f"checkout is not the exact origin/main base for {repository}"
        )
    return {"repository": repository, "base_branch": "main", "base_sha": commit}


def build_bundle(
    *,
    report_path: Path,
    work_dir: Path,
    infra_root: Path,
    generated_at: datetime,
    source_run_id: str,
    source_run_attempt: int,
    source_commit: str,
    run_url: str,
) -> dict[str, Any]:
    report = load_object(report_path, "supply-chain report")
    policy = load_object(
        infra_root / "policy/gardener-automation.json",
        "Gardener automation policy",
    )
    coverage = load_object(
        infra_root / "policy/gardener-github-app-coverage.json",
        "Gardener coverage policy",
    )
    rules = load_object(
        infra_root / "contracts/v1/fingerprint-rules.json",
        "fingerprint rules",
    )
    finding_schema = load_object(
        infra_root / "contracts/v1/finding.schema.json",
        "Finding schema",
    )
    contract_module = load_contract_module(infra_root)
    repositories = coverage_repositories(coverage)
    covered = set(repositories)
    detected_at = (
        generated_at.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    findings = report_findings(
        report,
        detected_at=detected_at,
        run_url=run_url,
        rules=rules,
        covered=covered,
    )
    snapshots: list[dict[str, str]] = []
    for repository in repositories:
        root = work_dir / repository.split("/", 1)[1]
        if not (root / ".git").is_dir():
            raise FindingExportError(
                "covered repository checkout is unavailable: " + repository
            )
        snapshots.append(repository_snapshot(repository, root))
        findings.extend(
            housekeeping_findings(
                repository,
                root,
                detected_at=detected_at,
                run_url=run_url,
                rules=rules,
            )
        )
    if len(snapshots) != 20:
        raise FindingExportError("Finding bundle does not contain 20 exact snapshots")

    by_fingerprint: dict[str, dict[str, Any]] = {}
    for finding in findings:
        errors = contract_module.validate_instance(finding, finding_schema)
        if errors:
            raise FindingExportError(
                f"canonical Finding failed validation: {errors[0]}"
            )
        by_fingerprint.setdefault(finding["fingerprint"], finding)
    ordered_findings = [by_fingerprint[key] for key in sorted(by_fingerprint)]
    authority_commit = git(infra_root, "rev-parse", "HEAD")
    if not SHA_RE.fullmatch(authority_commit):
        raise FindingExportError("Atlas Infra authority commit is invalid")
    bundle: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA,
        "producer": "AtlasReaper311/atlas-dep-audit",
        "source_workflow": ".github/workflows/audit.yml",
        "source_run_id": source_run_id,
        "source_run_attempt": source_run_attempt,
        "source_commit": source_commit,
        "authority_commit": authority_commit,
        "policy_digest": digest_value(policy),
        "generated_at": detected_at,
        "expires_at": (
            generated_at
            + timedelta(hours=int(policy["finding_bundle"]["maximum_age_hours"]))
        )
        .astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "public_only": True,
        "source_report_digest": digest_file(report_path),
        "repository_snapshots": sorted(
            snapshots,
            key=lambda value: value["repository"],
        ),
        "findings": ordered_findings,
        "bundle_digest": "sha256:" + "0" * 64,
    }
    material = dict(bundle)
    material.pop("bundle_digest")
    bundle["bundle_digest"] = digest_value(material)
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--infra-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generated-at")
    parser.add_argument(
        "--source-run-id",
        default=os.getenv("GITHUB_RUN_ID", "local"),
    )
    parser.add_argument(
        "--source-run-attempt",
        type=int,
        default=int(os.getenv("GITHUB_RUN_ATTEMPT", "1")),
    )
    parser.add_argument(
        "--source-commit",
        default=os.getenv("GITHUB_SHA", ""),
    )
    parser.add_argument(
        "--run-url",
        default=(
            os.getenv("GITHUB_SERVER_URL", "https://github.com")
            + "/"
            + os.getenv("GITHUB_REPOSITORY", "AtlasReaper311/atlas-dep-audit")
            + "/actions/runs/"
            + os.getenv("GITHUB_RUN_ID", "local")
        ),
    )
    args = parser.parse_args()
    try:
        generated = (
            datetime.fromisoformat(args.generated_at.replace("Z", "+00:00"))
            if args.generated_at
            else datetime.now(timezone.utc)
        )
        if generated.tzinfo is None:
            raise FindingExportError("generated-at requires a timezone")
        if not str(args.source_run_id).isdigit() or int(args.source_run_id) <= 0:
            raise FindingExportError("source run ID must contain positive digits")
        if args.source_run_attempt < 1:
            raise FindingExportError("source run attempt must be positive")
        if not SHA_RE.fullmatch(args.source_commit):
            raise FindingExportError(
                "source commit must be a lowercase 40-character SHA"
            )
        bundle = build_bundle(
            report_path=args.report.resolve(strict=True),
            work_dir=args.work_dir.resolve(strict=True),
            infra_root=args.infra_root.resolve(strict=True),
            generated_at=generated,
            source_run_id=str(args.source_run_id),
            source_run_attempt=args.source_run_attempt,
            source_commit=args.source_commit,
            run_url=args.run_url,
        )
    except (FindingExportError, OSError, ValueError) as error:
        print(f"Gardener Finding export failed: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "schema_version": "atlas-dep-audit/gardener-export-result/v1",
                "bundle_digest": bundle["bundle_digest"],
                "findings": len(bundle["findings"]),
                "repository_snapshots": len(bundle["repository_snapshots"]),
                "public_only": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
