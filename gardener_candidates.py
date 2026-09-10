#!/usr/bin/env python3
"""Enrich the public Gardener Finding bundle with bounded remediation candidates.

The base exporter remains responsible for authority, coverage, exact repository
snapshots, fingerprinting, and bundle construction. This module replaces the
previous generic dependency/container observations with structured candidates
only when ADR-0015 can be proven from the exact audited checkout.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import gardener_findings as base

SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REQUIREMENT_RE = re.compile(
    r"^(?P<leading>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^]]+\])?"
    r"(?P<operator>\s*==\s*)(?P<version>[^\s;#]+)(?P<suffix>.*)$"
)
CONTAINER_MESSAGE_PREFIX = "Container base is tag-pinned rather than digest-pinned: "
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DOCKER_HUB_REGISTRIES = {"docker.io", "index.docker.io", "registry-1.docker.io"}
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class CandidateError(ValueError):
    """A finding cannot be converted into a deterministic candidate."""


def semver(value: Any) -> tuple[int, int, int] | None:
    match = SEMVER_RE.fullmatch(str(value or ""))
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read deterministic {label}: {error}") from error
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must be a JSON object")
    return value


def _line_for_json_dependency(path: Path, dependency: str, spec: str) -> int:
    pattern = re.compile(
        rf'^\s*"{re.escape(dependency)}"\s*:\s*"{re.escape(spec)}"\s*,?\s*$'
    )
    matches = [
        number
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.fullmatch(line)
    ]
    if len(matches) != 1:
        raise CandidateError("direct npm declaration is not uniquely line-addressable")
    return matches[0]


def npm_direct_source(
    repository: Path,
    lock_relative: str,
    dependency: str,
    current_version: str,
) -> tuple[str, int]:
    lock_path = repository / lock_relative
    if lock_path.name != "package-lock.json" or not lock_path.is_file():
        raise CandidateError("npm vulnerability is not backed by package-lock.json")
    package_path = lock_path.parent / "package.json"
    if not package_path.is_file():
        raise CandidateError("matching package.json is unavailable")
    package = _json_object(package_path, "package.json")
    declarations: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(section)
        if isinstance(values, dict) and dependency in values:
            declarations.append((section, str(values[dependency])))
    if len(declarations) != 1:
        raise CandidateError("npm dependency is transitive, absent, or ambiguously declared")
    _, spec = declarations[0]
    if spec not in {current_version, f"^{current_version}", f"~{current_version}"}:
        raise CandidateError("npm direct declaration is not a supported deterministic version spec")

    lock = _json_object(lock_path, "package-lock.json")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise CandidateError("npm lockfile format does not expose deterministic package entries")
    entry = packages.get(f"node_modules/{dependency}")
    if not isinstance(entry, dict) or str(entry.get("version") or "") != current_version:
        raise CandidateError("npm lockfile direct version does not match the audit finding")
    relative = package_path.relative_to(repository).as_posix()
    return relative, _line_for_json_dependency(package_path, dependency, spec)


def python_direct_source(
    repository: Path,
    source_relative: str,
    dependency: str,
    current_version: str,
) -> tuple[str, int]:
    path = repository / source_relative
    if path.name != "requirements.txt" or not path.is_file():
        raise CandidateError("Python vulnerability is not backed by requirements.txt")
    matches: list[int] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = REQUIREMENT_RE.fullmatch(raw)
        if match is None:
            continue
        if normalized_name(match.group("name")) != normalized_name(dependency):
            continue
        if match.group("version") != current_version:
            continue
        matches.append(number)
    if len(matches) != 1:
        raise CandidateError("Python direct dependency is absent or ambiguously declared")
    return source_relative, matches[0]


def _dependency_target(items: list[dict[str, Any]]) -> tuple[str, str, list[str]]:
    current = str(items[0].get("version") or "")
    current_tuple = semver(current)
    if current_tuple is None:
        raise CandidateError("current dependency version is not a strict three-part version")
    fixed: list[tuple[tuple[int, int, int], str, str]] = []
    for item in items:
        value = str(item.get("fixed_version") or "")
        parsed = semver(value)
        if parsed is None or parsed <= current_tuple or parsed[0] != current_tuple[0]:
            continue
        fixed.append((parsed, value, str(item.get("vulnerability_id") or "unknown")))
    if not fixed:
        raise CandidateError("no published same-major fixed version is available")
    target_tuple, target, _ = max(fixed, key=lambda item: item[0])
    vulnerability_ids = sorted(
        {
            vulnerability_id
            for parsed, _, vulnerability_id in fixed
            if parsed <= target_tuple
        }
    )
    update_class = "patch" if target_tuple[:2] == current_tuple[:2] else "minor"
    return target, update_class, vulnerability_ids


def _candidate_finding(
    *,
    repository: str,
    rule_id: str,
    category: str,
    severity: str,
    location: str,
    summary: str,
    eligible: bool,
    reason: str,
    candidate: dict[str, Any] | None,
    detected_at: str,
    run_url: str,
    rules: dict[str, Any],
) -> dict[str, Any]:
    finding = base.make_finding(
        repository=repository,
        rule_id=rule_id,
        check_id=rule_id,
        category=category,
        severity=severity,
        location=location,
        summary=summary,
        eligible=eligible,
        reason=reason,
        detected_at=detected_at,
        run_url=run_url,
        rules=rules,
    )
    if candidate is not None:
        finding["remediation"]["candidate"] = candidate
    return finding


def dependency_findings(
    report: dict[str, Any],
    *,
    repositories: dict[str, Path],
    covered: set[str],
    detected_at: str,
    run_url: str,
    rules: dict[str, Any],
) -> list[dict[str, Any]]:
    raw = report.get("vulnerabilities")
    if not isinstance(raw, list):
        raise CandidateError("supply-chain vulnerability collection is malformed")
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in raw:
        if not isinstance(item, dict) or item.get("repo") not in covered:
            continue
        key = (
            str(item.get("repo")),
            str(item.get("dependency") or "unknown"),
            str(item.get("version") or "unknown"),
            str(item.get("source_file") or "repository"),
        )
        groups[key].append(item)

    findings: list[dict[str, Any]] = []
    observations: dict[tuple[str, str], list[str]] = defaultdict(list)
    for (repository, dependency, current, source_file), items in sorted(groups.items()):
        root = repositories.get(repository)
        if root is None:
            observations[(repository, source_file)].append(
                f"{dependency}: exact audited checkout unavailable"
            )
            continue
        severity_values = {str(item.get("severity") or "unknown").lower() for item in items}
        severity = "critical" if "critical" in severity_values else (
            "failure" if "high" in severity_values else "warning"
        )
        try:
            target, update_class, vulnerability_ids = _dependency_target(items)
            if source_file.endswith("package-lock.json"):
                ecosystem = "npm"
                candidate_source, line = npm_direct_source(
                    root, source_file, dependency, current
                )
            elif Path(source_file).name == "requirements.txt":
                ecosystem = "PyPI"
                candidate_source, line = python_direct_source(
                    root, source_file, dependency, current
                )
            else:
                raise CandidateError("dependency packaging format is outside ADR-0015")
            candidate = {
                "kind": "dependency-update",
                "ecosystem": ecosystem,
                "dependency": dependency,
                "current_version": current,
                "target_version": target,
                "source_file": candidate_source,
                "update_class": update_class,
                "direct": True,
                "vulnerability_ids": vulnerability_ids,
            }
            findings.append(
                _candidate_finding(
                    repository=repository,
                    rule_id="dependency-vulnerability",
                    category="security",
                    severity=severity,
                    location=f"{candidate_source}:{line}",
                    summary=(
                        f"{len(vulnerability_ids)} known vulnerability finding(s) affect "
                        f"direct dependency {dependency} {current}; bounded target {target}."
                    ),
                    eligible=True,
                    reason="Structured same-major direct dependency remediation is available.",
                    candidate=candidate,
                    detected_at=detected_at,
                    run_url=run_url,
                    rules=rules,
                )
            )
        except (CandidateError, OSError, UnicodeError) as error:
            observations[(repository, source_file)].append(f"{dependency}: {error}")

    for (repository, source_file), reasons in sorted(observations.items()):
        findings.append(
            _candidate_finding(
                repository=repository,
                rule_id="dependency-vulnerability",
                category="security",
                severity="warning",
                location=base.safe_location(source_file),
                summary=f"{len(reasons)} dependency remediation candidate(s) remain non-actionable.",
                eligible=False,
                reason=(reasons[0] if len(reasons) == 1 else "One or more dependency findings are outside the bounded ADR-0015 candidate rules."),
                candidate=None,
                detected_at=detected_at,
                run_url=run_url,
                rules=rules,
            )
        )
    return findings


def docker_hub_target(reference: str) -> tuple[str, str]:
    if "@" in reference or not reference or any(ch.isspace() for ch in reference):
        raise CandidateError("container reference is already digest-pinned or malformed")
    value = reference
    first, separator, remainder = value.partition("/")
    if separator and ("." in first or ":" in first or first == "localhost"):
        if first not in DOCKER_HUB_REGISTRIES:
            raise CandidateError("container registry is outside the initial Docker Hub boundary")
        value = remainder
    last = value.rsplit("/", 1)[-1]
    if ":" not in last:
        raise CandidateError("container reference does not use an explicit Docker Hub tag")
    image, tag = value.rsplit(":", 1)
    if not image or not tag or not re.fullmatch(r"[A-Za-z0-9_.-]+", tag):
        raise CandidateError("container Docker Hub tag is malformed")
    repository = image if "/" in image else f"library/{image}"
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", repository):
        raise CandidateError("container Docker Hub repository is malformed")
    return repository, tag


def resolve_docker_hub_digest(reference: str) -> str:
    repository, tag = docker_hub_target(reference)
    query = urllib.parse.urlencode(
        {
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        }
    )
    token_request = urllib.request.Request(
        f"https://auth.docker.io/token?{query}",
        headers={"User-Agent": "atlas-dep-audit/1.2"},
    )
    try:
        with urllib.request.urlopen(token_request, timeout=20) as response:
            payload = json.load(response)
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise CandidateError("Docker Hub token response is malformed")
        manifest_request = urllib.request.Request(
            f"https://registry-1.docker.io/v2/{repository}/manifests/{urllib.parse.quote(tag, safe='')}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": MANIFEST_ACCEPT,
                "User-Agent": "atlas-dep-audit/1.2",
            },
        )
        with urllib.request.urlopen(manifest_request, timeout=30) as response:
            digest = response.headers.get("Docker-Content-Digest", "")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
        raise CandidateError("Docker Hub digest resolution failed") from error
    if not DIGEST_RE.fullmatch(digest):
        raise CandidateError("Docker Hub returned no canonical sha256 manifest digest")
    return digest


def _container_reference(item: dict[str, Any]) -> str:
    message = str(item.get("message") or "")
    if not message.startswith(CONTAINER_MESSAGE_PREFIX):
        raise CandidateError("container audit finding does not expose a bounded reference")
    return message.removeprefix(CONTAINER_MESSAGE_PREFIX).strip()


def container_findings(
    report: dict[str, Any],
    *,
    repositories: dict[str, Path],
    covered: set[str],
    detected_at: str,
    run_url: str,
    rules: dict[str, Any],
    resolver: Callable[[str], str] = resolve_docker_hub_digest,
) -> list[dict[str, Any]]:
    raw = report.get("policy_findings")
    if not isinstance(raw, list):
        raise CandidateError("supply-chain policy finding collection is malformed")
    findings: list[dict[str, Any]] = []
    cache: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict) or item.get("repo") not in covered or item.get("rule") != "container-digest":
            continue
        repository = str(item["repo"])
        source_file = base.safe_location(item.get("path"))
        root = repositories.get(repository)
        if root is None:
            continue
        try:
            reference = _container_reference(item)
            path = root / source_file
            lines = path.read_text(encoding="utf-8").splitlines()
        except (CandidateError, OSError, UnicodeError):
            continue
        matched = False
        for number, raw_line in enumerate(lines, 1):
            tokens = raw_line.strip().split()
            if len(tokens) < 2 or tokens[0].upper() != "FROM" or tokens[1] != reference:
                continue
            matched = True
            if len(tokens) >= 4 and tokens[2].upper() == "AS":
                continue
            if len(tokens) != 2:
                reason = "Dockerfile FROM instruction is outside the simple ADR-0015 form."
                findings.append(
                    _candidate_finding(
                        repository=repository,
                        rule_id="container-digest",
                        category="policy",
                        severity="info",
                        location=f"{source_file}:{number}",
                        summary=f"Container base {reference} remains tag-addressed.",
                        eligible=False,
                        reason=reason,
                        candidate=None,
                        detected_at=detected_at,
                        run_url=run_url,
                        rules=rules,
                    )
                )
                continue
            try:
                docker_hub_target(reference)
                if reference not in cache:
                    cache[reference] = resolver(reference)
                digest = cache[reference]
                if not DIGEST_RE.fullmatch(digest):
                    raise CandidateError("container resolver returned a malformed digest")
                candidate = {
                    "kind": "container-digest-pin",
                    "source_file": source_file,
                    "current_reference": reference,
                    "target_digest": digest,
                }
                findings.append(
                    _candidate_finding(
                        repository=repository,
                        rule_id="container-digest",
                        category="policy",
                        severity="info",
                        location=f"{source_file}:{number}",
                        summary=f"Docker Hub base {reference} can be pinned to an immutable digest.",
                        eligible=True,
                        reason="Structured Docker Hub digest remediation is available.",
                        candidate=candidate,
                        detected_at=detected_at,
                        run_url=run_url,
                        rules=rules,
                    )
                )
            except CandidateError as error:
                findings.append(
                    _candidate_finding(
                        repository=repository,
                        rule_id="container-digest",
                        category="policy",
                        severity="info",
                        location=f"{source_file}:{number}",
                        summary=f"Container base {reference} remains tag-addressed.",
                        eligible=False,
                        reason=str(error),
                        candidate=None,
                        detected_at=detected_at,
                        run_url=run_url,
                        rules=rules,
                    )
                )
        if not matched:
            continue
    return findings


def enhance_bundle(
    bundle: dict[str, Any],
    *,
    report: dict[str, Any],
    work_dir: Path,
    infra_root: Path,
    detected_at: str,
    run_url: str,
    resolver: Callable[[str], str] = resolve_docker_hub_digest,
) -> dict[str, Any]:
    rules = base.load_object(
        infra_root / "contracts/v1/fingerprint-rules.json", "fingerprint rules"
    )
    schema = base.load_object(
        infra_root / "contracts/v1/finding.schema.json", "Finding schema"
    )
    contracts = base.load_contract_module(infra_root)
    covered = {item["repository"] for item in bundle["repository_snapshots"]}
    repositories = {
        repository: work_dir / repository.split("/", 1)[1]
        for repository in covered
    }
    retained = [
        item
        for item in bundle["findings"]
        if item.get("rule_id") not in {"dependency-vulnerability", "container-digest"}
    ]
    generated = dependency_findings(
        report,
        repositories=repositories,
        covered=covered,
        detected_at=detected_at,
        run_url=run_url,
        rules=rules,
    )
    generated.extend(
        container_findings(
            report,
            repositories=repositories,
            covered=covered,
            detected_at=detected_at,
            run_url=run_url,
            rules=rules,
            resolver=resolver,
        )
    )
    by_fingerprint: dict[str, dict[str, Any]] = {}
    for finding in retained + generated:
        errors = contracts.validate_instance(finding, schema)
        if errors:
            raise base.FindingExportError(
                f"canonical enriched Finding failed validation: {errors[0]}"
            )
        by_fingerprint.setdefault(finding["fingerprint"], finding)
    bundle["findings"] = [by_fingerprint[key] for key in sorted(by_fingerprint)]
    material = dict(bundle)
    material.pop("bundle_digest", None)
    bundle["bundle_digest"] = base.digest_value(material)
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--infra-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generated-at")
    parser.add_argument("--source-run-id", default="local")
    parser.add_argument("--source-run-attempt", type=int, default=1)
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--run-url", default="")
    args = parser.parse_args()
    try:
        generated = (
            datetime.fromisoformat(args.generated_at.replace("Z", "+00:00"))
            if args.generated_at
            else datetime.now(timezone.utc)
        )
        if generated.tzinfo is None:
            raise base.FindingExportError("generated-at requires a timezone")
        bundle = base.build_bundle(
            report_path=args.report.resolve(strict=True),
            work_dir=args.work_dir.resolve(strict=True),
            infra_root=args.infra_root.resolve(strict=True),
            generated_at=generated,
            source_run_id=str(args.source_run_id),
            source_run_attempt=args.source_run_attempt,
            source_commit=args.source_commit,
            run_url=args.run_url,
        )
        detected_at = generated.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        report = base.load_object(args.report.resolve(strict=True), "supply-chain report")
        bundle = enhance_bundle(
            bundle,
            report=report,
            work_dir=args.work_dir.resolve(strict=True),
            infra_root=args.infra_root.resolve(strict=True),
            detected_at=detected_at,
            run_url=args.run_url,
        )
    except (base.FindingExportError, CandidateError, OSError, ValueError) as error:
        print(f"Gardener candidate export failed: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    actionable = sum(1 for item in bundle["findings"] if item["remediation"]["eligible"])
    print(
        json.dumps(
            {
                "schema_version": "atlas-dep-audit/gardener-export-result/v1",
                "bundle_digest": bundle["bundle_digest"],
                "findings": len(bundle["findings"]),
                "actionable": actionable,
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
