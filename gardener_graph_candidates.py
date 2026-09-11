#!/usr/bin/env python3
"""ADR-0016 npm graph remediation candidate production."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable

import audit
import gardener_findings as base

NPM_VERSION = "10.9.3"
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SUPPORTED_SPEC_RE = re.compile(r"^(?P<prefix>[~^]?)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")


class GraphCandidateError(ValueError):
    """A dependency graph cannot be proven inside ADR-0016 authority."""

    def __init__(self, message: str, disposition: str = "unsupported-remediation") -> None:
        super().__init__(message)
        self.disposition = disposition


def semver(value: Any) -> tuple[int, int, int] | None:
    match = SEMVER_RE.fullmatch(str(value or ""))
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GraphCandidateError(f"cannot read deterministic {label}: {error}") from error
    if not isinstance(value, dict):
        raise GraphCandidateError(f"{label} must be a JSON object")
    return value


def package_name(package_path: str, entry: dict[str, Any]) -> str | None:
    return audit.npm_name_from_path(package_path, entry)


def _candidate_child_paths(parent_path: str, dependency: str) -> list[str]:
    child = f"node_modules/{dependency}"
    if not parent_path:
        return [child]
    candidates = [f"{parent_path}/node_modules/{dependency}"]
    parts = parent_path.split("/")
    while "node_modules" in parts:
        index = len(parts) - 1 - parts[::-1].index("node_modules")
        prefix = "/".join(parts[:index])
        candidate = f"{prefix + '/' if prefix else ''}node_modules/{dependency}"
        if candidate not in candidates:
            candidates.append(candidate)
        parts = parts[:index]
    if child not in candidates:
        candidates.append(child)
    return candidates


def resolve_child(packages: dict[str, Any], parent_path: str, dependency: str) -> str | None:
    for candidate in _candidate_child_paths(parent_path, dependency):
        if isinstance(packages.get(candidate), dict):
            return candidate
    return None


def parent_constraints(packages: dict[str, Any], child_path: str) -> list[dict[str, str]]:
    constraints: list[dict[str, str]] = []
    for parent_path, entry in packages.items():
        if not isinstance(parent_path, str) or not isinstance(entry, dict):
            continue
        dependencies = entry.get("dependencies")
        if not isinstance(dependencies, dict):
            continue
        for dependency, specifier in dependencies.items():
            if resolve_child(packages, parent_path, str(dependency)) != child_path:
                continue
            if not parent_path:
                continue
            constraints.append({"package_path": parent_path, "specifier": str(specifier)})
    return sorted(constraints, key=lambda item: (item["package_path"], item["specifier"]))


def reverse_graph(packages: dict[str, Any]) -> dict[str, set[str]]:
    parents: dict[str, set[str]] = defaultdict(set)
    for parent_path, entry in packages.items():
        if not isinstance(parent_path, str) or not isinstance(entry, dict):
            continue
        dependencies = entry.get("dependencies")
        if not isinstance(dependencies, dict):
            continue
        for dependency in dependencies:
            child = resolve_child(packages, parent_path, str(dependency))
            if child is not None:
                parents[child].add(parent_path)
    return parents


def direct_ancestors(packages: dict[str, Any], child_path: str) -> set[str]:
    parents = reverse_graph(packages)
    found: set[str] = set()
    queue: deque[str] = deque([child_path])
    seen = {child_path}
    while queue:
        current = queue.popleft()
        for parent in parents.get(current, set()):
            if parent == "":
                name = package_name(current, packages.get(current, {}))
                if name:
                    found.add(name)
                continue
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
    return found


def spec_accepts(specifier: str, target: tuple[int, int, int]) -> bool:
    match = SUPPORTED_SPEC_RE.fullmatch(specifier.strip())
    if match is not None:
        lower = semver(match.group("version"))
        assert lower is not None
        prefix = match.group("prefix")
        if prefix == "":
            return target == lower
        if prefix == "~":
            return target >= lower and target[0] == lower[0] and target[1] == lower[1]
        if prefix == "^":
            if lower[0] > 0:
                return target >= lower and target[0] == lower[0]
            if lower[1] > 0:
                return target >= lower and target[:2] == lower[:2]
            return target >= lower and target == lower
    tokens = specifier.split()
    if len(tokens) in {1, 2} and all(re.fullmatch(r"(?:>=|>|<=|<)[0-9]+\.[0-9]+\.[0-9]+", token) for token in tokens):
        for token in tokens:
            if token.startswith(">=") and not target >= semver(token[2:]):
                return False
            if token.startswith(">") and not target > semver(token[1:]):
                return False
            if token.startswith("<=") and not target <= semver(token[2:]):
                return False
            if token.startswith("<") and not target < semver(token[1:]):
                return False
        return True
    return False


def _same_major_target(items: list[dict[str, Any]]) -> tuple[str, list[str]]:
    current = str(items[0].get("version") or "")
    current_tuple = semver(current)
    if current_tuple is None:
        raise GraphCandidateError("current dependency version is not strict three-part semver")
    fixed: list[tuple[tuple[int, int, int], str, str]] = []
    any_fixed = False
    any_newer = False
    for item in items:
        value = str(item.get("fixed_version") or "")
        parsed = semver(value)
        if parsed is None:
            continue
        any_fixed = True
        if parsed > current_tuple:
            any_newer = True
        if parsed > current_tuple and parsed[0] == current_tuple[0]:
            fixed.append((parsed, value, str(item.get("vulnerability_id") or "unknown")))
    if not fixed:
        if not any_fixed:
            raise GraphCandidateError(
                "no released non-affected version is present in current advisory evidence",
                "awaiting-upstream-fix",
            )
        if any_newer:
            raise GraphCandidateError(
                "available remediation crosses the current major-version boundary",
                "manual-remediation-required",
            )
        raise GraphCandidateError("no newer fixed version is available", "awaiting-upstream-fix")
    target_tuple = max(item[0] for item in fixed)
    target = next(value for parsed, value, _ in fixed if parsed == target_tuple)
    ids = sorted({vuln_id for parsed, _, vuln_id in fixed if parsed <= target_tuple})
    return target, ids


def _declaration(package: dict[str, Any], dependency: str) -> tuple[str, str] | None:
    matches: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(section)
        if isinstance(values, dict) and dependency in values:
            matches.append((section, str(values[dependency])))
    if len(matches) > 1:
        raise GraphCandidateError("dependency declaration is ambiguous")
    return matches[0] if matches else None


def _replace_json_spec(text: str, dependency: str, current_spec: str, target_spec: str) -> str:
    pattern = re.compile(
        rf'^(?P<prefix>\s*"{re.escape(dependency)}"\s*:\s*")'
        rf'{re.escape(current_spec)}(?P<suffix>"\s*,?\s*)(?P<newline>\r?\n)?$'
    )
    lines = text.splitlines(keepends=True)
    matches = [(index, pattern.fullmatch(line)) for index, line in enumerate(lines)]
    matches = [(index, match) for index, match in matches if match is not None]
    if len(matches) != 1:
        raise GraphCandidateError("npm package.json declaration is not uniquely line-addressable")
    index, match = matches[0]
    assert match is not None
    lines[index] = match.group("prefix") + target_spec + match.group("suffix") + (match.group("newline") or "")
    return "".join(lines)


def _npm_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_ignore_scripts": "true",
        "npm_config_package_lock": "true",
        "npm_config_registry": "https://registry.npmjs.org/",
        "npm_config_update_notifier": "false",
    }


def run_pinned_npm(root: Path, update_names: list[str]) -> None:
    commands = [
        ["npx", "--yes", f"npm@{NPM_VERSION}", "--", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    ]
    if update_names:
        commands.append([
            "npx", "--yes", f"npm@{NPM_VERSION}", "--", "update", *sorted(set(update_names)),
            "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
        ])
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
                env=_npm_environment(root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise GraphCandidateError("pinned npm regeneration is unavailable or timed out") from error
        if completed.returncode != 0:
            raise GraphCandidateError("pinned npm regeneration failed")


def active_osv_ids(repository: str, root: Path, lock_relative: str) -> set[str]:
    lock_path = root / lock_relative
    components, _ = audit.npm_components(lock_path, root)
    results = audit.osv_query(components)
    return {row.vulnerability_id for row in audit.vulnerabilities_for(repository, components, results)}


def build_npm_graph_candidate(
    repository: str,
    root: Path,
    lock_relative: str,
    items: list[dict[str, Any]],
    *,
    npm_runner: Callable[[Path, list[str]], None] = run_pinned_npm,
    vulnerability_checker: Callable[[str, Path, str], set[str]] = active_osv_ids,
) -> dict[str, Any]:
    lock_path = root / lock_relative
    if lock_path.name != "package-lock.json" or not lock_path.is_file():
        raise GraphCandidateError("npm graph remediation requires package-lock.json")
    manifest_path = lock_path.parent / "package.json"
    if not manifest_path.is_file():
        raise GraphCandidateError("matching package.json is unavailable")
    manifest_relative = manifest_path.relative_to(root).as_posix()
    package = read_json(manifest_path, "package.json")
    lock = read_json(lock_path, "package-lock.json")
    if lock.get("lockfileVersion") != 3:
        raise GraphCandidateError("npm graph remediation requires lockfileVersion 3")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise GraphCandidateError("npm lockfile packages map is unavailable")

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        grouped[(str(item.get("dependency") or ""), str(item.get("version") or ""))].append(item)

    direct_seed: dict[str, dict[str, Any]] = {}
    transitive_seed: dict[str, dict[str, Any]] = {}
    parent_update_ids: dict[str, set[str]] = defaultdict(set)
    update_names: set[str] = set()
    all_ids: set[str] = set()
    manifest_text = manifest_path.read_text(encoding="utf-8")

    for (dependency, current), group in sorted(grouped.items()):
        target, ids = _same_major_target(group)
        all_ids.update(ids)
        current_tuple = semver(current)
        target_tuple = semver(target)
        assert current_tuple is not None and target_tuple is not None
        matching_paths = [
            path for path, entry in packages.items()
            if isinstance(path, str)
            and isinstance(entry, dict)
            and package_name(path, entry) == dependency
            and str(entry.get("version") or "") == current
        ]
        if len(matching_paths) != 1:
            raise GraphCandidateError(f"{dependency}: vulnerable lock node is absent or ambiguous")
        package_path = matching_paths[0]
        declaration = _declaration(package, dependency)
        if declaration is not None and package_path == f"node_modules/{dependency}":
            section, current_spec = declaration
            spec_match = SUPPORTED_SPEC_RE.fullmatch(current_spec)
            if spec_match is None:
                raise GraphCandidateError(f"{dependency}: direct declaration uses unsupported semver syntax")
            prefix = spec_match.group("prefix")
            target_spec = prefix + target
            if current_spec != target_spec:
                manifest_text = _replace_json_spec(manifest_text, dependency, current_spec, target_spec)
            direct_seed[dependency] = {
                "dependency": dependency,
                "section": section,
                "current_version": current,
                "target_version": target,
                "current_spec": current_spec,
                "target_spec": target_spec,
                "vulnerability_ids": ids,
            }
            update_names.add(dependency)
            continue

        constraints = parent_constraints(packages, package_path)
        if not constraints:
            raise GraphCandidateError(f"{dependency}: no bounded parent constraint was found")
        if all(spec_accepts(item["specifier"], target_tuple) for item in constraints):
            transitive_seed[package_path] = {
                "dependency": dependency,
                "package_path": package_path,
                "current_version": current,
                "target_version": target,
                "parents": constraints,
                "vulnerability_ids": ids,
            }
            update_names.add(dependency)
            continue

        ancestors = direct_ancestors(packages, package_path)
        if not ancestors:
            raise GraphCandidateError(f"{dependency}: no direct ancestor can be updated within authority")
        supported_ancestor = False
        for ancestor in sorted(ancestors):
            declaration = _declaration(package, ancestor)
            if declaration is None:
                continue
            _, spec = declaration
            if SUPPORTED_SPEC_RE.fullmatch(spec) is None:
                continue
            supported_ancestor = True
            update_names.add(ancestor)
            parent_update_ids[ancestor].update(ids)
        if not supported_ancestor:
            raise GraphCandidateError(f"{dependency}: no supported direct ancestor declaration is available")

    with tempfile.TemporaryDirectory(prefix="atlas-dep-audit-adr0016-") as directory:
        temp_root = Path(directory)
        temp_manifest = temp_root / "package.json"
        temp_lock = temp_root / "package-lock.json"
        temp_manifest.write_text(manifest_text, encoding="utf-8")
        temp_lock.write_bytes(lock_path.read_bytes())
        npm_runner(temp_root, sorted(update_names))
        manifest_after = temp_manifest.read_bytes()
        lock_after = temp_lock.read_bytes()
        generated_package = read_json(temp_manifest, "generated package.json")
        generated_lock = read_json(temp_lock, "generated package-lock.json")
        generated_packages = generated_lock.get("packages")
        if generated_lock.get("lockfileVersion") != 3 or not isinstance(generated_packages, dict):
            raise GraphCandidateError("pinned npm produced an unsupported lockfile")
        active = vulnerability_checker(repository, temp_root, "package-lock.json")
        remaining = sorted(all_ids & active)
        if remaining:
            raise GraphCandidateError(
                "post-regeneration vulnerability proof still reports: " + ", ".join(remaining)
            )

        direct_updates = list(direct_seed.values())
        for ancestor, ids in sorted(parent_update_ids.items()):
            original_decl = _declaration(package, ancestor)
            generated_decl = _declaration(generated_package, ancestor)
            if original_decl is None or generated_decl is None or original_decl != generated_decl:
                raise GraphCandidateError(f"{ancestor}: npm unexpectedly changed direct manifest declaration")
            section, spec = original_decl
            original_entry = packages.get(f"node_modules/{ancestor}")
            generated_entry = generated_packages.get(f"node_modules/{ancestor}")
            if not isinstance(original_entry, dict) or not isinstance(generated_entry, dict):
                raise GraphCandidateError(f"{ancestor}: direct ancestor lock node is unavailable")
            current_version = str(original_entry.get("version") or "")
            target_version = str(generated_entry.get("version") or "")
            current_tuple = semver(current_version)
            target_tuple = semver(target_version)
            if current_tuple is None or target_tuple is None or target_tuple <= current_tuple or target_tuple[0] != current_tuple[0]:
                raise GraphCandidateError(f"{ancestor}: regeneration did not produce a newer same-major direct ancestor")
            direct_updates.append({
                "dependency": ancestor,
                "section": section,
                "current_version": current_version,
                "target_version": target_version,
                "current_spec": spec,
                "target_spec": spec,
                "vulnerability_ids": sorted(ids),
            })

        transitive_updates: list[dict[str, Any]] = []
        for package_path, operation in sorted(transitive_seed.items()):
            generated_entry = generated_packages.get(package_path)
            if not isinstance(generated_entry, dict) or str(generated_entry.get("version") or "") != operation["target_version"]:
                raise GraphCandidateError(f"{operation['dependency']}: npm did not resolve the exact transitive target")
            transitive_updates.append(operation)

        if not direct_updates and not transitive_updates:
            raise GraphCandidateError("regeneration produced no authorised graph operations")
        if manifest_after == manifest_path.read_bytes() and lock_after == lock_path.read_bytes():
            raise GraphCandidateError("regeneration produced no source change")

        return {
            "kind": "npm-lock-security-remediation",
            "manifest_file": manifest_relative,
            "lockfile_file": lock_relative,
            "npm_version": NPM_VERSION,
            "direct_updates": sorted(direct_updates, key=lambda item: item["dependency"]),
            "transitive_updates": transitive_updates,
            "vulnerability_ids": sorted(all_ids),
            "target_manifest_sha256": sha256_bytes(manifest_after),
            "target_lockfile_sha256": sha256_bytes(lock_after),
        }


def _severity(items: list[dict[str, Any]]) -> str:
    values = {str(item.get("severity") or "unknown").lower() for item in items}
    if "critical" in values:
        return "critical"
    if "high" in values:
        return "failure"
    return "warning"


def _finding(
    *, repository: str, source_file: str, items: list[dict[str, Any]], eligible: bool,
    reason: str, disposition: str, candidate: dict[str, Any] | None, detected_at: str,
    run_url: str, rules: dict[str, Any],
) -> dict[str, Any]:
    finding = base.make_finding(
        repository=repository,
        rule_id="dependency-vulnerability",
        check_id="dependency-vulnerability",
        category="security",
        severity=_severity(items),
        location=base.safe_location(source_file),
        summary=(
            f"{len({str(item.get('vulnerability_id') or 'unknown') for item in items})} known vulnerability "
            f"identifier(s) affect dependencies recorded in {source_file}."
        ),
        eligible=eligible,
        reason=reason,
        detected_at=detected_at,
        run_url=run_url,
        rules=rules,
    )
    finding["remediation"]["disposition"] = disposition
    if candidate is not None:
        finding["remediation"]["candidate"] = candidate
    return finding


def dependency_findings(
    report: dict[str, Any], *, repositories: dict[str, Path], covered: set[str],
    detected_at: str, run_url: str, rules: dict[str, Any],
    npm_runner: Callable[[Path, list[str]], None] = run_pinned_npm,
    vulnerability_checker: Callable[[str, Path, str], set[str]] = active_osv_ids,
) -> list[dict[str, Any]]:
    raw = report.get("vulnerabilities")
    if not isinstance(raw, list):
        raise GraphCandidateError("supply-chain vulnerability collection is malformed")
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in raw:
        if isinstance(item, dict) and item.get("repo") in covered:
            groups[(str(item.get("repo")), str(item.get("source_file") or "repository"))].append(item)

    findings: list[dict[str, Any]] = []
    for (repository, source_file), items in sorted(groups.items()):
        root = repositories.get(repository)
        if root is None:
            findings.append(_finding(
                repository=repository, source_file=source_file, items=items, eligible=False,
                reason="exact audited checkout is unavailable", disposition="unsupported-remediation",
                candidate=None, detected_at=detected_at, run_url=run_url, rules=rules,
            ))
            continue
        if source_file.endswith("package-lock.json"):
            try:
                candidate = build_npm_graph_candidate(
                    repository, root, source_file, items,
                    npm_runner=npm_runner, vulnerability_checker=vulnerability_checker,
                )
                findings.append(_finding(
                    repository=repository, source_file=source_file, items=items, eligible=True,
                    reason="Deterministic ADR-0016 npm graph remediation is available.",
                    disposition="remediation-available", candidate=candidate,
                    detected_at=detected_at, run_url=run_url, rules=rules,
                ))
            except GraphCandidateError as error:
                findings.append(_finding(
                    repository=repository, source_file=source_file, items=items, eligible=False,
                    reason=str(error)[:240], disposition=error.disposition, candidate=None,
                    detected_at=detected_at, run_url=run_url, rules=rules,
                ))
            continue

        if Path(source_file).name == "requirements.txt":
            if len({str(item.get("dependency") or "") for item in items}) != 1 or len({str(item.get("version") or "") for item in items}) != 1:
                findings.append(_finding(
                    repository=repository, source_file=source_file, items=items, eligible=False,
                    reason="requirements.txt contains multiple vulnerability groups requiring separate review",
                    disposition="manual-remediation-required", candidate=None,
                    detected_at=detected_at, run_url=run_url, rules=rules,
                ))
                continue
            dependency = str(items[0].get("dependency") or "")
            current = str(items[0].get("version") or "")
            try:
                target, ids = _same_major_target(items)
                path = root / source_file
                matches = []
                pattern = re.compile(rf"^\s*{re.escape(dependency)}(?:\[[^]]+\])?\s*==\s*{re.escape(current)}(?:\s|$)", re.IGNORECASE)
                for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                    if pattern.search(line):
                        matches.append(number)
                if len(matches) != 1:
                    raise GraphCandidateError("Python direct dependency is absent or ambiguous")
                current_tuple = semver(current)
                target_tuple = semver(target)
                assert current_tuple is not None and target_tuple is not None
                candidate = {
                    "kind": "dependency-update", "ecosystem": "PyPI", "dependency": dependency,
                    "current_version": current, "target_version": target, "source_file": source_file,
                    "update_class": "patch" if current_tuple[:2] == target_tuple[:2] else "minor",
                    "direct": True, "vulnerability_ids": ids,
                }
                finding = _finding(
                    repository=repository, source_file=source_file, items=items, eligible=True,
                    reason="Structured same-major direct Python remediation is available.",
                    disposition="remediation-available", candidate=candidate,
                    detected_at=detected_at, run_url=run_url, rules=rules,
                )
                finding["location"] = f"{source_file}:{matches[0]}"
                findings.append(finding)
            except (GraphCandidateError, OSError, UnicodeError) as error:
                disposition = error.disposition if isinstance(error, GraphCandidateError) else "unsupported-remediation"
                findings.append(_finding(
                    repository=repository, source_file=source_file, items=items, eligible=False,
                    reason=str(error)[:240], disposition=disposition, candidate=None,
                    detected_at=detected_at, run_url=run_url, rules=rules,
                ))
            continue

        findings.append(_finding(
            repository=repository, source_file=source_file, items=items, eligible=False,
            reason="dependency packaging format is outside ADR-0016 authority",
            disposition="unsupported-remediation", candidate=None,
            detected_at=detected_at, run_url=run_url, rules=rules,
        ))
    return findings
