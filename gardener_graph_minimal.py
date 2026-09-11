#!/usr/bin/env python3
"""ADR-0016 minimal lockfile overlay for transitive-only npm remediation.

The pinned npm toolchain remains the resolver of record. For a graph proposal made
entirely of already-admitted transitive targets, this module copies only those
resolved package nodes back onto the exact audited lockfile. This prevents npm
version-specific normalization of unrelated lock metadata from entering a
security remediation while preserving the producer's digest and OSV proofs.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

import gardener_graph_candidates as legacy

_LEGACY_BUILD = legacy.build_npm_graph_candidate


def _npm_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def _load_json_bytes(value: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(value.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise legacy.GraphCandidateError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise legacy.GraphCandidateError(f"{label} must be a JSON object")
    return payload


def _transitive_only_paths(
    root: Path,
    lock_relative: str,
    items: list[dict[str, Any]],
) -> list[str] | None:
    lock_path = root / lock_relative
    manifest_path = lock_path.parent / "package.json"
    package = legacy.read_json(manifest_path, "package.json")
    lock = legacy.read_json(lock_path, "package-lock.json")
    packages = lock.get("packages")
    if lock.get("lockfileVersion") != 3 or not isinstance(packages, dict):
        return None
    if "dependencies" in lock:
        return None

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        grouped[(str(item.get("dependency") or ""), str(item.get("version") or ""))].append(item)

    paths: list[str] = []
    for (dependency, current), group in sorted(grouped.items()):
        target, _ = legacy._same_major_target(group)
        target_tuple = legacy.semver(target)
        if target_tuple is None:
            return None
        matching = [
            path
            for path, entry in packages.items()
            if isinstance(path, str)
            and isinstance(entry, dict)
            and legacy.package_name(path, entry) == dependency
            and str(entry.get("version") or "") == current
        ]
        if len(matching) != 1:
            return None
        package_path = matching[0]
        if (
            legacy._declaration(package, dependency) is not None
            and package_path == f"node_modules/{dependency}"
        ):
            return None
        constraints = legacy.parent_constraints(packages, package_path)
        if not constraints or not all(
            legacy.spec_accepts(item["specifier"], target_tuple) for item in constraints
        ):
            return None
        paths.append(package_path)
    return sorted(set(paths)) if paths else None


def _minimalizing_runner(
    source_root: Path,
    lock_relative: str,
    items: list[dict[str, Any]],
    npm_runner: Callable[[Path, list[str]], None],
) -> Callable[[Path, list[str]], None]:
    paths = _transitive_only_paths(source_root, lock_relative, items)
    if paths is None:
        return npm_runner

    source_lock_bytes = (source_root / lock_relative).read_bytes()
    source_manifest_bytes = (source_root / lock_relative).with_name("package.json").read_bytes()
    original = _load_json_bytes(source_lock_bytes, "audited package-lock.json")
    if _npm_json_bytes(original) != source_lock_bytes:
        raise legacy.GraphCandidateError(
            "transitive-only minimal remediation requires canonical npm JSON formatting"
        )

    def run(work: Path, names: list[str]) -> None:
        temp_lock = work / "package-lock.json"
        temp_manifest = work / "package.json"
        if temp_lock.read_bytes() != source_lock_bytes:
            raise legacy.GraphCandidateError("transitive-only lock preimage changed before npm")
        npm_runner(work, names)
        if temp_manifest.read_bytes() != source_manifest_bytes:
            raise legacy.GraphCandidateError(
                "pinned npm unexpectedly rewrote package.json during transitive remediation"
            )
        generated = _load_json_bytes(temp_lock.read_bytes(), "generated package-lock.json")
        generated_packages = generated.get("packages")
        minimal = _load_json_bytes(source_lock_bytes, "audited package-lock.json")
        minimal_packages = minimal.get("packages")
        if not isinstance(generated_packages, dict) or not isinstance(minimal_packages, dict):
            raise legacy.GraphCandidateError("npm lockfile packages map is unavailable")
        for package_path in paths:
            entry = generated_packages.get(package_path)
            if not isinstance(entry, dict):
                raise legacy.GraphCandidateError(
                    f"{package_path}: npm did not preserve the admitted transitive node"
                )
            minimal_packages[package_path] = entry
        temp_lock.write_bytes(_npm_json_bytes(minimal))

    return run


def build_npm_graph_candidate(
    repository: str,
    root: Path,
    lock_relative: str,
    items: list[dict[str, Any]],
    *,
    npm_runner: Callable[[Path, list[str]], None] = legacy.run_pinned_npm,
    vulnerability_checker: Callable[[str, Path, str], set[str]] = legacy.active_osv_ids,
) -> dict[str, Any]:
    return _LEGACY_BUILD(
        repository,
        root,
        lock_relative,
        items,
        npm_runner=_minimalizing_runner(root, lock_relative, items, npm_runner),
        vulnerability_checker=vulnerability_checker,
    )


def dependency_findings(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    previous = legacy.build_npm_graph_candidate
    legacy.build_npm_graph_candidate = build_npm_graph_candidate
    try:
        return legacy.dependency_findings(*args, **kwargs)
    finally:
        legacy.build_npm_graph_candidate = previous


GraphCandidateError = legacy.GraphCandidateError
NPM_VERSION = legacy.NPM_VERSION
