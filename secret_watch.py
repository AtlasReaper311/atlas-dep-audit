#!/usr/bin/env python3
"""Names-only secret hygiene assurance with redacted plaintext findings."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

POLICY_SCHEMA_VERSION = "atlas-secret-watch/declaration/v1"
REPORT_SCHEMA_VERSION = "atlas-secret-watch/report/v1"
METADATA_FIXTURE_SCHEMA_VERSION = "atlas-secret-watch/metadata-fixture/v1"
FINDING_SCHEMA_VERSION = "atlas-control-plane/finding/v1"
PRODUCER = "atlas-dep-audit"
PRODUCER_VERSION = "1.0.0"
POLICY_OWNER = "AtlasReaper311/atlas-infra"
POLICY_LOCATION = "policy/secret-watch.json"
TOKEN_ENVIRONMENT_NAME = "SECRET_WATCH_GITHUB_TOKEN"
GITHUB_API = "https://api.github.com"
SECRET_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,99}$")
REPOSITORY_NAME = re.compile(r"^AtlasReaper311/[A-Za-z0-9._-]+$")
RULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

RUNBOOKS = {
    "missing-required-secret": "docs/runbooks/secret-watch-missing-required.md",
    "deprecated-secret-present": "docs/runbooks/secret-watch-deprecated-present.md",
    "plaintext-credential-pattern": "docs/runbooks/secret-watch-plaintext-pattern.md",
    "metadata-unavailable": "docs/runbooks/secret-watch-metadata-unavailable.md",
    "malformed-declaration": "docs/runbooks/secret-watch-malformed-declaration.md",
    "rotation-overdue": "docs/runbooks/secret-watch-overdue-rotation.md",
}


class PolicyLoadError(RuntimeError):
    """A declaration cannot be consumed safely."""


class MetadataUnavailable(RuntimeError):
    """GitHub names-only metadata could not be read completely."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class MetadataObservation:
    repository: str
    environment: str | None
    status: str
    names: frozenset[str]
    reason: str


@dataclass(frozen=True)
class ScanStats:
    files_scanned: int = 0
    binary_files_skipped: int = 0
    fixture_files_skipped: int = 0
    oversized_files_skipped: int = 0
    symlinks_skipped: int = 0

    def plus(self, **changes: int) -> "ScanStats":
        values = {
            "files_scanned": self.files_scanned,
            "binary_files_skipped": self.binary_files_skipped,
            "fixture_files_skipped": self.fixture_files_skipped,
            "oversized_files_skipped": self.oversized_files_skipped,
            "symlinks_skipped": self.symlinks_skipped,
        }
        for key, value in changes.items():
            values[key] += value
        return ScanStats(**values)


@dataclass(frozen=True)
class ScannerRule:
    rule_id: str
    pattern: re.Pattern[str]
    value_group: int | None = None


SCANNER_RULES = (
    ScannerRule("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ScannerRule("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ScannerRule(
        "private-key-header",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    ScannerRule(
        "provider-webhook-url",
        re.compile(
            r"https://(?:hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"
            r"|(?:canary\.)?discord(?:app)?\.com/api/webhooks/\d{8,}/[A-Za-z0-9._-]{20,})"
        ),
    ),
    ScannerRule(
        "jwt-token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"
        ),
    ),
    ScannerRule(
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|passwd)\b\s*[:=]\s*['\"]([^'\"\r\n]{16,})['\"]"
        ),
        value_group=1,
    ),
)

PLACEHOLDER_MARKERS = (
    "example",
    "fixture",
    "placeholder",
    "replace-me",
    "replace_me",
    "your-",
    "your_",
    "not-a-real",
    "${",
    "{{",
    "process.env",
    "os.getenv",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def utc_timestamp(value: str | None = None) -> str:
    if value is None:
        return (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    if not UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be UTC RFC 3339 ending in Z")
    datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    return value


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized[:60] or "item"


def _is_string(value: Any, *, allow_empty: bool = False) -> bool:
    return isinstance(value, str) and (allow_empty or bool(value.strip()))


def _unknown_keys(value: dict[str, Any], allowed: set[str], path: str) -> list[str]:
    return [
        f"{path}: undeclared property {key}" for key in sorted(set(value) - allowed)
    ]


def _validate_name_list(
    value: Any,
    path: str,
    definitions: dict[str, Any],
) -> list[str]:
    if not isinstance(value, list):
        return [f"{path}: expected an array of secret names"]
    errors: list[str] = []
    seen: set[str] = set()
    for index, name in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(name, str) or not SECRET_NAME.fullmatch(name):
            errors.append(f"{item_path}: invalid secret name")
            continue
        if name in seen:
            errors.append(f"{item_path}: duplicate secret name")
        seen.add(name)
        if name not in definitions:
            errors.append(f"{item_path}: references an undeclared secret name")
    return errors


def validate_policy(policy: Any) -> list[str]:
    """Validate structure without ever including declaration values in errors."""
    if not isinstance(policy, dict):
        return ["$: expected an object"]
    errors = _unknown_keys(
        policy,
        {
            "schema_version",
            "owner",
            "github_metadata",
            "plaintext_scan",
            "secret_definitions",
            "repositories",
        },
        "$",
    )
    if policy.get("schema_version") != POLICY_SCHEMA_VERSION:
        errors.append("$.schema_version: unsupported declaration version")
    if policy.get("owner") != POLICY_OWNER:
        errors.append("$.owner: unexpected policy owner")

    metadata = policy.get("github_metadata")
    if not isinstance(metadata, dict):
        errors.append("$.github_metadata: expected an object")
    else:
        errors.extend(
            _unknown_keys(metadata, {"mode", "token_secret_name"}, "$.github_metadata")
        )
        if metadata.get("mode") not in {"optional", "required"}:
            errors.append("$.github_metadata.mode: expected optional or required")
        if metadata.get("token_secret_name") != TOKEN_ENVIRONMENT_NAME:
            errors.append("$.github_metadata.token_secret_name: unexpected token name")

    scan = policy.get("plaintext_scan")
    if not isinstance(scan, dict):
        errors.append("$.plaintext_scan: expected an object")
    else:
        errors.extend(
            _unknown_keys(
                scan,
                {
                    "enabled",
                    "max_file_bytes",
                    "fixture_globs",
                    "inline_suppression_marker",
                    "suppressions",
                },
                "$.plaintext_scan",
            )
        )
        if not isinstance(scan.get("enabled"), bool):
            errors.append("$.plaintext_scan.enabled: expected a boolean")
        max_bytes = scan.get("max_file_bytes")
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 1024 <= max_bytes <= 10485760
        ):
            errors.append(
                "$.plaintext_scan.max_file_bytes: expected an integer from 1024 to 10485760"
            )
        fixture_globs = scan.get("fixture_globs")
        if not isinstance(fixture_globs, list) or any(
            not _is_string(item) for item in fixture_globs
        ):
            errors.append(
                "$.plaintext_scan.fixture_globs: expected non-empty string globs"
            )
        elif len(fixture_globs) != len(set(fixture_globs)):
            errors.append("$.plaintext_scan.fixture_globs: duplicate glob")
        if scan.get("inline_suppression_marker") != "secret-watch: ignore":
            errors.append(
                "$.plaintext_scan.inline_suppression_marker: unsupported marker"
            )
        suppressions = scan.get("suppressions")
        if not isinstance(suppressions, list):
            errors.append("$.plaintext_scan.suppressions: expected an array")
        else:
            for index, suppression in enumerate(suppressions):
                path = f"$.plaintext_scan.suppressions[{index}]"
                if not isinstance(suppression, dict):
                    errors.append(f"{path}: expected an object")
                    continue
                errors.extend(
                    _unknown_keys(
                        suppression,
                        {
                            "repository",
                            "path",
                            "line",
                            "rule_id",
                            "owner",
                            "reason",
                            "expires_at",
                        },
                        path,
                    )
                )
                if not REPOSITORY_NAME.fullmatch(
                    str(suppression.get("repository", ""))
                ):
                    errors.append(f"{path}.repository: invalid repository name")
                relative = suppression.get("path")
                if (
                    not _is_string(relative)
                    or Path(str(relative)).is_absolute()
                    or ".." in Path(str(relative)).parts
                ):
                    errors.append(f"{path}.path: invalid repository-relative path")
                line = suppression.get("line")
                if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                    errors.append(f"{path}.line: expected a positive integer")
                if not RULE_ID.fullmatch(str(suppression.get("rule_id", ""))):
                    errors.append(f"{path}.rule_id: invalid rule id")
                if not _is_string(suppression.get("owner")):
                    errors.append(f"{path}.owner: expected a non-empty owner")
                if not _is_string(suppression.get("reason")):
                    errors.append(f"{path}.reason: expected a non-empty reason")
                expires_at = suppression.get("expires_at")
                if expires_at is not None:
                    try:
                        utc_timestamp(expires_at)
                    except (TypeError, ValueError):
                        errors.append(f"{path}.expires_at: invalid UTC timestamp")

    definitions = policy.get("secret_definitions")
    if not isinstance(definitions, dict):
        errors.append("$.secret_definitions: expected an object")
        definitions = {}
    else:
        for name, definition in definitions.items():
            path = f"$.secret_definitions.{name}"
            if not SECRET_NAME.fullmatch(str(name)):
                errors.append(f"{path}: invalid secret name")
            if not isinstance(definition, dict):
                errors.append(f"{path}: expected an object")
                continue
            errors.extend(
                _unknown_keys(
                    definition,
                    {
                        "owner",
                        "purpose",
                        "lifecycle",
                        "provenance",
                        "rotation",
                        "replacement",
                    },
                    path,
                )
            )
            if "owner" in definition and not _is_string(definition["owner"]):
                errors.append(f"{path}.owner: expected a non-empty owner")
            if "purpose" in definition and not _is_string(definition["purpose"]):
                errors.append(f"{path}.purpose: expected a non-empty purpose")
            if definition.get("lifecycle") not in {"active", "deprecated"}:
                errors.append(f"{path}.lifecycle: invalid lifecycle")
            if definition.get("provenance") not in {
                "github-actions",
                "github-managed",
                "cloudflare-worker",
                "external-provider",
            }:
                errors.append(f"{path}.provenance: invalid provenance")
            rotation = definition.get("rotation")
            if not isinstance(rotation, dict):
                errors.append(f"{path}.rotation: expected an object")
            else:
                errors.extend(
                    _unknown_keys(
                        rotation,
                        {"required", "max_age_days", "last_rotated_at"},
                        f"{path}.rotation",
                    )
                )
                if not isinstance(rotation.get("required"), bool):
                    errors.append(f"{path}.rotation.required: expected a boolean")
                max_age = rotation.get("max_age_days")
                if max_age is not None and (
                    not isinstance(max_age, int)
                    or isinstance(max_age, bool)
                    or not 1 <= max_age <= 3650
                ):
                    errors.append(f"{path}.rotation.max_age_days: invalid maximum age")
                last_rotated = rotation.get("last_rotated_at")
                if last_rotated is not None:
                    try:
                        utc_timestamp(last_rotated)
                    except (TypeError, ValueError):
                        errors.append(
                            f"{path}.rotation.last_rotated_at: invalid UTC timestamp"
                        )
            replacement = definition.get("replacement")
            if replacement is not None and not _is_string(replacement):
                errors.append(
                    f"{path}.replacement: expected non-empty guidance or null"
                )
            if definition.get("lifecycle") == "deprecated" and not _is_string(
                replacement
            ):
                errors.append(
                    f"{path}.replacement: deprecated names require replacement guidance"
                )

    repositories = policy.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        errors.append("$.repositories: expected a non-empty array")
        repositories = []
    seen_repositories: set[str] = set()
    for index, declaration in enumerate(repositories):
        path = f"$.repositories[{index}]"
        if not isinstance(declaration, dict):
            errors.append(f"{path}: expected an object")
            continue
        errors.extend(
            _unknown_keys(
                declaration,
                {"repository", "classification", "assurance", "scopes"},
                path,
            )
        )
        repository = declaration.get("repository")
        if not isinstance(repository, str) or not REPOSITORY_NAME.fullmatch(repository):
            errors.append(f"{path}.repository: invalid repository name")
        elif repository in seen_repositories:
            errors.append(f"{path}.repository: duplicate repository declaration")
        else:
            seen_repositories.add(repository)

        classification = declaration.get("classification")
        if not isinstance(classification, dict):
            errors.append(f"{path}.classification: expected an object")
        else:
            errors.extend(
                _unknown_keys(
                    classification,
                    {"lifecycle", "scope", "provenance"},
                    f"{path}.classification",
                )
            )
            if classification.get("lifecycle") not in {
                "production",
                "active",
                "experimental",
                "deprecated",
                "archived",
            }:
                errors.append(f"{path}.classification.lifecycle: invalid lifecycle")
            if classification.get("scope") not in {"public", "internal"}:
                errors.append(f"{path}.classification.scope: invalid scope")
            if classification.get("provenance") not in {"original", "external-derived"}:
                errors.append(f"{path}.classification.provenance: invalid provenance")

        assurance = declaration.get("assurance")
        if not isinstance(assurance, dict):
            errors.append(f"{path}.assurance: expected an object")
        else:
            errors.extend(
                _unknown_keys(
                    assurance,
                    {"enabled", "metadata_required", "exclusion_reason"},
                    f"{path}.assurance",
                )
            )
            if not isinstance(assurance.get("enabled"), bool):
                errors.append(f"{path}.assurance.enabled: expected a boolean")
            if not isinstance(assurance.get("metadata_required"), bool):
                errors.append(f"{path}.assurance.metadata_required: expected a boolean")
            exclusion_reason = assurance.get("exclusion_reason")
            if exclusion_reason is not None and not _is_string(exclusion_reason):
                errors.append(
                    f"{path}.assurance.exclusion_reason: expected a non-empty reason or null"
                )

        scopes = declaration.get("scopes")
        if not isinstance(scopes, list):
            errors.append(f"{path}.scopes: expected an array")
            continue
        seen_scopes: set[tuple[str, str | None]] = set()
        for scope_index, scope in enumerate(scopes):
            scope_path = f"{path}.scopes[{scope_index}]"
            if not isinstance(scope, dict):
                errors.append(f"{scope_path}: expected an object")
                continue
            errors.extend(
                _unknown_keys(
                    scope,
                    {
                        "store",
                        "environment",
                        "required_secret_names",
                        "optional_secret_names",
                        "deprecated_secret_names",
                    },
                    scope_path,
                )
            )
            store = scope.get("store")
            environment = scope.get("environment")
            if store not in {
                "github-actions",
                "cloudflare-worker",
                "external-provider",
            }:
                errors.append(f"{scope_path}.store: invalid store")
            if environment is not None and (
                not isinstance(environment, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", environment)
            ):
                errors.append(f"{scope_path}.environment: invalid environment")
            scope_key = (
                str(store),
                environment if isinstance(environment, str) else None,
            )
            if scope_key in seen_scopes:
                errors.append(f"{scope_path}: duplicate store/environment scope")
            seen_scopes.add(scope_key)
            names_by_lifecycle: dict[str, set[str]] = {}
            for field in (
                "required_secret_names",
                "optional_secret_names",
                "deprecated_secret_names",
            ):
                errors.extend(
                    _validate_name_list(
                        scope.get(field), f"{scope_path}.{field}", definitions
                    )
                )
                value = scope.get(field)
                names_by_lifecycle[field] = (
                    set(value) if isinstance(value, list) else set()
                )
            overlap = (
                names_by_lifecycle["required_secret_names"]
                & names_by_lifecycle["optional_secret_names"]
                | names_by_lifecycle["required_secret_names"]
                & names_by_lifecycle["deprecated_secret_names"]
                | names_by_lifecycle["optional_secret_names"]
                & names_by_lifecycle["deprecated_secret_names"]
            )
            if overlap:
                errors.append(
                    f"{scope_path}: a secret name appears in multiple lifecycle lists"
                )
            for name in names_by_lifecycle["deprecated_secret_names"]:
                if (
                    isinstance(definitions.get(name), dict)
                    and definitions[name].get("lifecycle") != "deprecated"
                ):
                    errors.append(
                        f"{scope_path}.deprecated_secret_names: name is not deprecated in the definition"
                    )
            for field in ("required_secret_names", "optional_secret_names"):
                for name in names_by_lifecycle[field]:
                    if (
                        isinstance(definitions.get(name), dict)
                        and definitions[name].get("lifecycle") != "active"
                    ):
                        errors.append(
                            f"{scope_path}.{field}: deprecated definition used as active"
                        )
    return sorted(set(errors))


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PolicyLoadError("declaration file is missing") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyLoadError("declaration file is not valid UTF-8 JSON") from error
    errors = validate_policy(policy)
    if errors:
        raise PolicyLoadError("; ".join(errors[:10]))
    return policy


def _fingerprint(finding: dict[str, Any]) -> str:
    selected = {
        "source.producer": finding["source"]["producer"],
        "source.check_id": finding["source"]["check_id"],
        "subject.repository": finding["subject"]["repository"],
        "subject.service_id": finding["subject"].get("service_id"),
        "category": finding["category"],
        "rule_id": finding["rule_id"],
        "location": finding["location"],
    }
    digest = hashlib.sha256(canonical_json(selected).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def make_finding(
    *,
    check_id: str,
    repository: str,
    category: str,
    severity: str,
    rule_id: str,
    location: str,
    summary: str,
    detected_at: str,
    runbook_ref: str,
) -> dict[str, Any]:
    """Build a Finding v1 record without accepting raw evidence content."""
    finding: dict[str, Any] = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "source": {
            "producer": PRODUCER,
            "check_id": check_id[:96],
            "producer_version": PRODUCER_VERSION,
        },
        "subject": {"repository": repository},
        "category": category,
        "severity": severity,
        "rule_id": rule_id,
        "location": location,
        "evidence": {
            "summary": summary[:500],
            "references": [],
            "redacted": True,
        },
        "detected_at": detected_at,
        "fingerprint": "",
        "remediation": {
            "eligible": False,
            "reason": "Secret changes require explicit owner action through the provider's protected interface.",
        },
        "runbook_ref": runbook_ref,
    }
    finding["fingerprint"] = _fingerprint(finding)
    return finding


def malformed_policy_report(message: str, detected_at: str) -> dict[str, Any]:
    finding = make_finding(
        check_id="malformed-secret-declaration",
        repository=POLICY_OWNER,
        category="secret-hygiene",
        severity="failure",
        rule_id="malformed-declaration",
        location=POLICY_LOCATION,
        summary=f"Secret declaration cannot be consumed safely: {message}",
        detected_at=detected_at,
        runbook_ref=RUNBOOKS["malformed-declaration"],
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": detected_at,
        "state": "failure",
        "blocking": True,
        "policy": {"valid": False, "location": POLICY_LOCATION},
        "metadata": {
            "mode": "disabled",
            "status": "unavailable",
            "available_scopes": 0,
            "unavailable_scopes": 0,
        },
        "summary": {
            "repositories_evaluated": 0,
            "repositories_excluded": 0,
            "required_names": 0,
            "required_names_present": 0,
            "rotation_unknown": 0,
            "findings": 1,
        },
        "plaintext_scan": {
            "status": "not-run",
            "files_scanned": 0,
            "binary_files_skipped": 0,
            "fixture_files_skipped": 0,
            "oversized_files_skipped": 0,
            "symlinks_skipped": 0,
        },
        "findings": [finding],
    }


class GitHubMetadataClient:
    """Read only Actions secret names; never request values or public keys."""

    def __init__(self, token: str, *, timeout_seconds: int = 20) -> None:
        if not token:
            raise ValueError("a token is required for live metadata mode")
        self._token = token
        self._timeout_seconds = timeout_seconds

    def _json_get(self, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{GITHUB_API}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "atlas-dep-audit-secret-watch/1.0",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout_seconds
            ) as response:
                if response.status != 200:
                    raise MetadataUnavailable("unexpected-status")
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in {401, 403}:
                raise MetadataUnavailable("permission-denied") from error
            if error.code == 404:
                raise MetadataUnavailable(
                    "repository-or-environment-not-found"
                ) from error
            if error.code == 429:
                raise MetadataUnavailable("rate-limited") from error
            raise MetadataUnavailable("provider-error") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise MetadataUnavailable("network-unavailable") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MetadataUnavailable("invalid-provider-response") from error
        if not isinstance(payload, dict):
            raise MetadataUnavailable("invalid-provider-response")
        return payload

    def _list_names(self, path: str) -> frozenset[str]:
        names: set[str] = set()
        page = 1
        total_count: int | None = None
        while True:
            separator = "&" if "?" in path else "?"
            payload = self._json_get(f"{path}{separator}per_page=100&page={page}")
            if total_count is None:
                raw_total = payload.get("total_count")
                if (
                    not isinstance(raw_total, int)
                    or isinstance(raw_total, bool)
                    or raw_total < 0
                ):
                    raise MetadataUnavailable("invalid-provider-response")
                total_count = raw_total
            secrets = payload.get("secrets")
            if not isinstance(secrets, list):
                raise MetadataUnavailable("invalid-provider-response")
            for item in secrets:
                name = item.get("name") if isinstance(item, dict) else None
                if not isinstance(name, str) or not SECRET_NAME.fullmatch(name):
                    raise MetadataUnavailable("invalid-provider-response")
                names.add(name)
            if len(names) >= total_count:
                break
            if not secrets or page >= 100:
                raise MetadataUnavailable("incomplete-provider-response")
            page += 1
        return frozenset(names)

    def list_secret_names(
        self,
        repository: str,
        environment: str | None,
    ) -> frozenset[str]:
        owner, name = repository.split("/", 1)
        if environment is None:
            return self._list_names(f"/repos/{owner}/{name}/actions/secrets")
        metadata = self._json_get(f"/repos/{owner}/{name}")
        repository_id = metadata.get("id")
        if (
            not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id < 1
        ):
            raise MetadataUnavailable("invalid-provider-response")
        encoded_environment = urllib.parse.quote(environment, safe="")
        return self._list_names(
            f"/repositories/{repository_id}/environments/{encoded_environment}/secrets"
        )


def load_metadata_fixture(
    path: Path,
) -> dict[tuple[str, str | None], MetadataObservation]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyLoadError("metadata fixture is not valid UTF-8 JSON") from error
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != METADATA_FIXTURE_SCHEMA_VERSION
    ):
        raise PolicyLoadError("metadata fixture has an unsupported schema version")
    entries = payload.get("repositories")
    if not isinstance(entries, list):
        raise PolicyLoadError("metadata fixture repositories must be an array")
    observations: dict[tuple[str, str | None], MetadataObservation] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {
            "repository",
            "environment",
            "secret_names",
        }:
            raise PolicyLoadError(f"metadata fixture entry {index} is malformed")
        repository = entry.get("repository")
        environment = entry.get("environment")
        secret_names = entry.get("secret_names")
        if not isinstance(repository, str) or not REPOSITORY_NAME.fullmatch(repository):
            raise PolicyLoadError(
                f"metadata fixture entry {index} has an invalid repository"
            )
        if environment is not None and not isinstance(environment, str):
            raise PolicyLoadError(
                f"metadata fixture entry {index} has an invalid environment"
            )
        if not isinstance(secret_names, list) or any(
            not isinstance(name, str) or not SECRET_NAME.fullmatch(name)
            for name in secret_names
        ):
            raise PolicyLoadError(
                f"metadata fixture entry {index} has invalid secret names"
            )
        if len(secret_names) != len(set(secret_names)):
            raise PolicyLoadError(
                f"metadata fixture entry {index} has duplicate secret names"
            )
        key = (repository, environment)
        if key in observations:
            raise PolicyLoadError(f"metadata fixture entry {index} duplicates a scope")
        observations[key] = MetadataObservation(
            repository=repository,
            environment=environment,
            status="available",
            names=frozenset(secret_names),
            reason="fixture",
        )
    return observations


def collect_metadata(
    policy: dict[str, Any],
    *,
    fixture_path: Path | None = None,
    live_client: GitHubMetadataClient | None = None,
) -> tuple[dict[tuple[str, str | None], MetadataObservation], str]:
    if fixture_path is not None:
        fixture = load_metadata_fixture(fixture_path)
        mode = "fixture"
    elif live_client is not None:
        fixture = {}
        mode = "live"
    else:
        fixture = {}
        mode = "disabled"

    observations: dict[tuple[str, str | None], MetadataObservation] = {}
    for declaration in policy["repositories"]:
        if not declaration["assurance"]["enabled"]:
            continue
        repository = declaration["repository"]
        for scope in declaration["scopes"]:
            if scope["store"] != "github-actions":
                continue
            key = (repository, scope["environment"])
            if key in observations:
                continue
            if mode == "fixture":
                observations[key] = fixture.get(
                    key,
                    MetadataObservation(
                        repository,
                        key[1],
                        "unavailable",
                        frozenset(),
                        "fixture-missing",
                    ),
                )
            elif mode == "live":
                assert live_client is not None
                try:
                    names = live_client.list_secret_names(repository, key[1])
                    observations[key] = MetadataObservation(
                        repository, key[1], "available", names, "live"
                    )
                except MetadataUnavailable as error:
                    observations[key] = MetadataObservation(
                        repository, key[1], "unavailable", frozenset(), error.reason
                    )
            else:
                observations[key] = MetadataObservation(
                    repository, key[1], "disabled", frozenset(), "live-mode-disabled"
                )
    return observations, mode


def _suppression_keys(
    policy: dict[str, Any],
    now: datetime,
) -> set[tuple[str, str, int, str]]:
    keys: set[tuple[str, str, int, str]] = set()
    for suppression in policy["plaintext_scan"]["suppressions"]:
        expires_at = suppression.get("expires_at")
        if expires_at is not None and parse_timestamp(expires_at) < now:
            continue
        keys.add(
            (
                suppression["repository"],
                suppression["path"],
                suppression["line"],
                suppression["rule_id"],
            )
        )
    return keys


def _inline_suppressed(line: str, marker: str, rule_id: str) -> bool:
    if marker not in line:
        return False
    tail = line.split(marker, 1)[1].strip()
    return not tail or tail.split()[0] == rule_id


def _looks_like_placeholder(match: re.Match[str], rule: ScannerRule) -> bool:
    if rule.value_group is None:
        return False
    candidate = match.group(rule.value_group).lower()
    return any(marker in candidate for marker in PLACEHOLDER_MARKERS)


def tracked_paths(repository_root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repository_root,
        check=True,
        capture_output=True,
    )
    return sorted(
        item.decode("utf-8", errors="surrogateescape")
        for item in completed.stdout.split(b"\0")
        if item
    )


def scan_repository(
    repository: str,
    repository_root: Path,
    policy: dict[str, Any],
    detected_at: str,
) -> tuple[list[dict[str, Any]], ScanStats]:
    scan_policy = policy["plaintext_scan"]
    if not scan_policy["enabled"]:
        return [], ScanStats()
    now = parse_timestamp(detected_at)
    suppressions = _suppression_keys(policy, now)
    fixture_globs = scan_policy["fixture_globs"]
    marker = scan_policy["inline_suppression_marker"]
    max_file_bytes = scan_policy["max_file_bytes"]
    findings: list[dict[str, Any]] = []
    stats = ScanStats()

    for relative in tracked_paths(repository_root):
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            continue
        if any(fnmatch.fnmatch(relative, pattern) for pattern in fixture_globs):
            stats = stats.plus(fixture_files_skipped=1)
            continue
        path = repository_root / relative_path
        if path.is_symlink():
            stats = stats.plus(symlinks_skipped=1)
            continue
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        if size > max_file_bytes:
            stats = stats.plus(oversized_files_skipped=1)
            continue
        try:
            content = path.read_bytes()
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            continue
        if b"\0" in content:
            stats = stats.plus(binary_files_skipped=1)
            continue
        stats = stats.plus(files_scanned=1)
        text = content.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule in SCANNER_RULES:
                match = rule.pattern.search(line)
                if match is None or _looks_like_placeholder(match, rule):
                    continue
                if _inline_suppressed(line, marker, rule.rule_id):
                    continue
                if (repository, relative, line_number, rule.rule_id) in suppressions:
                    continue
                findings.append(
                    make_finding(
                        check_id=f"plaintext-{rule.rule_id}",
                        repository=repository,
                        category="security",
                        severity="critical",
                        rule_id="plaintext-credential-pattern",
                        location=f"{relative}:{line_number}",
                        summary=(
                            f"Redacted credential-like text matched rule {rule.rule_id}; "
                            "the matched text was discarded and is not present in this report."
                        ),
                        detected_at=detected_at,
                        runbook_ref=RUNBOOKS["plaintext-credential-pattern"],
                    )
                )
    return findings, stats


def declaration_findings(
    policy: dict[str, Any],
    detected_at: str,
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    now = parse_timestamp(detected_at)
    rotation_unknown = 0
    for name, definition in sorted(policy["secret_definitions"].items()):
        name_slug = _slug(name)
        if not _is_string(definition.get("owner")):
            findings.append(
                make_finding(
                    check_id=f"ownerless-secret-{name_slug}",
                    repository=POLICY_OWNER,
                    category="secret-hygiene",
                    severity="warning",
                    rule_id="ownerless-secret-declaration",
                    location=POLICY_LOCATION,
                    summary=f"Secret name {name} has no declared owner.",
                    detected_at=detected_at,
                    runbook_ref=RUNBOOKS["malformed-declaration"],
                )
            )
        if not _is_string(definition.get("purpose")):
            findings.append(
                make_finding(
                    check_id=f"missing-secret-purpose-{name_slug}",
                    repository=POLICY_OWNER,
                    category="secret-hygiene",
                    severity="warning",
                    rule_id="missing-secret-purpose",
                    location=POLICY_LOCATION,
                    summary=f"Secret name {name} has no declared purpose.",
                    detected_at=detected_at,
                    runbook_ref=RUNBOOKS["malformed-declaration"],
                )
            )
        rotation = definition["rotation"]
        if not rotation["required"]:
            continue
        max_age = rotation.get("max_age_days")
        last_rotated_at = rotation.get("last_rotated_at")
        if max_age is None:
            findings.append(
                make_finding(
                    check_id=f"missing-rotation-metadata-{name_slug}",
                    repository=POLICY_OWNER,
                    category="secret-hygiene",
                    severity="warning",
                    rule_id="missing-rotation-metadata",
                    location=POLICY_LOCATION,
                    summary=f"Secret name {name} requires rotation but has no maximum age.",
                    detected_at=detected_at,
                    runbook_ref=RUNBOOKS["rotation-overdue"],
                )
            )
        if last_rotated_at is None:
            rotation_unknown += 1
            continue
        if (
            max_age is not None
            and parse_timestamp(last_rotated_at) + timedelta(days=max_age) < now
        ):
            findings.append(
                make_finding(
                    check_id=f"rotation-overdue-{name_slug}",
                    repository=POLICY_OWNER,
                    category="secret-hygiene",
                    severity="failure",
                    rule_id="rotation-overdue",
                    location=POLICY_LOCATION,
                    summary=f"Secret name {name} is overdue under its owner-attested maximum age.",
                    detected_at=detected_at,
                    runbook_ref=RUNBOOKS["rotation-overdue"],
                )
            )

    expected_simple_proxy = {
        "lifecycle": "deprecated",
        "scope": "internal",
        "provenance": "external-derived",
    }
    for declaration in policy["repositories"]:
        repository = declaration["repository"]
        classification = declaration["classification"]
        assurance = declaration["assurance"]
        conflict = False
        if (
            classification["lifecycle"] in {"deprecated", "archived"}
            and assurance["enabled"]
        ):
            conflict = True
        if classification["provenance"] == "external-derived" and assurance["enabled"]:
            conflict = True
        if not assurance["enabled"] and not _is_string(
            assurance.get("exclusion_reason")
        ):
            conflict = True
        if repository == "AtlasReaper311/simple-proxy" and (
            classification != expected_simple_proxy or assurance["enabled"]
        ):
            conflict = True
        if conflict:
            findings.append(
                make_finding(
                    check_id=f"classification-conflict-{_slug(repository)}",
                    repository=repository,
                    category="secret-hygiene",
                    severity="failure",
                    rule_id="repository-classification-conflict",
                    location=POLICY_LOCATION,
                    summary="Repository classification conflicts with its secret-assurance inclusion state.",
                    detected_at=detected_at,
                    runbook_ref=RUNBOOKS["malformed-declaration"],
                )
            )
    return findings, rotation_unknown


def metadata_findings(
    policy: dict[str, Any],
    observations: dict[tuple[str, str | None], MetadataObservation],
    detected_at: str,
) -> tuple[list[dict[str, Any]], dict[str, int], bool]:
    findings: list[dict[str, Any]] = []
    counts = {
        "required": 0,
        "required_present": 0,
        "available_scopes": 0,
        "unavailable_scopes": 0,
    }
    blocking = False
    global_required = policy["github_metadata"]["mode"] == "required"
    for declaration in policy["repositories"]:
        if not declaration["assurance"]["enabled"]:
            continue
        repository = declaration["repository"]
        metadata_required = (
            global_required or declaration["assurance"]["metadata_required"]
        )
        for scope in declaration["scopes"]:
            if scope["store"] != "github-actions":
                continue
            required = set(scope["required_secret_names"])
            optional = set(scope["optional_secret_names"])
            deprecated = set(scope["deprecated_secret_names"])
            counts["required"] += len(required)
            key = (repository, scope["environment"])
            observation = observations[key]
            environment_label = scope["environment"] or "repository"
            if observation.status != "available":
                counts["unavailable_scopes"] += 1
                severity = "failure" if metadata_required else "warning"
                blocking = blocking or metadata_required
                findings.append(
                    make_finding(
                        check_id=f"metadata-unavailable-{_slug(repository)}-{_slug(environment_label)}",
                        repository=repository,
                        category="secret-hygiene",
                        severity=severity,
                        rule_id="metadata-unavailable",
                        location=POLICY_LOCATION,
                        summary=(
                            f"Names-only metadata is {observation.status} for {environment_label} scope "
                            f"({observation.reason}); health is unknown."
                        ),
                        detected_at=detected_at,
                        runbook_ref=RUNBOOKS["metadata-unavailable"],
                    )
                )
                continue
            counts["available_scopes"] += 1
            counts["required_present"] += len(required & observation.names)
            for name in sorted(required - observation.names):
                findings.append(
                    make_finding(
                        check_id=f"missing-required-{_slug(name)}-{_slug(environment_label)}",
                        repository=repository,
                        category="secret-hygiene",
                        severity="failure",
                        rule_id="missing-required-secret",
                        location=POLICY_LOCATION,
                        summary=f"Required secret name {name} is absent from {environment_label} metadata.",
                        detected_at=detected_at,
                        runbook_ref=RUNBOOKS["missing-required-secret"],
                    )
                )
            for name in sorted(observation.names - required - optional - deprecated):
                findings.append(
                    make_finding(
                        check_id=f"unexpected-secret-{_slug(name)}-{_slug(environment_label)}",
                        repository=repository,
                        category="secret-hygiene",
                        severity="warning",
                        rule_id="unexpected-secret-name",
                        location=POLICY_LOCATION,
                        summary=f"Unexpected secret name {name} is present in {environment_label} metadata.",
                        detected_at=detected_at,
                        runbook_ref=RUNBOOKS["missing-required-secret"],
                    )
                )
            for name in sorted(deprecated & observation.names):
                findings.append(
                    make_finding(
                        check_id=f"deprecated-secret-{_slug(name)}-{_slug(environment_label)}",
                        repository=repository,
                        category="secret-hygiene",
                        severity="failure",
                        rule_id="deprecated-secret-present",
                        location=POLICY_LOCATION,
                        summary=f"Deprecated secret name {name} is still present in {environment_label} metadata.",
                        detected_at=detected_at,
                        runbook_ref=RUNBOOKS["deprecated-secret-present"],
                    )
                )
    return findings, counts, blocking


def _report_state(findings: Iterable[dict[str, Any]], metadata_status: str) -> str:
    severities = {finding["severity"] for finding in findings}
    if "critical" in severities or "failure" in severities:
        return "failure"
    if "warning" in severities:
        return "warning"
    if metadata_status != "available":
        return "unknown"
    return "healthy"


def run_secret_watch(
    policy_path: Path,
    repository_roots: dict[str, Path],
    *,
    metadata_fixture: Path | None = None,
    live_client: GitHubMetadataClient | None = None,
    detected_at: str | None = None,
) -> dict[str, Any]:
    timestamp = utc_timestamp(detected_at)
    try:
        policy = load_policy(policy_path)
        observations, metadata_mode = collect_metadata(
            policy,
            fixture_path=metadata_fixture,
            live_client=live_client,
        )
    except PolicyLoadError as error:
        return malformed_policy_report(str(error), timestamp)

    findings, rotation_unknown = declaration_findings(policy, timestamp)
    comparison_findings, counts, metadata_blocking = metadata_findings(
        policy, observations, timestamp
    )
    findings.extend(comparison_findings)

    declarations = {item["repository"]: item for item in policy["repositories"]}
    excluded = {
        repository
        for repository, declaration in declarations.items()
        if not declaration["assurance"]["enabled"]
    }
    scan_stats = ScanStats()
    if policy["plaintext_scan"]["enabled"]:
        for repository, root in sorted(repository_roots.items()):
            if repository in excluded or not root.is_dir():
                continue
            try:
                local_findings, local_stats = scan_repository(
                    repository, root, policy, timestamp
                )
            except subprocess.CalledProcessError:
                findings.append(
                    make_finding(
                        check_id=f"plaintext-scan-unavailable-{_slug(repository)}",
                        repository=repository,
                        category="security",
                        severity="failure",
                        rule_id="plaintext-scan-unavailable",
                        location=".gitignore",
                        summary="Tracked-file enumeration failed; plaintext scan coverage is unavailable.",
                        detected_at=timestamp,
                        runbook_ref=RUNBOOKS["plaintext-credential-pattern"],
                    )
                )
                continue
            findings.extend(local_findings)
            scan_stats = ScanStats(
                files_scanned=scan_stats.files_scanned + local_stats.files_scanned,
                binary_files_skipped=scan_stats.binary_files_skipped
                + local_stats.binary_files_skipped,
                fixture_files_skipped=scan_stats.fixture_files_skipped
                + local_stats.fixture_files_skipped,
                oversized_files_skipped=scan_stats.oversized_files_skipped
                + local_stats.oversized_files_skipped,
                symlinks_skipped=scan_stats.symlinks_skipped
                + local_stats.symlinks_skipped,
            )

    findings.sort(key=lambda item: (item["fingerprint"], item["rule_id"]))
    statuses = {observation.status for observation in observations.values()}
    if not observations:
        metadata_status = "disabled"
    elif statuses == {"available"}:
        metadata_status = "available"
    elif "available" in statuses:
        metadata_status = "partial"
    elif "unavailable" in statuses:
        metadata_status = "unavailable"
    else:
        metadata_status = "disabled"
    blocking = metadata_blocking or any(
        finding["severity"] in {"failure", "critical"} for finding in findings
    )
    state = _report_state(findings, metadata_status)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": timestamp,
        "state": state,
        "blocking": blocking,
        "policy": {"valid": True, "location": POLICY_LOCATION},
        "metadata": {
            "mode": metadata_mode,
            "status": metadata_status,
            "available_scopes": counts["available_scopes"],
            "unavailable_scopes": counts["unavailable_scopes"],
        },
        "summary": {
            "repositories_evaluated": len(repository_roots)
            - len(excluded & set(repository_roots)),
            "repositories_excluded": len(excluded),
            "required_names": counts["required"],
            "required_names_present": counts["required_present"],
            "rotation_unknown": rotation_unknown,
            "findings": len(findings),
        },
        "plaintext_scan": {
            "status": "completed"
            if policy["plaintext_scan"]["enabled"]
            else "disabled",
            "files_scanned": scan_stats.files_scanned,
            "binary_files_skipped": scan_stats.binary_files_skipped,
            "fixture_files_skipped": scan_stats.fixture_files_skipped,
            "oversized_files_skipped": scan_stats.oversized_files_skipped,
            "symlinks_skipped": scan_stats.symlinks_skipped,
        },
        "findings": findings,
    }


def render_summary(report: dict[str, Any]) -> str:
    metadata = report["metadata"]
    summary = report["summary"]
    scan = report["plaintext_scan"]
    lines = [
        "## Secret watch",
        "",
        f"State: **{report['state']}**  ",
        f"Policy valid: **{str(report['policy']['valid']).lower()}**  ",
        f"Metadata: **{metadata['status']}** ({metadata['mode']})  ",
        f"Repositories evaluated: **{summary['repositories_evaluated']}**  ",
        f"Repositories excluded: **{summary['repositories_excluded']}**  ",
        f"Required names present: **{summary['required_names_present']}/{summary['required_names']}**  ",
        f"Rotation status unknown: **{summary['rotation_unknown']}**  ",
        f"Tracked text files scanned: **{scan['files_scanned']}**  ",
        f"Findings: **{summary['findings']}**",
        "",
    ]
    if report["findings"]:
        lines.extend(
            [
                "| Severity | Repository | Rule | Location | Redacted evidence |",
                "|---|---|---|---|---|",
            ]
        )
        for finding in report["findings"]:
            lines.append(
                "| {severity} | `{repository}` | `{rule}` | `{location}` | {summary} |".format(
                    severity=finding["severity"],
                    repository=finding["subject"]["repository"],
                    rule=finding["rule_id"],
                    location=finding["location"],
                    summary=finding["evidence"]["summary"].replace("|", "\\|"),
                )
            )
    else:
        lines.append("No secret-watch findings.")
    return "\n".join(lines) + "\n"


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def repository_roots_from_directory(root: Path) -> dict[str, Path]:
    repositories: dict[str, Path] = {}
    if not root.is_dir():
        return repositories
    for child in sorted(root.iterdir()):
        if child.is_dir() and (child / ".git").exists():
            repositories[f"AtlasReaper311/{child.name}"] = child
    return repositories


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--repositories-root", type=Path, required=True)
    parser.add_argument("--metadata-fixture", type=Path)
    parser.add_argument("--live-github", action="store_true")
    parser.add_argument("--now")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    live_client: GitHubMetadataClient | None = None
    if args.live_github:
        token = os.getenv(TOKEN_ENVIRONMENT_NAME, "")
        if token:
            live_client = GitHubMetadataClient(token)
    roots = repository_roots_from_directory(args.repositories_root.resolve())
    report = run_secret_watch(
        args.policy.resolve(),
        roots,
        metadata_fixture=args.metadata_fixture.resolve()
        if args.metadata_fixture
        else None,
        live_client=live_client,
        detected_at=args.now,
    )
    write_report(args.report, report)
    markdown = render_summary(report)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")
    print(markdown, end="")
    return 1 if report["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
