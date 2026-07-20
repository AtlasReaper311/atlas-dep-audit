#!/usr/bin/env python3
"""Generate source SBOMs, provenance records, and OSV findings for the estate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import contract_validation
import secret_watch

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
USES_LINE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s;]+)")
PEP508_PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([^\s;]+)")
SEVERITY_ORDER = {
    "unknown": 0,
    "low": 1,
    "moderate": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str
    purl: str
    scope: str
    license: str
    source_file: str


@dataclass(frozen=True)
class Vulnerability:
    repo: str
    dependency: str
    version: str
    vulnerability_id: str
    severity: str
    fixed_version: str | None
    source_file: str


@dataclass(frozen=True)
class PolicyFinding:
    repo: str
    severity: str
    rule: str
    path: str
    message: str


def load_json(source: str) -> dict[str, Any]:
    if source.startswith("https://"):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "atlas-dep-audit/1.0"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    return json.loads(Path(source).read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def normalize_repo(url: str) -> str:
    cleaned = url.removesuffix(".git").rstrip("/")
    if "github.com/" in cleaned:
        return cleaned.split("github.com/", 1)[1]
    return cleaned


def clone_repository(full_name: str, destination: Path, token: str) -> Path:
    target = destination / full_name.split("/", 1)[1]
    if target.exists():
        shutil.rmtree(target)
    url = f"https://github.com/{full_name}.git"
    env = os.environ.copy()
    askpass_path: Path | None = None
    if token:
        askpass_path = destination / ".git-askpass.sh"
        askpass_path.write_text(
            "#!/usr/bin/env sh\n"
            "case \"$1\" in\n"
            "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
            "  *Password*) printf '%s\\n' \"$GH_DIGEST_PAT\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        askpass_path.chmod(0o700)
        env["GIT_ASKPASS"] = str(askpass_path)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GH_DIGEST_PAT"] = token
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", url, str(target)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    finally:
        if askpass_path and askpass_path.exists():
            askpass_path.unlink()
    return target


def npm_name_from_path(path: str, entry: dict[str, Any]) -> str | None:
    if entry.get("name"):
        return str(entry["name"])
    marker = "node_modules/"
    if marker not in path:
        return None
    tail = path.rsplit(marker, 1)[1]
    parts = tail.split("/")
    if tail.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def npm_components(
    path: Path,
    repo_root: Path,
) -> tuple[list[Component], list[PolicyFinding]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    components: list[Component] = []
    findings: list[PolicyFinding] = []
    relative = str(path.relative_to(repo_root))
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, entry in packages.items():
            if not package_path or not isinstance(entry, dict):
                continue
            name = npm_name_from_path(package_path, entry)
            version = str(entry.get("version") or "")
            if not name or not version:
                continue
            encoded = urllib.parse.quote(name, safe="/")
            components.append(
                Component(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    purl=f"pkg:npm/{encoded}@{version}",
                    scope="development" if entry.get("dev") else "required",
                    license=str(entry.get("license") or "UNKNOWN"),
                    source_file=relative,
                )
            )
    else:

        def walk(dependencies: dict[str, Any]) -> None:
            for name, entry in dependencies.items():
                if not isinstance(entry, dict):
                    continue
                version = str(entry.get("version") or "")
                if version:
                    encoded = urllib.parse.quote(name, safe="/")
                    components.append(
                        Component(
                            ecosystem="npm",
                            name=name,
                            version=version,
                            purl=f"pkg:npm/{encoded}@{version}",
                            scope="development" if entry.get("dev") else "required",
                            license=str(entry.get("license") or "UNKNOWN"),
                            source_file=relative,
                        )
                    )
                child = entry.get("dependencies")
                if isinstance(child, dict):
                    walk(child)

        walk(payload.get("dependencies", {}))
    return components, findings


def requirements_components(
    path: Path,
    repo_root: Path,
    repo: str,
) -> tuple[list[Component], list[PolicyFinding]]:
    components: list[Component] = []
    findings: list[PolicyFinding] = []
    relative = str(path.relative_to(repo_root))
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(
            ("-r", "--", "git+", "http://", "https://")
        ):
            continue
        match = REQUIREMENT.match(line)
        if not match:
            findings.append(
                PolicyFinding(
                    repo,
                    "warning",
                    "python-unpinned",
                    relative,
                    f"Line {line_number} is not pinned with ==: {line[:120]}",
                )
            )
            continue
        name, version = match.groups()
        normalized = name.lower().replace("_", "-")
        components.append(
            Component(
                ecosystem="PyPI",
                name=normalized,
                version=version,
                purl=f"pkg:pypi/{urllib.parse.quote(normalized)}@{version}",
                scope="required",
                license="UNKNOWN",
                source_file=relative,
            )
        )
    return components, findings


def pyproject_components(
    path: Path,
    repo_root: Path,
    repo: str,
) -> tuple[list[Component], list[PolicyFinding]]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies = payload.get("project", {}).get("dependencies", [])
    components: list[Component] = []
    findings: list[PolicyFinding] = []
    relative = str(path.relative_to(repo_root))
    for dependency in dependencies:
        match = PEP508_PIN.match(str(dependency))
        if not match:
            findings.append(
                PolicyFinding(
                    repo,
                    "warning",
                    "python-unpinned",
                    relative,
                    f"Project dependency is not pinned with ==: {dependency}",
                )
            )
            continue
        name, version = match.groups()
        normalized = name.lower().replace("_", "-")
        components.append(
            Component(
                ecosystem="PyPI",
                name=normalized,
                version=version,
                purl=f"pkg:pypi/{urllib.parse.quote(normalized)}@{version}",
                scope="required",
                license="UNKNOWN",
                source_file=relative,
            )
        )
    return components, findings


def poetry_lock_components(
    path: Path,
    repo_root: Path,
) -> tuple[list[Component], list[PolicyFinding]]:
    """Read exact PyPI versions from Poetry's lockfile."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    relative = str(path.relative_to(repo_root))
    components: list[Component] = []
    for entry in payload.get("package", []):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").lower().replace("_", "-")
        version = str(entry.get("version") or "")
        if not name or not version:
            continue
        category = str(entry.get("category") or "main")
        groups = entry.get("groups") or []
        development = category == "dev" or "dev" in groups
        components.append(
            Component(
                ecosystem="PyPI",
                name=name,
                version=version,
                purl=f"pkg:pypi/{urllib.parse.quote(name)}@{version}",
                scope="development" if development else "required",
                license="UNKNOWN",
                source_file=relative,
            )
        )
    return components, []


def pipfile_lock_components(
    path: Path,
    repo_root: Path,
) -> tuple[list[Component], list[PolicyFinding]]:
    """Read exact PyPI versions from Pipenv's lockfile."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    relative = str(path.relative_to(repo_root))
    components: list[Component] = []
    findings: list[PolicyFinding] = []
    for section, scope in (("default", "required"), ("develop", "development")):
        for raw_name, entry in (payload.get(section) or {}).items():
            value = entry if isinstance(entry, str) else (entry or {}).get("version", "")
            value = str(value)
            if not value.startswith("=="):
                findings.append(
                    PolicyFinding(
                        str(repo_root.name),
                        "warning",
                        "python-unpinned",
                        relative,
                        f"Pipfile.lock entry is not an exact == pin: {raw_name} {value}",
                    )
                )
                continue
            name = str(raw_name).lower().replace("_", "-")
            version = value[2:]
            components.append(
                Component(
                    ecosystem="PyPI",
                    name=name,
                    version=version,
                    purl=f"pkg:pypi/{urllib.parse.quote(name)}@{version}",
                    scope=scope,
                    license="UNKNOWN",
                    source_file=relative,
                )
            )
    return components, findings


def parse_actions(
    repo_root: Path,
    repo: str,
) -> tuple[list[dict[str, str]], list[PolicyFinding]]:
    actions: list[dict[str, str]] = []
    findings: list[PolicyFinding] = []
    workflows = repo_root / ".github" / "workflows"
    if not workflows.exists():
        return actions, findings
    for path in sorted(workflows.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = str(path.relative_to(repo_root))
        for value in USES_LINE.findall(text):
            if value.startswith("./") or value.startswith("docker://"):
                continue
            action, separator, ref = value.rpartition("@")
            pinned = bool(separator and FULL_SHA.fullmatch(ref))
            actions.append(
                {
                    "path": relative,
                    "action": action or value,
                    "ref": ref,
                    "pinned": str(pinned).lower(),
                }
            )
            if not pinned:
                findings.append(
                    PolicyFinding(
                        repo,
                        "warning",
                        "actions-pin",
                        relative,
                        f"Action is not pinned to a full commit SHA: {value}",
                    )
                )
    return actions, findings


def parse_container_bases(
    repo_root: Path,
    repo: str,
) -> tuple[list[dict[str, str]], list[PolicyFinding]]:
    bases: list[dict[str, str]] = []
    findings: list[PolicyFinding] = []
    dockerfiles = [
        path
        for path in repo_root.rglob("Dockerfile*")
        if ".git" not in path.parts
    ]
    for path in sorted(dockerfiles):
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
    return bases, findings


def discover_components(
    repo_root: Path,
    repo: str,
) -> tuple[list[Component], list[PolicyFinding], list[Path]]:
    components: list[Component] = []
    findings: list[PolicyFinding] = []
    manifests: list[Path] = []

    for path in repo_root.rglob("package-lock.json"):
        if ".git" in path.parts or "node_modules" in path.parts:
            continue
        manifests.append(path)
        found, local_findings = npm_components(path, repo_root)
        components.extend(found)
        findings.extend(local_findings)

    for path in repo_root.rglob("requirements.txt"):
        if ".git" in path.parts or ".venv" in path.parts:
            continue
        manifests.append(path)
        found, local_findings = requirements_components(path, repo_root, repo)
        components.extend(found)
        findings.extend(local_findings)

    for path in repo_root.rglob("poetry.lock"):
        if ".git" in path.parts or ".venv" in path.parts:
            continue
        manifests.append(path)
        found, local_findings = poetry_lock_components(path, repo_root)
        components.extend(found)
        findings.extend(local_findings)

    for path in repo_root.rglob("Pipfile.lock"):
        if ".git" in path.parts or ".venv" in path.parts:
            continue
        manifests.append(path)
        found, local_findings = pipfile_lock_components(path, repo_root)
        components.extend(found)
        findings.extend(local_findings)

    for path in repo_root.rglob("pyproject.toml"):
        if ".git" in path.parts or ".venv" in path.parts:
            continue
        if (path.parent / "poetry.lock").exists():
            continue
        manifests.append(path)
        found, local_findings = pyproject_components(path, repo_root, repo)
        components.extend(found)
        findings.extend(local_findings)

    unique = {
        (item.purl, item.source_file, item.scope): item
        for item in components
    }
    return (
        sorted(
            unique.values(),
            key=lambda item: (item.ecosystem, item.name, item.version),
        ),
        findings,
        sorted(set(manifests)),
    )


def cyclonedx(repo: str, commit: str, components: list[Component]) -> dict[str, Any]:
    serial = hashlib.sha256(f"{repo}:{commit}".encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": (
            f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-"
            f"{serial[16:20]}-{serial[20:32]}"
        ),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": repo,
                "version": commit,
            },
            "tools": [
                {
                    "vendor": "Atlas Systems",
                    "name": "atlas-dep-audit",
                    "version": "1.0.0",
                }
            ],
        },
        "components": [
            {
                "type": "library",
                "name": item.name,
                "version": item.version,
                "purl": item.purl,
                "scope": item.scope,
                "licenses": [{"license": {"name": item.license}}],
                "properties": [
                    {"name": "atlas:ecosystem", "value": item.ecosystem},
                    {"name": "atlas:source_file", "value": item.source_file},
                ],
            }
            for item in components
        ],
    }


def osv_query(components: list[Component]) -> list[dict[str, Any]]:
    if not components:
        return []
    all_results: list[dict[str, Any]] = []
    for offset in range(0, len(components), 500):
        batch = components[offset : offset + 500]
        payload = json.dumps(
            {
                "queries": [
                    {"package": {"purl": item.purl}}
                    for item in batch
                ]
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "atlas-dep-audit/1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.load(response)
        all_results.extend(data.get("results", []))
        if offset + 500 < len(components):
            time.sleep(1)
    return all_results


def cvss_v3_score(vector: str) -> float | None:
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    scope_changed = metrics["S"] == "C"
    pr_values = {
        False: {"N": 0.85, "L": 0.62, "H": 0.27},
        True: {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    pr = pr_values[scope_changed][metrics["PR"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
    confidentiality = impact_values[metrics["C"]]
    integrity = impact_values[metrics["I"]]
    availability = impact_values[metrics["A"]]
    impact_subscore = (
        1
        - (1 - confidentiality)
        * (1 - integrity)
        * (1 - availability)
    )
    if scope_changed:
        impact = (
            7.52 * (impact_subscore - 0.029)
            - 3.25 * (impact_subscore - 0.02) ** 15
        )
    else:
        impact = 6.42 * impact_subscore
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    base = (
        min(1.08 * (impact + exploitability), 10)
        if scope_changed
        else min(impact + exploitability, 10)
    )
    return float(int(base * 10 + 0.999999)) / 10


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "moderate"
    if score > 0:
        return "low"
    return "unknown"


def severity_of(vulnerability: dict[str, Any]) -> str:
    value = str(
        vulnerability.get("database_specific", {}).get("severity") or ""
    ).lower()
    if value in SEVERITY_ORDER:
        return "moderate" if value == "medium" else value
    scores = []
    for entry in vulnerability.get("severity", []):
        vector = str(entry.get("score") or "")
        score = cvss_v3_score(vector)
        if score is not None:
            scores.append(score)
    if scores:
        return severity_from_score(max(scores))
    aliases = " ".join(vulnerability.get("aliases", []))
    summary = (
        f"{vulnerability.get('summary', '')} "
        f"{vulnerability.get('details', '')} {aliases}"
    ).lower()
    for level in ("critical", "high", "moderate", "low"):
        if re.search(rf"\b{level}\b", summary):
            return level
    return "unknown"


def fixed_version_of(vulnerability: dict[str, Any]) -> str | None:
    fixed: list[str] = []
    for affected in vulnerability.get("affected", []):
        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                if event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    return sorted(set(fixed))[0] if fixed else None


def vulnerabilities_for(
    repo: str,
    components: list[Component],
    results: list[dict[str, Any]],
) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    for component, result in zip(components, results, strict=False):
        for vulnerability in result.get("vulns", []):
            findings.append(
                Vulnerability(
                    repo=repo,
                    dependency=component.name,
                    version=component.version,
                    vulnerability_id=str(vulnerability.get("id") or "unknown"),
                    severity=severity_of(vulnerability),
                    fixed_version=fixed_version_of(vulnerability),
                    source_file=component.source_file,
                )
            )
    return findings


def render_summary(
    repos: list[str],
    clean_repos: list[str],
    vulnerabilities: list[Vulnerability],
    policy_findings: list[PolicyFinding],
    secret_watch_report: dict[str, Any] | None = None,
) -> str:
    severity_counts = Counter(item.severity for item in vulnerabilities)
    lines = [
        "# Atlas Systems supply-chain report",
        "",
        f"Repositories scanned: **{len(repos)}**  ",
        f"Repositories with no vulnerability finding: **{len(clean_repos)}**  ",
        f"Vulnerabilities: **{len(vulnerabilities)}**  ",
        f"Supply-chain policy findings: **{len(policy_findings)}**",
        "",
        "## Severity totals",
        "",
    ]
    for level in ("critical", "high", "moderate", "low", "unknown"):
        lines.append(f"- {level}: **{severity_counts.get(level, 0)}**")
    lines.extend(["", "## Vulnerabilities", ""])
    if vulnerabilities:
        lines.extend(
            [
                "| Repository | Dependency | Installed | Severity | Fixed | ID |",
                "|---|---|---|---|---|---|",
            ]
        )
        for item in sorted(
            vulnerabilities,
            key=lambda value: (
                -SEVERITY_ORDER.get(value.severity, 0),
                value.repo,
                value.dependency,
            ),
        ):
            lines.append(
                f"| `{item.repo}` | `{item.dependency}` | `{item.version}` | "
                f"{item.severity} | `{item.fixed_version or 'not published'}` | "
                f"`{item.vulnerability_id}` |"
            )
    else:
        lines.append("No known vulnerabilities were returned by OSV.")
    lines.extend(["", "## Supply-chain policy findings", ""])
    if policy_findings:
        lines.extend(
            [
                "| Severity | Repository | Rule | Path | Finding |",
                "|---|---|---|---|---|",
            ]
        )
        for item in sorted(
            policy_findings,
            key=lambda value: (value.repo, value.rule, value.path),
        ):
            message = item.message.replace("|", "\\|")
            lines.append(
                f"| {item.severity} | `{item.repo}` | `{item.rule}` | "
                f"`{item.path}` | {message} |"
            )
    else:
        lines.append("No supply-chain policy findings.")
    lines.extend(
        [
            "",
            "## Evidence",
            "",
            "Each repository has a CycloneDX source SBOM and a provenance record "
            "containing the commit, manifest hashes, action refs, and container "
            "base refs. These records describe source and build inputs. They do "
            "not claim to inventory operating-system packages inside an image "
            "that was not built during this run.",
        ]
    )
    rendered = "\n".join(lines) + "\n"
    if secret_watch_report is not None:
        rendered += "\n" + secret_watch.render_summary(secret_watch_report)
    return rendered


def write_provenance(
    output: Path,
    repo: str,
    commit: str,
    manifests: list[Path],
    repo_root: Path,
    actions: list[dict[str, str]],
    container_bases: list[dict[str, str]],
    sbom_path: Path,
    contract_result: contract_validation.ContractValidationResult | None,
) -> None:
    payload = {
        "schema": "atlas-build-provenance/v1",
        "repository": repo,
        "commit": commit,
        "workflow_run": (
            os.getenv("GITHUB_SERVER_URL", "https://github.com")
            + "/"
            + os.getenv("GITHUB_REPOSITORY", "AtlasReaper311/atlas-dep-audit")
            + "/actions/runs/"
            + os.getenv("GITHUB_RUN_ID", "local")
        ),
        "manifests": [
            {
                "path": str(path.relative_to(repo_root)),
                "sha256": sha256_file(path),
            }
            for path in manifests
        ],
        "github_actions": actions,
        "container_bases": container_bases,
        "sbom": {
            "path": sbom_path.name,
            "sha256": sha256_file(sbom_path),
        },
    }
    if contract_result is not None:
        payload["control_plane_contract_validation"] = contract_result.provenance()
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--work-dir", default="work")
    parser.add_argument("--report-dir", default="reports")
    parser.add_argument("--sbom-dir", default="sbom")
    parser.add_argument("--provenance-dir", default="provenance")
    parser.add_argument("--skip-osv", action="store_true")
    parser.add_argument("--local-repositories-root", type=Path)
    parser.add_argument("--secret-policy", type=Path)
    parser.add_argument("--secret-metadata-fixture", type=Path)
    parser.add_argument("--secret-watch-live", action="store_true")
    parser.add_argument("--secret-watch-now")
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    policy = load_json(args.policy)
    token = os.getenv("GH_DIGEST_PAT") or os.getenv("GITHUB_TOKEN", "")
    repos = sorted(
        {
            normalize_repo(item["url"])
            for item in manifest.get("repositories", [])
            if item.get("url") and "github.com/" in item["url"]
        }
    )

    work_dir = Path(args.work_dir)
    report_dir = Path(args.report_dir)
    sbom_dir = Path(args.sbom_dir)
    provenance_dir = Path(args.provenance_dir)
    for directory in (work_dir, report_dir, sbom_dir, provenance_dir):
        directory.mkdir(parents=True, exist_ok=True)

    vulnerabilities: list[Vulnerability] = []
    policy_findings: list[PolicyFinding] = []
    clean_repos: list[str] = []
    repository_roots: dict[str, Path] = {}

    for repo in repos:
        print(f"Scanning {repo}", flush=True)
        if args.local_repositories_root:
            repo_root = (
                args.local_repositories_root.resolve()
                / repo.split("/", 1)[1]
            )
            if not (repo_root / ".git").exists():
                policy_findings.append(
                    PolicyFinding(
                        repo,
                        "error",
                        "local-checkout",
                        "",
                        "Declared repository is missing from the offline checkout root.",
                    )
                )
                continue
        else:
            try:
                repo_root = clone_repository(repo, work_dir, token)
            except subprocess.CalledProcessError as error:
                detail = (
                    (error.stderr or str(error)).strip().replace(token, "[redacted]")
                    if token
                    else (error.stderr or str(error)).strip()
                )
                policy_findings.append(
                    PolicyFinding(repo, "error", "clone", "", detail[:300])
                )
                continue

        repository_roots[repo] = repo_root
        commit = run(["git", "rev-parse", "HEAD"], cwd=repo_root)
        components, component_findings, manifests = discover_components(
            repo_root,
            repo,
        )
        actions, action_findings = parse_actions(repo_root, repo)
        container_bases, container_findings = parse_container_bases(repo_root, repo)
        contract_result = contract_validation.validate_checkout(repo, repo_root)
        policy_findings.extend(component_findings)
        policy_findings.extend(action_findings)
        policy_findings.extend(container_findings)
        if contract_result is not None and contract_result.status == "failed":
            policy_findings.append(
                PolicyFinding(
                    repo,
                    "error",
                    "control-plane-contract-validation",
                    "contracts/v1",
                    contract_result.error,
                )
            )

        safe_name = repo.replace("/", "__")
        sbom_path = sbom_dir / f"{safe_name}.cdx.json"
        sbom_path.write_text(
            json.dumps(
                cyclonedx(repo, commit, components),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        provenance_path = provenance_dir / f"{safe_name}.provenance.json"
        write_provenance(
            provenance_path,
            repo,
            commit,
            manifests,
            repo_root,
            actions,
            container_bases,
            sbom_path,
            contract_result,
        )

        repo_vulnerabilities: list[Vulnerability] = []
        if not args.skip_osv:
            try:
                results = osv_query(components)
                repo_vulnerabilities = vulnerabilities_for(
                    repo,
                    components,
                    results,
                )
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
            ) as error:
                policy_findings.append(
                    PolicyFinding(
                        repo,
                        "warning",
                        "osv-query",
                        "",
                        f"OSV query failed: {error}",
                    )
                )
        vulnerabilities.extend(repo_vulnerabilities)
        if not repo_vulnerabilities:
            clean_repos.append(repo)

    canonical_root = repository_roots.get(contract_validation.CONTRACT_OWNER)
    if args.secret_policy:
        secret_policy_path = args.secret_policy.resolve()
    elif canonical_root is not None:
        secret_policy_path = canonical_root / "policy" / "secret-watch.json"
    else:
        secret_policy_path = work_dir / "atlas-infra" / "policy" / "secret-watch.json"

    live_client: secret_watch.GitHubMetadataClient | None = None
    if args.secret_watch_live:
        secret_token = os.getenv(secret_watch.TOKEN_ENVIRONMENT_NAME, "")
        if secret_token:
            live_client = secret_watch.GitHubMetadataClient(secret_token)
    secret_watch_report = secret_watch.run_secret_watch(
        secret_policy_path,
        repository_roots,
        metadata_fixture=(
            args.secret_metadata_fixture.resolve()
            if args.secret_metadata_fixture
            else None
        ),
        live_client=live_client,
        detected_at=args.secret_watch_now,
    )
    secret_watch.write_report(
        report_dir / "secret-watch.json",
        secret_watch_report,
    )
    (report_dir / "secret-watch.md").write_text(
        secret_watch.render_summary(secret_watch_report),
        encoding="utf-8",
    )

    summary = render_summary(
        repos,
        clean_repos,
        vulnerabilities,
        policy_findings,
        secret_watch_report,
    )
    summary_path = report_dir / "summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    machine_path = report_dir / "report.json"
    machine_path.write_text(
        json.dumps(
            {
                "schema": "atlas-supply-chain-report/v1",
                "repositories_scanned": len(repos),
                "clean_repositories": len(clean_repos),
                "vulnerabilities": [asdict(item) for item in vulnerabilities],
                "policy_findings": [asdict(item) for item in policy_findings],
                "secret_watch": secret_watch_report,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(summary)

    counts = Counter(item.severity for item in vulnerabilities)
    output_path = os.getenv("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(f"critical={counts.get('critical', 0)}\n")
            handle.write(f"high={counts.get('high', 0)}\n")
            handle.write(f"total={len(vulnerabilities)}\n")
            handle.write(f"policy_findings={len(policy_findings)}\n")
            handle.write(f"secret_findings={len(secret_watch_report['findings'])}\n")

    threshold = str(policy.get("fail_on", "critical")).lower()
    threshold_value = SEVERITY_ORDER.get(threshold, 4)
    if any(
        SEVERITY_ORDER.get(item.severity, 0) >= threshold_value
        for item in vulnerabilities
    ):
        return 1
    blocking_policy_errors = [
        item
        for item in policy_findings
        if item.severity == "error" and item.rule not in {"osv-query"}
    ]
    if blocking_policy_errors:
        return 1
    if secret_watch_report["blocking"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
