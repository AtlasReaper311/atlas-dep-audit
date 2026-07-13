#!/usr/bin/env python3
"""Check drift between the estate manifest, repository docs, and live Worker metadata.

The job is read-only. Findings are warnings and become report artifacts; only an
operational failure, such as an unreadable manifest, fails the workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import estate
import notify_client

META_TIMEOUT = 10
SUMMARY_LINE_CAP = 15

VERSION_PATTERNS = (
    re.compile(r"badge/version-(\d+\.\d+\.\d+)"),
    re.compile(r"\bversion:?\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r'"version":\s*"(\d+\.\d+\.\d+)"'),
)
BACKTICK_TOKEN = re.compile(r"`([^`\n]{1,120})`")
ROUTE_LIKE = re.compile(r"^/[A-Za-z0-9_\-./]*(\?[A-Za-z0-9_\-=&.]*)?$")
METHOD_PREFIX = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", re.IGNORECASE
)
DEPENDENCY_LINE_KEYWORDS = (
    "depend",
    "requires",
    "prerequisite",
    "built with",
    "built on",
    "stack",
)
NOT_A_PACKAGE = {
    "bash",
    "curl",
    "docker",
    "docker compose",
    "gh",
    "git",
    "make",
    "node",
    "npm",
    "npm ci",
    "npm install",
    "npx",
    "pip",
    "python",
    "python3",
    "systemd",
    "venv",
    "wrangler",
    "wsl",
}


@dataclass(frozen=True)
class Finding:
    subject: str
    rule: str
    message: str
    severity: str = "warning"


def readme_version(readme: str) -> str | None:
    for pattern in VERSION_PATTERNS:
        match = pattern.search(readme)
        if match:
            return match.group(1)
    return None


def fetch_meta(meta_url: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        status, body = estate.http_get(meta_url, timeout=META_TIMEOUT, retries=1)
    except estate.EstateError as error:
        return None, f"unreachable ({error.__class__.__name__})"
    if status != 200:
        return None, f"http {status}"
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return None, "not JSON"
    if not isinstance(document, dict):
        return None, "JSON root is not an object"
    if not isinstance(document.get("endpoints"), list) or "version" not in document:
        return None, "answers, but not in the /_meta contract shape"
    return document, None


def normalize_path(path: str) -> str:
    path = path.split("?", 1)[0]
    return path.rstrip("/") or "/"


def route_prefix(meta_url: str, meta_paths: set[str]) -> str:
    path = urlparse(meta_url).path
    if path.endswith("/_meta"):
        prefix = path[: -len("/_meta")]
        if prefix:
            return prefix
    segments: Counter[str] = Counter()
    for endpoint in meta_paths:
        parts = [segment for segment in endpoint.split("/") if segment]
        if parts:
            segments["/" + parts[0]] += 1
    return segments.most_common(1)[0][0] if segments else ""


def readme_route_paths(readme: str) -> set[str]:
    paths: set[str] = set()
    for token in BACKTICK_TOKEN.findall(readme):
        token = METHOD_PREFIX.sub("", token.strip())
        if ROUTE_LIKE.match(token):
            paths.add(normalize_path(token))
    return paths


def repository_parts(repo_url: str) -> tuple[str, str] | None:
    parts = [
        item
        for item in repo_url.replace("https://github.com/", "").split("/")
        if item
    ]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def check_worker(component: dict[str, Any], findings: list[Finding]) -> None:
    name = str(component.get("name") or "unknown")
    meta_url = str(component["meta_url"])
    meta, problem = fetch_meta(meta_url)
    if problem:
        findings.append(
            Finding(name, "meta-live", f"manifest meta_url {meta_url} is {problem}")
        )
        return
    assert meta is not None

    meta_paths = {
        normalize_path(str(endpoint.get("path", "")))
        for endpoint in meta.get("endpoints", [])
        if isinstance(endpoint, dict) and endpoint.get("path")
    }
    prefix = route_prefix(meta_url, meta_paths)

    parts = repository_parts(str(component.get("repo") or ""))
    if parts is None:
        findings.append(
            Finding(name, "repo-link", "manifest entry has no usable GitHub repository URL")
        )
        return

    readme = estate.fetch_readme(*parts)
    if readme is None:
        findings.append(Finding(name, "readme-fetch", "README is not fetchable"))
        return

    stated_version = readme_version(readme)
    live_version = str(meta.get("version") or "")
    if stated_version and stated_version != live_version:
        findings.append(
            Finding(
                name,
                "version-drift",
                f"README states version {stated_version}, live /_meta says {live_version}",
            )
        )

    documented = {
        path for path in readme_route_paths(readme) if prefix and path.startswith(prefix)
    }
    meta_route = normalize_path(urlparse(meta_url).path)
    for path in sorted(documented - meta_paths):
        if path == meta_route or path == "/_meta" or path.endswith("/_meta"):
            continue
        findings.append(
            Finding(name, "readme-endpoint", f"README documents {path}, absent from live /_meta")
        )

    for path in sorted(meta_paths):
        if path == "/_meta" or path.endswith("/_meta"):
            continue
        if path not in readme:
            findings.append(
                Finding(name, "live-endpoint", f"live endpoint {path} is absent from README")
            )


def pyproject_names(raw: bytes) -> set[str]:
    try:
        import tomllib

        document = tomllib.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        return set()
    names: set[str] = set()
    dependencies = (document.get("project") or {}).get("dependencies", [])
    for dependency in dependencies:
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", str(dependency))
        if match:
            names.add(match.group(1).lower())
    poetry = ((document.get("tool") or {}).get("poetry") or {}).get("dependencies", {})
    names.update(str(name).lower() for name in poetry if str(name).lower() != "python")
    return names


def package_names_from_manifests(
    owner: str, repo: str, branch: str, paths: list[str]
) -> set[str]:
    names: set[str] = set()
    for path in paths:
        basename = path.rsplit("/", 1)[-1]
        raw = estate.fetch_file(owner, repo, path, branch)
        if raw is None:
            continue
        if basename == "package.json":
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                continue
            names.update(document.get("dependencies", {}))
            names.update(document.get("devDependencies", {}))
        elif basename == "requirements.txt":
            for line in raw.decode("utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if match and not line.startswith("-"):
                    names.add(match.group(1).lower())
        elif basename == "pyproject.toml":
            names.update(pyproject_names(raw))
    return {str(name).lower() for name in names}


def check_dependency_claims(
    owner: str, repo: str, findings: list[Finding]
) -> bool:
    branch = estate.default_branch(owner, repo)
    if branch is None:
        return False
    try:
        paths, truncated = estate.repo_tree(owner, repo, branch)
    except estate.EstateError:
        findings.append(
            Finding(repo, "tree-fetch", "repository tree is not fetchable for dependency-claim checks")
        )
        return True
    if truncated:
        findings.append(
            Finding(repo, "tree-truncated", "GitHub returned a truncated repository tree")
        )

    manifest_paths = [
        path
        for path in paths
        if path.rsplit("/", 1)[-1]
        in {"package.json", "requirements.txt", "pyproject.toml"}
    ]
    if not manifest_paths:
        return True

    actual = package_names_from_manifests(owner, repo, branch, manifest_paths)
    readme = estate.fetch_readme(owner, repo)
    if not readme:
        return True

    for line in readme.splitlines():
        lowered = line.lower()
        if not any(keyword in lowered for keyword in DEPENDENCY_LINE_KEYWORDS):
            continue
        for token in BACKTICK_TOKEN.findall(line):
            token = token.strip()
            lowered_token = token.lower()
            if lowered_token in NOT_A_PACKAGE or "/" in token.lstrip("@"):
                continue
            if not re.match(r"^@?[a-z0-9][a-z0-9._-]{1,40}$", token, re.IGNORECASE):
                continue
            if lowered_token not in actual:
                findings.append(
                    Finding(
                        repo,
                        "dependency-claim",
                        f"README names `{token}` as a dependency, absent from dependency manifests",
                    )
                )
    return True


def write_reports(
    report_dir: Path,
    findings: list[Finding],
    workers_checked: int,
    repositories_checked: int,
    skipped: int,
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "atlas-doc-drift/v1",
        "workers_checked": workers_checked,
        "repositories_checked": repositories_checked,
        "skipped": skipped,
        "findings": [asdict(finding) for finding in findings],
        "finding_count": len(findings),
    }
    (report_dir / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# Atlas Systems documentation drift report",
        "",
        f"Workers checked: **{workers_checked}**",
        f"Non-Worker repositories checked: **{repositories_checked}**",
        f"Skipped repositories: **{skipped}**",
        f"Findings: **{len(findings)}**",
        "",
    ]
    if findings:
        lines.extend(
            [
                "| Subject | Rule | Finding |",
                "|---|---|---|",
            ]
        )
        for finding in findings:
            message = finding.message.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{finding.subject}` | `{finding.rule}` | {message} |")
    else:
        lines.append("The manifest, repository documentation, and live Worker contracts agree.")
    lines.append("")
    (report_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def set_output(name: str, value: str | int) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def run(report_dir: Path) -> int:
    manifest = estate.fetch_manifest()
    workers = estate.manifest_workers(manifest)
    repositories = estate.manifest_repositories(manifest)
    worker_repo_names = {
        str(worker.get("repo") or "").rstrip("/").rsplit("/", 1)[-1]
        for worker in workers
    }

    findings: list[Finding] = []
    seen_meta_urls: dict[str, str] = {}
    for component in workers:
        url = str(component["meta_url"])
        name = str(component.get("name") or "unknown")
        previous = seen_meta_urls.get(url)
        if previous:
            findings.append(
                Finding(
                    name,
                    "duplicate-meta-url",
                    f"meta_url {url} is also claimed by {previous}; only one Worker can own a route",
                )
            )
            continue
        seen_meta_urls[url] = name
        check_worker(component, findings)

    checked_claims = 0
    skipped = 0
    for owner, repo in repositories:
        if repo in worker_repo_names:
            continue
        if check_dependency_claims(owner, repo, findings):
            checked_claims += 1
        else:
            skipped += 1

    write_reports(report_dir, findings, len(workers), checked_claims, skipped)
    print((report_dir / "summary.md").read_text(encoding="utf-8"))
    set_output("findings", len(findings))

    totals = (
        f"{len(workers)} workers checked against live /_meta; "
        f"{checked_claims} non-Worker repositories checked"
        + (f"; {skipped} skipped" if skipped else "")
    )
    shown = [f"{finding.subject}: {finding.message}" for finding in findings[:SUMMARY_LINE_CAP]]
    if len(findings) > SUMMARY_LINE_CAP:
        shown.append(f"plus {len(findings) - SUMMARY_LINE_CAP} more in the workflow artifact")

    if findings:
        notify_client.post_summary(
            "warning",
            f"Doc drift: {len(findings)} mismatch{'es' if len(findings) != 1 else ''}",
            "\n".join(shown) + f"\n{totals}",
            fields={"run_log": estate.run_url(), "cadence": "weekly"},
        )
    return 0


def selftest() -> int:
    readme = (
        "![Version](https://img.shields.io/badge/version-1.2.3-aaa9a0)\n"
        "Use `GET /notify/recent` and `/notify/health`; also see `/sonify`.\n"
        "Requires `eslint` and `left-pad` to build.\n"
    )
    assert readme_version(readme) == "1.2.3"
    assert readme_version("no version here") is None
    assert readme_version('  "version": "2.0.0"') == "2.0.0"
    paths = readme_route_paths(readme)
    assert {"/notify/recent", "/notify/health", "/sonify"}.issubset(paths)
    assert route_prefix("https://api.atlas-systems.uk/notify/_meta", set()) == "/notify"
    assert (
        route_prefix(
            "https://api.atlas-systems.uk/_meta",
            {"/v1", "/v1/docs", "/v1/stats"},
        )
        == "/v1"
    )
    assert normalize_path("/quota/?x=1") == "/quota"
    print("doc_drift selftest: all assertions passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", default="doc-drift-reports")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        return run(Path(args.report_dir))
    except estate.EstateError as error:
        print(f"operational failure: {error}", file=sys.stderr)
        notify_client.post_summary(
            "failure",
            "Doc drift check could not run",
            str(error),
            fields={"run_log": estate.run_url()},
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
