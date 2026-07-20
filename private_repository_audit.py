#!/usr/bin/env python3
"""Run Atlas supply-chain assurance against one authenticated repository checkout.

The script is intentionally source-local. It never discovers or names private
repositories centrally; the caller supplies its own GitHub repository identity
and checkout path, and all generated evidence stays in that caller's workflow.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path

import audit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=Path("policy.json"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    parser.add_argument("--sbom-dir", type=Path, default=Path("sbom"))
    parser.add_argument("--provenance-dir", type=Path, default=Path("provenance"))
    parser.add_argument("--skip-osv", action="store_true")
    args = parser.parse_args()

    repository = args.repository.strip()
    if not repository.startswith("AtlasReaper311/") or repository.count("/") != 1:
        raise SystemExit("repository must be an AtlasReaper311 owner/name identity")

    repo_root = args.repository_root.resolve()
    if not (repo_root / ".git").exists():
        raise SystemExit("repository-root must be a checked-out Git repository")

    policy = audit.load_json(str(args.policy))
    for directory in (args.report_dir, args.sbom_dir, args.provenance_dir):
        directory.mkdir(parents=True, exist_ok=True)

    commit = audit.run(["git", "rev-parse", "HEAD"], cwd=repo_root)
    components, component_findings, manifests = audit.discover_components(
        repo_root,
        repository,
    )
    actions, action_findings = audit.parse_actions(repo_root, repository)
    container_bases, container_findings = audit.parse_container_bases(
        repo_root,
        repository,
    )
    policy_findings = [
        *component_findings,
        *action_findings,
        *container_findings,
    ]

    safe_name = repository.replace("/", "__")
    sbom_path = args.sbom_dir / f"{safe_name}.cdx.json"
    sbom_path.write_text(
        json.dumps(
            audit.cyclonedx(repository, commit, components),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    provenance_path = args.provenance_dir / f"{safe_name}.provenance.json"
    audit.write_provenance(
        provenance_path,
        repository,
        commit,
        manifests,
        repo_root,
        actions,
        container_bases,
        sbom_path,
        None,
    )

    vulnerabilities = []
    if not args.skip_osv:
        results = audit.osv_query(components)
        vulnerabilities = audit.vulnerabilities_for(repository, components, results)

    clean_repositories = [] if vulnerabilities else [repository]
    summary = audit.render_summary(
        [repository],
        clean_repositories,
        vulnerabilities,
        policy_findings,
    )
    (args.report_dir / "summary.md").write_text(summary, encoding="utf-8")
    (args.report_dir / "report.json").write_text(
        json.dumps(
            {
                "schema": "atlas-private-repository-supply-chain-report/v1",
                "repositories_scanned": 1,
                "clean_repositories": len(clean_repositories),
                "vulnerabilities": [asdict(item) for item in vulnerabilities],
                "policy_findings": [asdict(item) for item in policy_findings],
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

    threshold = str(policy.get("fail_on", "critical")).lower()
    threshold_value = audit.SEVERITY_ORDER.get(threshold, 4)
    if any(
        audit.SEVERITY_ORDER.get(item.severity, 0) >= threshold_value
        for item in vulnerabilities
    ):
        return 1

    blocking_policy_errors = [
        item
        for item in policy_findings
        if item.severity == "error" and item.rule not in {"osv-query"}
    ]
    return 1 if blocking_policy_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
