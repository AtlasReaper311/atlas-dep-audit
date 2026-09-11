#!/usr/bin/env python3
"""Build ADR-0016 Gardener handoff bundles from public audit evidence."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import gardener_candidates as legacy
import gardener_findings as base
import gardener_graph_candidates as graph


def enhance_bundle(
    bundle: dict,
    *,
    report: dict,
    work_dir: Path,
    infra_root: Path,
    detected_at: str,
    run_url: str,
) -> dict:
    bundle = legacy.enhance_bundle(
        bundle,
        report=report,
        work_dir=work_dir,
        infra_root=infra_root,
        detected_at=detected_at,
        run_url=run_url,
    )
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
        item for item in bundle["findings"]
        if item.get("rule_id") != "dependency-vulnerability"
    ]
    generated = graph.dependency_findings(
        report,
        repositories=repositories,
        covered=covered,
        detected_at=detected_at,
        run_url=run_url,
        rules=rules,
    )
    by_fingerprint: dict[str, dict] = {}
    for finding in retained + generated:
        errors = contracts.validate_instance(finding, schema)
        if errors:
            raise base.FindingExportError(
                f"canonical ADR-0016 Finding failed validation: {errors[0]}"
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
    except (base.FindingExportError, graph.GraphCandidateError, legacy.CandidateError, OSError, ValueError) as error:
        print(f"Gardener ADR-0016 export failed: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    actionable = sum(1 for item in bundle["findings"] if item["remediation"]["eligible"])
    dispositions: dict[str, int] = {}
    for item in bundle["findings"]:
        value = item["remediation"].get("disposition")
        if value:
            dispositions[value] = dispositions.get(value, 0) + 1
    print(json.dumps({
        "schema_version": "atlas-dep-audit/gardener-export-result/v1",
        "bundle_digest": bundle["bundle_digest"],
        "findings": len(bundle["findings"]),
        "actionable": actionable,
        "dispositions": dispositions,
        "repository_snapshots": len(bundle["repository_snapshots"]),
        "public_only": True,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
