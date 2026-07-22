# Gardener Finding handoff

Atlas Dep Audit remains the detection owner for the public Atlas Systems estate. It converts the completed weekly supply-chain report and the exact audited repository checkouts into one canonical, public-only Finding bundle for Atlas Gardener.

Merging this source does not publish a bundle. The publication job requires the repository variable `ATLAS_GARDENER_HANDOFF_ENABLED` to equal `true`. The variable must remain absent or false until the source PRs are merged, the controller is configured in disabled mode, and the staged rollout is separately approved.

## Bundle contents

`reports/gardener-findings.json` records:

- the canonical `atlas-control-plane/gardener-finding-bundle/v1` schema;
- the exact Atlas Dep Audit workflow, run ID, run attempt, and source commit;
- the exact reviewed Atlas Infra authority commit and policy digest;
- generated and expiry timestamps;
- a public-only declaration;
- the source report digest;
- one exact `main` base SHA for every verified public Gardener repository;
- sorted, deduplicated canonical Findings;
- the canonical bundle digest.

The exporter requires all 20 verified public coverage repositories to have complete local audit checkouts at the exact `origin/main` commit. A missing or stale checkout blocks the handoff. It never discovers account repositories and never copies a private repository identity into the bundle.

## Finding production

The initial deterministic housekeeping detectors produce:

- `macos-metadata-ignore` when `.DS_Store` is not ignored or a tracked `.DS_Store` exists;
- `python-cache-ignore` when a Python repository lacks `__pycache__/` or `*.py[cod]`, or tracked Python cache artifacts exist.

The Finding remains remediation-eligible because a deterministic fixer exists. Atlas Gardener independently inspects the generated patch. A pure `.gitignore` addition can enter the initial low-risk gate. Tracked binary deletion makes the resulting plan review-only.

Existing audit results are also projected:

- mutable GitHub Actions become `missing-action-pin`, which is review-only;
- vulnerabilities become `dependency-vulnerability`, which is not automatically remediable;
- unsupported policy rules remain visible with `remediation.eligible=false`;
- unknown or malformed rule and path values are normalized to bounded generic values rather than becoming executable input.

Findings are data, never commands.

## Attestation and publication

After a successful audit and successful Finding export, the disabled publication job can:

1. download the exact audit artifact from the same workflow run;
2. recheck schema, producer, run, commit, and public-only fields;
3. create a GitHub artifact attestation for the exact bundle bytes;
4. create the dedicated `gardener-findings` branch once if it does not exist;
5. update `gardener-findings.json` through one linear contents commit without force-pushing.

The publication job has only `contents: write`, `id-token: write`, and `attestations: write`. Those are repository-scoped workflow permissions. They do not change the Atlas Gardener GitHub App permission contract.

Atlas Gardener fetches the file by branch, verifies the attestation against `AtlasReaper311/atlas-dep-audit`, then revalidates every contract and digest before processing it.

## Failure behaviour

The handoff fails closed when:

- the audit report is unavailable or has an unknown schema;
- Atlas Infra authority or coverage is malformed;
- any covered checkout is absent or does not equal `origin/main`;
- a Finding fails the canonical schema;
- the source run or commit identity is invalid;
- the exporter cannot produce all 20 repository snapshots;
- bundle publication is not explicitly enabled.

The existing consolidated supply-chain notification remains the outcome for audit failures and critical vulnerabilities. A failed audit job cannot publish a Gardener bundle.

## Rollback

Set `ATLAS_GARDENER_HANDOFF_ENABLED=false` or remove the variable. This immediately prevents future publication without deleting historical evidence or changing credentials. The existing weekly audit continues to produce its normal reports, SBOMs, provenance, and notification.

Closing or reverting this source PR removes the exporter and publication job. Existing `gardener-findings` branch history may remain as public evidence; Atlas Gardener rejects stale bundles after the configured 36-hour expiry.
