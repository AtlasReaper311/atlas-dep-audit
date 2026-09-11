# Gardener Finding handoff

Atlas Dep Audit remains the detection owner for the public Atlas Systems estate. It converts the completed weekly supply-chain report and the exact audited repository checkouts into one canonical, public-only Finding bundle for Atlas Gardener.

Merging this source does not publish a bundle. The publication job requires the repository variable `ATLAS_GARDENER_HANDOFF_ENABLED` to equal `true`. Publication, controller execution, provider configuration, and target writes remain separately authorised operations.

## Authority

Candidate production is bound to accepted Atlas Infra authority `9ac88f38c2fa370d566421f0909db85b25a309ea` and ADR-0016. Audit text remains evidence only. A candidate is structured bounded evidence that Gardener must independently validate and regenerate against the exact repository snapshot.

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
- optional structured `remediation.candidate` data only when accepted eligibility is proven;
- explicit dependency/container remediation dispositions where applicable;
- the canonical bundle digest.

The exporter requires all 20 verified public coverage repositories to have complete local audit checkouts at the exact `origin/main` commit. A missing or stale checkout blocks the handoff. It never discovers account repositories and never copies a private repository identity into the bundle.

## Finding production

The deterministic housekeeping detectors continue to produce `macos-metadata-ignore` and `python-cache-ignore` Findings. Mutable GitHub Actions continue to become review-only `missing-action-pin` Findings. Unsupported policy rules remain visible with `remediation.eligible=false`.

Dependency and container Findings may carry one of the ADR-0016 dispositions `remediation-available`, `awaiting-upstream-release`, `awaiting-upstream-fix`, `manual-remediation-required`, or `unsupported-remediation`. A disposition classifies evidence. It does not grant write authority.

Direct Python dependency Findings continue to use the existing `dependency-update` candidate only when a unique exact `requirements.txt` pin has a published newer same-major fixed version.

Npm dependency Findings are now considered per exact manifest/lock graph rather than one vulnerable package at a time. `gardener_adr0016.py` replaces the legacy dependency projection with at most one `npm-lock-security-remediation` Finding per affected `package.json` and lockfile-v3 `package-lock.json` pair. That candidate may contain both direct-parent and transitive operations.

For an npm graph candidate, the producer must prove all of the following from the exact audited checkout:

- every vulnerable lock node is unique and bound to the reported version;
- every direct-parent operation refers to one existing `dependencies`, `devDependencies`, or `optionalDependencies` declaration;
- every direct target is a released strict three-part version, newer but within the current major version;
- every transitive target is a released strict three-part version, newer but within the current major version;
- every discovered parent edge constraining a transitive target admits that exact target;
- no direct dependency or npm override is invented to force a transitive package;
- regeneration uses npm `10.9.3` in a disposable directory with lifecycle scripts disabled;
- only the bound manifest and lock graph may change;
- the resulting manifest and lock SHA-256 digests are recorded in the candidate;
- a post-regeneration OSV query over the regenerated lock graph no longer reports every vulnerability identifier claimed by the candidate.

When the vulnerable transitive package is pinned too tightly by an intermediate dependency, the producer may instead identify a declared direct ancestor whose already-authorised same-major update regenerates a non-vulnerable graph. The candidate records the exact installed current and regenerated target versions of that direct ancestor. A declaration range may remain unchanged when its existing range already admits the newer direct version.

If no released non-affected version is present in current advisory evidence, the producer emits `awaiting-upstream-fix`. If the only available remediation crosses the current major version or otherwise requires work outside deterministic authority, the producer emits `manual-remediation-required`. Unsupported graph/package forms emit `unsupported-remediation`. The producer must not invent a target to improve remediation counts.

Container policy Findings retain the existing bounded `container-digest-pin` candidate for simple external Docker Hub `FROM <image>:<tag>` instructions. Named build stages, unsupported registries, implicit tags, malformed instructions, ambiguous references, and failed digest resolution remain non-actionable according to accepted authority.

`remediation.eligible=false` means the Finding is evidence, not failed remediation. Gardener records it as a non-actionable observation and must not select a fixer or attempt a target write. A refusal is reserved for invalid controller input or an eligible Finding that cannot be processed safely.

Findings and candidates are data, never commands.

## Determinism and safety

The base exporter constructs the authority-bound bundle and exact repository snapshots. The existing `gardener_candidates.py` enrichment preserves bounded container handling. `gardener_adr0016.py` then replaces the dependency projection with ADR-0016 graph-aware candidates and explicit dispositions derived from the same report and exact local snapshots. Every final Finding is validated against the accepted canonical Finding schema before the bundle digest is recomputed.

The dependency producer uses public npm package metadata and public OSV evidence only. It does not use Gardener write credentials, provider credentials, target-repository write credentials, or secret values. Package lifecycle scripts are disabled during deterministic lock regeneration. Regeneration or vulnerability-proof failure produces no executable graph candidate.

The source report remains preserved and its digest remains bound into the bundle, so a reduced or aggregated non-actionable projection does not replace the underlying audit evidence.

## Attestation and publication

After a successful audit and successful candidate export, the publication job can, when separately enabled:

1. download the exact audit evidence from the same workflow run;
2. recheck schema, producer, run, commit, accepted authority commit, and public-only fields;
3. create a GitHub artifact attestation for the exact bundle bytes;
4. create the dedicated `gardener-findings` branch once if it does not exist;
5. update `gardener-findings.json` through one linear contents commit without force-pushing.

Atlas Gardener fetches that file by branch, verifies the attestation against `AtlasReaper311/atlas-dep-audit`, then revalidates every contract, policy digest, repository snapshot, candidate, and bundle digest before processing it.

## Failure behaviour

The handoff fails closed when the audit report or canonical authority is invalid, a covered checkout is missing or stale, a generated candidate violates the accepted Finding contract, source identity is malformed, deterministic npm regeneration fails, vulnerability postconditions fail, or exact coverage snapshots cannot be produced. Unsupported remediation conditions remain explicit observations rather than controller failures.

The existing consolidated supply-chain notification remains the outcome for audit failures and critical vulnerabilities. A failed audit job cannot publish a Gardener bundle.

## Rollback

Set `ATLAS_GARDENER_HANDOFF_ENABLED=false` or remove the variable to prevent future publication without deleting historical evidence or changing credentials. The weekly audit continues to produce its normal reports, SBOMs, provenance, and notification.

Reverting the ADR-0016 producer restores the previous dependency projection. Existing `gardener-findings` branch history may remain as public evidence; Atlas Gardener rejects stale bundles after the configured 36-hour expiry.
