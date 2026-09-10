# Gardener Finding handoff

Atlas Dep Audit remains the detection owner for the public Atlas Systems estate. It converts the completed weekly supply-chain report and the exact audited repository checkouts into one canonical, public-only Finding bundle for Atlas Gardener.

Merging this source does not publish a bundle. The publication job requires the repository variable `ATLAS_GARDENER_HANDOFF_ENABLED` to equal `true`. Publication, controller execution, provider configuration, and target writes remain separately authorised operations.

## Authority

Candidate production is bound to accepted Atlas Infra authority `11e7a727590aa5376e766416b1e6a83fb6fd98ef` and ADR-0015. Audit text remains evidence only. A candidate is structured bounded evidence that Gardener must independently validate and regenerate against the exact repository snapshot.

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
- optional structured `remediation.candidate` data only when ADR-0015 eligibility is proven;
- the canonical bundle digest.

The exporter requires all 20 verified public coverage repositories to have complete local audit checkouts at the exact `origin/main` commit. A missing or stale checkout blocks the handoff. It never discovers account repositories and never copies a private repository identity into the bundle.

## Finding production

The deterministic housekeeping detectors continue to produce `macos-metadata-ignore` and `python-cache-ignore` Findings. Mutable GitHub Actions continue to become review-only `missing-action-pin` Findings. Unsupported policy rules remain visible with `remediation.eligible=false`.

Dependency vulnerability Findings can now become structured `dependency-update` candidates only when the exact audited checkout proves all ADR-0015 conditions. The producer requires a direct dependency, strict three-part current and target versions, a strictly newer same-major target, at least one published fixed vulnerability addressed by that target, and one of these source forms:

- npm: a uniquely declared direct dependency in `package.json` with a matching `package-lock.json` entry;
- Python: a unique exact `==` pin in `requirements.txt`, including PEP 508 extras such as `uvicorn[standard]==0.52.4`.

The initial npm declaration boundary accepts only exact, caret, or tilde specifications that name the exact audited current version. Transitive-only npm vulnerabilities, major-only fixes, unresolved fixed versions, unsupported Python packaging formats, ambiguous declarations, prerelease/non-three-part versions, and unsupported npm lockfile forms remain observations.

For multiple vulnerability records affecting the same exact direct dependency version, the candidate selects the highest published same-major fixed version and records the vulnerability identifiers addressed at or below that target. Candidate locations include the exact manifest line so multiple direct dependency candidates in one file retain distinct canonical fingerprints.

Container policy Findings can become `container-digest-pin` candidates only for simple external Docker Hub `FROM <image>:<tag>` instructions in Dockerfiles. The producer resolves the public registry's canonical `Docker-Content-Digest` and records the resulting immutable `sha256` value. Named build stages are not exported as container findings. Already digest-pinned images, unsupported registries, implicit tags, malformed instructions, ambiguous references, and failed digest resolution remain observations or are omitted where ADR-0015 says they are not findings.

`remediation.eligible=false` means the Finding is evidence, not failed remediation. Gardener records it as a non-actionable observation and must not select a fixer or attempt a target write. A refusal is reserved for invalid controller input or an eligible Finding that cannot be processed safely.

Findings and candidates are data, never commands.

## Determinism and safety

The base exporter still constructs the authority-bound bundle and exact repository snapshots. `gardener_candidates.py` then replaces only the generic dependency/container projection with structured candidates derived from the same report and exact local snapshots. Every enriched Finding is validated against the accepted canonical Finding schema before the bundle digest is recomputed.

Docker Hub resolution uses public registry metadata only. It does not use Gardener credentials, provider credentials, target-repository write credentials, or secret values. Resolution failure produces no executable candidate.

The source report remains preserved and its digest remains bound into the bundle, so a reduced or aggregated non-actionable projection does not replace the underlying audit evidence.

## Attestation and publication

After a successful audit and successful candidate export, the publication job can, when separately enabled:

1. download the exact audit evidence from the same workflow run;
2. recheck schema, producer, run, commit, and public-only fields;
3. create a GitHub artifact attestation for the exact bundle bytes;
4. create the dedicated `gardener-findings` branch once if it does not exist;
5. update `gardener-findings.json` through one linear contents commit without force-pushing.

Atlas Gardener fetches that file by branch, verifies the attestation against `AtlasReaper311/atlas-dep-audit`, then revalidates every contract, policy digest, repository snapshot, and bundle digest before processing it.

## Failure behaviour

The handoff fails closed when the audit report or canonical authority is invalid, a covered checkout is missing or stale, a generated candidate violates the accepted Finding contract, source identity is malformed, or the exact coverage snapshots cannot be produced. Unsupported remediation conditions remain observations rather than controller failures.

The existing consolidated supply-chain notification remains the outcome for audit failures and critical vulnerabilities. A failed audit job cannot publish a Gardener bundle.

## Rollback

Set `ATLAS_GARDENER_HANDOFF_ENABLED=false` or remove the variable to prevent future publication without deleting historical evidence or changing credentials. The weekly audit continues to produce its normal reports, SBOMs, provenance, and notification.

Reverting the candidate implementation restores observation-only dependency/container projection. Existing `gardener-findings` branch history may remain as public evidence; Atlas Gardener rejects stale bundles after the configured 36-hour expiry.
