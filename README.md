<div align="center">
  <img src="https://raw.githubusercontent.com/AtlasReaper311/AtlasReaper311/main/atlas-icon-dark-256.png" width="88" alt="Atlas Systems"/>
</div>

# atlas-dep-audit

```
┌─────────────────────────────────────────────┐
│  ATLAS SYSTEMS // atlas-dep-audit           │
│  source SBOMs, vulnerabilities, provenance  │
└─────────────────────────────────────────────┘
```

[![Audit](https://github.com/AtlasReaper311/atlas-dep-audit/actions/workflows/audit.yml/badge.svg)](https://github.com/AtlasReaper311/atlas-dep-audit/actions)
![SBOM](https://img.shields.io/badge/sbom-cyclonedx_1.5-f5a623?style=flat-square&labelColor=0a0a0f)
![Vulnerabilities](https://img.shields.io/badge/database-osv-4ade80?style=flat-square&labelColor=0a0a0f)
![Cost](https://img.shields.io/badge/cost-%C2%A30-aaa9a0?style=flat-square&labelColor=0a0a0f)

Supply-chain assurance for Atlas Systems source repositories. Public repositories are scanned by the scheduled public workflow; private repositories call the same audit capability from their own authenticated repository so their evidence remains private while the checks stay consistent.

## Public audit

The weekly public workflow reads `atlas-api-public/data/public-repositories.json`, clones only repositories explicitly reported as public, and produces:

- CycloneDX 1.5 source SBOMs.
- OSV vulnerability findings.
- immutable source and build provenance.
- GitHub Action pin checks.
- container base reference checks.
- public secret-policy assurance.
- bounded ADR-0018 vulnerability risk evaluation.
- one consolidated public-estate report.

The public audit never discovers private repositories through an account-wide token. Its scan manifest is built from the generated public repository inventory.

Raw vulnerability detection and blocking policy are separate. `audit.py` produces the complete vulnerability evidence first. `vulnerability_risk_gate.py` then validates a separately pinned `atlas-infra` ADR-0018 authority, verifies exact repository/package/version/advisory/severity matches and exact source-evidence Git blobs, and calculates the final public-workflow blocking result. An accepted risk remains in every vulnerability report at its original severity.

The Gardener Finding handoff remains bound to its existing accepted ADR-0016 authority revision. The scheduled workflow uses an independent immutable ADR-0018 authority checkout for risk policy so a risk-policy update cannot silently change Gardener controller authority.

## Private repository assurance

Private Atlas Systems repositories use the reusable workflow:

```yaml
jobs:
  supply-chain:
    uses: AtlasReaper311/atlas-dep-audit/.github/workflows/private-repository-audit.yml@<immutable-commit>
```

The called workflow runs inside the private caller repository. It checks out that caller, checks out a pinned revision of the audit tooling, then runs `private_repository_audit.py` against the local authenticated checkout.

Private evidence is uploaded as an artifact of the private caller workflow, not the public audit repository. The public repository therefore contains the audit mechanism without containing a central inventory, report, or artifact naming private repositories.

The source-local private audit includes:

- CycloneDX source SBOM generation.
- OSV vulnerability lookup.
- Action pin policy checks.
- container base reference checks.
- build provenance.

Private repository governance is validated separately through the reusable workflow owned by `atlas-infra`. Native repository CI, Dependabot, and GitHub security controls remain source-owned. ADR-0018 public risk evaluation is not implicitly applied to private caller workflows.

## Outputs

For each scanned repository:

- `sbom/<repo>.cdx.json`: CycloneDX 1.5 source dependency inventory.
- `provenance/<repo>.provenance.json`: commit, manifest hashes, Action refs, container bases, workflow run, and SBOM digest.

For each workflow scope:

- `reports/summary.md`: human-readable findings.
- `reports/report.json`: machine-readable findings.

For the scheduled public workflow, `reports/report.json` also contains `vulnerability_risk`, which records the immutable risk authority commit, canonical risk-policy digest, original severity totals, accepted-risk totals, undispositioned totals, threshold-blocking totals, accepted findings, rejected disposition matches, and the final blocking decision. The original `vulnerabilities` collection is not rewritten or filtered.

Public workflow artifacts contain public repositories only. Private workflow artifacts remain attached to the authenticated private caller.

## Vulnerability source

The audit uses [OSV](https://osv.dev), an open vulnerability schema and public query API. Queries use exact package URLs and installed versions from committed dependency manifests and lockfiles. Fixed versions are extracted from OSV ranges when publishers provide them.

Critical vulnerabilities fail the audit by default. Lower severities remain visible unless policy raises the threshold. Operational failures also fail rather than producing an incomplete green report.

Under accepted Atlas Infra ADR-0018 authority, the scheduled public workflow may exclude one exact, current, source-bound `accepted-risk` finding from the blocking threshold. The finding remains critical and visible. A new advisory, dependency change, severity change, source-evidence drift, expired policy, malformed policy, unavailable evidence, or newly published fixed version fails closed and keeps the finding blocking.

Risk disposition is independent from ADR-0016 remediation disposition. `awaiting-upstream-fix` still means no released remediation target exists; `accepted-risk` only describes the temporary blocking decision.

## Scope boundary

This is a source SBOM. It inventories dependencies committed in supported npm and Python dependency files, Action refs, and container base references. It does not claim to inventory operating-system packages inside an image that was not built during the run.

Repository visibility controls where evidence is retained, not whether the repository receives assurance.

Source-evidence binding proves only that the reviewed repository source files have not changed. It does not prove deployment, provider, network, host, authentication, container, or live runtime state.

## Local use

Public multi-repository audit:

```bash
python3 audit.py \
  --manifest public-scan-manifest.json \
  --policy policy.json \
  --skip-osv
```

To reproduce the scheduled public risk decision after a real report and SBOM set have been generated, check out the exact accepted ADR-0018 `atlas-infra` authority and run:

```bash
python3 vulnerability_risk_gate.py \
  --report reports/report.json \
  --summary reports/summary.md \
  --audit-policy policy.json \
  --work-dir work \
  --sbom-dir sbom \
  --infra-root ../atlas-infra \
  --authority-sha <accepted-ADR-0018-authority-SHA>
```

The authority argument must be the exact commit checked out at `--infra-root`. The gate refuses branch names, short SHAs, authority drift, invalid or expired policy, and incomplete source evidence.

Single checked-out repository audit:

```bash
python3 private_repository_audit.py \
  --repository AtlasReaper311/example-repository \
  --repository-root ../example-repository \
  --policy policy.json \
  --skip-osv
```

The example identity is illustrative; private repository identities are not committed to this public repository.

## Documentation drift

The documentation drift workflow compares the declared public manifest, public repository documentation, and approved public Worker metadata. It detects dead metadata URLs, duplicate route ownership, version disagreement, undocumented public endpoints, stale documented endpoints, and dependency claims that no longer match public repository manifests.

Private repositories do not participate in the public documentation-drift report because they are intentionally absent from public architecture documentation.

## Control-plane contract assurance

The public audit validates the shared v1 contracts when it scans the allowlisted public `atlas-infra` checkout. The canonical validator runs without credential-bearing environment variables, with bounded execution time and no dependency installation.

Private governance declarations are validated in the repository that owns them, not copied into this audit repository.

## Secret watch

Public secret assurance consumes names-only public policy from `atlas-infra`. It never reports secret values or value-derived hashes. Optional GitHub metadata comparison uses a separate read-only token and distinguishes unavailable evidence from healthy evidence.

Private repositories retain their source-owned GitHub security controls and private workflow evidence rather than publishing secret-policy identities through this repository.

## How it fits into Atlas Systems

`atlas-dep-audit` provides one audit implementation with two evidence locations: public estate assurance in the public audit repository, and private source-local assurance inside authenticated caller repositories. Public architecture remains bounded while private repositories keep equivalent dependency and provenance checks.

The transferable principle is to move the evidence boundary with the data: shared tooling can be public without forcing every audited target to become public inventory.

---

Part of [atlas-systems.uk](https://atlas-systems.uk)
