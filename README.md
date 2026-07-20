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
- one consolidated public-estate report.

The public audit never discovers private repositories through an account-wide token. Its scan manifest is built from the generated public repository inventory.

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

Private repository governance is validated separately through the reusable workflow owned by `atlas-infra`. Native repository CI, Dependabot, and GitHub security controls remain source-owned.

## Outputs

For each scanned repository:

- `sbom/<repo>.cdx.json`: CycloneDX 1.5 source dependency inventory.
- `provenance/<repo>.provenance.json`: commit, manifest hashes, Action refs, container bases, workflow run, and SBOM digest.

For each workflow scope:

- `reports/summary.md`: human-readable findings.
- `reports/report.json`: machine-readable findings.

Public workflow artifacts contain public repositories only. Private workflow artifacts remain attached to the authenticated private caller.

## Vulnerability source

The audit uses [OSV](https://osv.dev), an open vulnerability schema and public query API. Queries use exact package URLs and installed versions from committed dependency manifests and lockfiles. Fixed versions are extracted from OSV ranges when publishers provide them.

Critical vulnerabilities fail the audit by default. Lower severities remain visible unless policy raises the threshold. Operational failures also fail rather than producing an incomplete green report.

## Scope boundary

This is a source SBOM. It inventories dependencies committed in supported npm and Python dependency files, Action refs, and container base references. It does not claim to inventory operating-system packages inside an image that was not built during the run.

Repository visibility controls where evidence is retained, not whether the repository receives assurance.

## Local use

Public multi-repository audit:

```bash
python3 audit.py \
  --manifest public-scan-manifest.json \
  --policy policy.json \
  --skip-osv
```

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
