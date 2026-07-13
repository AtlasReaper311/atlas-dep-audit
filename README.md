<div align="center">
  <img src="https://raw.githubusercontent.com/AtlasReaper311/AtlasReaper311/main/atlas-icon-dark-256.png" width="88" alt="Atlas Systems"/>
</div>

# atlas-dep-audit

```
┌─────────────────────────────────────────────┐
│  ATLAS SYSTEMS // atlas-dep-audit           │
│  source SBOMs, known vulnerabilities,       │
│  action pins, and build provenance          │
└─────────────────────────────────────────────┘
```

[![Audit](https://github.com/AtlasReaper311/atlas-dep-audit/actions/workflows/audit.yml/badge.svg)](https://github.com/AtlasReaper311/atlas-dep-audit/actions)
![SBOM](https://img.shields.io/badge/sbom-cyclonedx_1.5-f5a623?style=flat-square&labelColor=0a0a0f)
![Vulnerabilities](https://img.shields.io/badge/database-osv-4ade80?style=flat-square&labelColor=0a0a0f)
![Cost](https://img.shields.io/badge/cost-%C2%A30-aaa9a0?style=flat-square&labelColor=0a0a0f)

A weekly supply-chain audit over every repository declared in `estate.manifest.json`. It clones each repository read-only, generates a CycloneDX source SBOM from npm and Python manifests, queries the Open Source Vulnerabilities database, records immutable build inputs, checks GitHub Action refs, inventories container base references, and publishes one consolidated report.

## Outputs

For every repository:

- `sbom/<repo>.cdx.json`: CycloneDX 1.5 source dependency inventory.
- `provenance/<repo>.provenance.json`: commit, manifest hashes, Action refs, container bases, workflow run, and SBOM digest.

For the full estate:

- `reports/summary.md`: human comparison grouped by severity and repository.
- `reports/report.json`: machine-readable findings for later dashboards or trend analysis.

The workflow uploads one 90-day evidence artifact and sends one `atlas-notify` event only when a finding exists. Repositories with no known vulnerability are counted but not listed individually.

## Vulnerability source

The audit uses [OSV](https://osv.dev), an open vulnerability schema and public query API maintained for package ecosystem vulnerability data. Queries use exact package URLs and installed versions from committed lockfiles. Fixed versions are extracted from OSV range events when publishers provide them.

## Scope boundary

This is a source SBOM. It inventories dependencies committed in `package-lock.json`, `requirements.txt`, and `pyproject.toml`. It also records Docker base image references and whether they are digest-pinned. It does not claim to inventory operating-system packages inside an image that was not built during the run.

## Credentials

The workflow reuses `GH_DIGEST_PAT`, the existing read-only cross-repository token. No new GitHub token is required. `NOTIFY_TOKEN` is optional and only delivers the consolidated report.

## Local use

```bash
python3 -m unittest discover -s tests -v
python3 audit.py   --manifest ../atlas-api-public/data/estate.manifest.json   --skip-osv
```

`--skip-osv` proves manifest parsing, repository cloning, SBOM generation, provenance, and policy checks without making vulnerability API requests.

## Failure policy

Critical known vulnerabilities fail the scheduled workflow. High, moderate, low, and unknown findings remain visible in the report and notification. Repository clone failures and OSV query failures also fail, because an incomplete audit must not appear green.

GitHub Actions refs that are not pinned to full commit SHAs are warnings during adoption. Container bases that are tag-pinned rather than digest-pinned are informational until image builds become part of this audit.

## How it fits into Atlas Systems

This repository consumes the canonical map from [`atlas-api-public`](https://github.com/AtlasReaper311/atlas-api-public), scans the repository estate listed there, reports through [`atlas-notify`](https://github.com/AtlasReaper311/atlas-notify), and complements the conformance and change-impact workflows in [`atlas-infra`](https://github.com/AtlasReaper311/atlas-infra).

A dependency list says what the code asked for. An SBOM plus provenance says what was present, where it came from, and which commit shipped the claim.

---

Part of [atlas-systems.uk](https://atlas-systems.uk)
