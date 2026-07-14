# Control-plane contract assurance

Owner: `AtlasReaper311/atlas-dep-audit`

Schema authority: `AtlasReaper311/atlas-infra`

## Boundary

The weekly dependency audit already clones every manifest-declared repository.
When the checkout is exactly `AtlasReaper311/atlas-infra`,
`contract_validation.py` requires `contracts/v1` and invokes its canonical
validator. A missing contract directory fails closed after Phase 1. No other
repository script is executed.

The subprocess receives only basic locale, temporary-directory, and executable
path variables. GitHub, notification, Cloudflare, and other credential-bearing
environment variables are not forwarded. The invocation is read-only, has a
60-second timeout, and captures a bounded error message.

## Evidence

Successful validation adds `control_plane_contract_validation` to the
`atlas-infra` provenance record. The entry contains schema and fixture counts,
status, and idempotency only. A failure becomes a blocking
`control-plane-contract-validation` policy finding; a partial or unknown report
never appears successful.

## Local validation

From `atlas-dep-audit`, with the sibling contract branch checked out:

```bash
python3 -m py_compile audit.py contract_validation.py
python3 -m unittest discover -s tests -v
python3 contract_validation.py --contracts-root ../atlas-infra
```

These commands use no network and install no dependency.

## Migration and rollback

Merge `atlas-infra` first so the dependency-audit branch sees the canonical
validator on `atlas-infra/main`. Then merge the adapter. If assurance fails,
keep the audit blocked, run the contract-owner runbook, and correct or revert
the contract change. Roll back by reverting the focused adapter change first,
then reverting the owning contract change; no runtime or deployment is
involved.
