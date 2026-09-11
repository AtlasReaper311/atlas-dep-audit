# ADR-0016 minimal transitive lockfile remediation

The live ADR-0016 rollout on 2026-09-11 proved that the pinned npm resolver could remove unrelated lockfile metadata while resolving an otherwise valid transitive security update. The producer and consumer had matching digests, so this was not a trust-boundary failure. It was an output-minimality defect.

For transitive-only `npm-lock-security-remediation` candidates, the pinned npm toolchain remains the resolver of record. After regeneration, only the exact admitted transitive package nodes are copied back onto the exact audited `package-lock.json` preimage. Unrelated lockfile nodes remain byte-equivalent after canonical npm JSON serialization.

The final minimal lockfile, not the noisier raw npm output, is the artifact used for the target digest and OSV post-regeneration proof. Direct dependency and direct-ancestor graph remediation continue to use full deterministic regeneration because those operations can legitimately alter a wider dependency graph.

The overlay fails closed when the audited lockfile is not canonical npm JSON, uses a legacy top-level dependency map, cannot resolve the exact admitted node, or when npm rewrites `package.json` during a transitive-only operation.
