# Gardener candidate safety invariants

Candidate production is evidence generation, not target mutation.

- Every dependency candidate is derived from an exact audited checkout and current full OSV records, not shallow batch metadata.
- Direct Python candidates require one exact `requirements.txt` pin, a strict newer same-major target, and at least one published vulnerability fix addressed by that target.
- npm graph candidates are limited to one matching `package.json` plus lockfile-v3 `package-lock.json` pair.
- A direct npm graph operation must bind one existing declaration and a strict newer same-major installed target. An existing manifest range may remain unchanged only when deterministic regeneration proves the newer direct version and clears the claimed vulnerability set.
- A transitive npm graph operation must bind one exact vulnerable lock node, a strict newer same-major target, and every discovered parent package path/specifier. Every parent constraint must accept the exact target.
- The producer never invents a direct dependency or npm `overrides` entry merely to force a transitive version.
- Producer npm regeneration is pinned to npm `10.9.3`, runs in a disposable directory, disables lifecycle scripts, and may change only the bound manifest/lock graph.
- The producer records exact target manifest and lock SHA-256 digests and emits `remediation-available` only after a post-regeneration OSV query proves all candidate vulnerability identifiers absent.
- No released non-affected target becomes `awaiting-upstream-fix`; major-only or otherwise non-deterministic remediations become `manual-remediation-required`; unsupported source/graph forms become `unsupported-remediation`.
- Container candidates retain the accepted simple Docker Hub tag boundary and bind the resolved immutable `sha256` digest into the Finding. Named build stages remain outside the automatic container rewrite boundary.
- All generated Findings are validated against accepted Atlas Infra authority `9ac88f38c2fa370d566421f0909db85b25a309ea` before the bundle digest is recomputed.
- No candidate field is treated as a shell command by this producer.
