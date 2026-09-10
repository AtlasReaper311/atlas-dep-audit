# Gardener candidate safety invariants

Candidate production is evidence generation, not target mutation.

- Dependency candidates require an exact audited checkout, one supported direct declaration, a strict newer same-major target, and at least one published vulnerability fix addressed by that target.
- npm candidates are limited to `package.json` plus its matching `package-lock.json`; unsupported or transitive cases remain observations.
- Python candidates are limited to exact `==` pins in `requirements.txt`; other Python packaging formats remain observations.
- Container candidates are limited to simple Docker Hub tag references in Dockerfiles and bind the resolved immutable `sha256` digest into the Finding.
- Named build stages are not container findings under ADR-0015.
- All generated Findings are validated against the accepted Atlas Infra contract before the bundle digest is recomputed.
- No candidate field is executed as a command by this producer.
