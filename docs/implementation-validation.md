# Candidate implementation validation

Repository-native validation for the ADR-0016 producer change is the existing pull-request CI bound to accepted Atlas Infra authority `eb634e5b19725ecc87902543058a4dd2a2e089c7`.

The branch must pass immutable-authority validation, Gardener schedule validation, self-tooling pin validation, Python compilation, the full offline unit-test suite, documentation drift self-test, canonical contract validation, and `git diff --check` before merge review.

ADR-0016 npm graph candidates additionally require lockfile-v3 graph analysis, exact direct/transitive preimages, same-major targets, exact parent constraints, npm `10.9.3`, lifecycle scripts disabled, producer target digests, and a post-regeneration OSV absence proof. Tests stub package-manager and OSV execution; source CI does not constitute a live audit or target remediation.

No successful source check is deployment or live-controller evidence.
