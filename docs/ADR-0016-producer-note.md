# ADR-0016 producer implementation note

This branch implements the producer side of accepted Atlas Infra authority `eb634e5b19725ecc87902543058a4dd2a2e089c7`.

Atlas Dep Audit remains detection and public Finding-bundle producer. It may emit the ADR-0016 `npm-lock-security-remediation` candidate only when the exact audited lockfile-v3 graph can be regenerated with npm `10.9.3`, lifecycle scripts disabled, the accepted direct/transitive operation boundary, exact target manifest/lock digests, and a post-regeneration OSV proof that the candidate vulnerability identifiers are absent.

Dependency Findings that cannot satisfy that proof remain non-actionable with an explicit accepted disposition. The producer does not invent dependency declarations, npm overrides, unavailable releases, or major-version targets merely to produce a pull request.

This source implementation does not publish a fresh Finding bundle by itself. Workflow execution, Gardener controller execution, target PR creation, target merges, deployment, and live verification remain separate authority gates.
