# ADR-0015 producer implementation note

This branch implements the producer side of accepted Atlas Infra authority `11e7a727590aa5376e766416b1e6a83fb6fd98ef`.

`atlas-dep-audit` remains the detection and public Finding-bundle producer. It may emit structured remediation candidates only when the exact audited checkout proves the bounded ADR-0015 conditions. Unsupported, ambiguous, major-version, transitive-only, or unresolved cases remain observations.

Docker Hub digest resolution is public read-only evidence gathering. It does not use Gardener write credentials or provider secrets. Candidate publication and controller execution remain separate workflow/runtime gates.
