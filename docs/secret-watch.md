# Secret-watch enforcement

## Responsibility

`atlas-dep-audit` enforces the declaration owned by `atlas-infra`. The module
is standard-library only and runs inside the existing audit job; it does not
create a service or add a scheduled workflow. The canonical policy, threat
model, lifecycle procedures, and incident runbooks remain in `atlas-infra`.

## Assurance path

For each run, `audit.py`:

1. validates the canonical shared contracts as before;
2. loads and fails closed on the secret declaration;
3. evaluates owner, purpose, rotation metadata, repository classification, and
   exclusions;
4. compares required/optional/deprecated names with a deterministic fixture or
   optional GitHub names-only metadata;
5. enumerates `git ls-files`, skips approved fixtures, binaries, symlinks, and
   oversized files, then emits redacted plaintext-pattern findings;
6. validates Finding compatibility in the test gate, writes JSON and Markdown
   summaries, and includes the report in the existing artifact.

Existing SBOM, OSV, provenance, action-pin, container, and contract checks are
unchanged. A malformed declaration, required unavailable metadata, missing
required name, deprecated name still present, overdue rotation, classification
conflict, or plaintext credential finding is blocking. Optional disabled or
unavailable live metadata is a warning/unknown state and is not blocking.

## Local deterministic mode

Tests never make GitHub requests:

```bash
python3 -m unittest tests.test_secret_watch -v
python3 secret_watch.py \
  --policy ../atlas-infra/policy/secret-watch.json \
  --repositories-root .. \
  --metadata-fixture tests/fixtures/secret-watch/metadata-valid.json \
  --now 2026-07-14T10:00:00Z \
  --report /tmp/secret-watch.json \
  --markdown /tmp/secret-watch.md
```

Supplying the same repositories, fixture, policy, and `--now` produces
byte-identical JSON. The fixture carries names only.

The full dependency audit also accepts `--local-repositories-root` so a local
manifest can exercise cloning-independent, `--skip-osv` assurance without any
network call.

## Optional live mode

`--secret-watch-live` reads only `SECRET_WATCH_GITHUB_TOKEN`. If it is absent,
metadata is `disabled`. The selected-repository token needs repository
`Metadata: read` and `Secrets: read` only. It must not have `Secrets: write`.
The adapter calls repository/environment Actions secret list endpoints and a
repository metadata endpoint needed to address environment secrets. It never
calls a public-key, create, update, or delete endpoint.

Provider response bodies and authorization material are never copied into
errors. Permission denial, rate limit, timeout, missing repository/environment,
invalid response, or incomplete pagination becomes a bounded unavailable
reason. No result with incomplete metadata is healthy.

## Plaintext scan safety

The scanner processes each matched substring only in memory and immediately
discards it. The Finding fingerprint uses producer, check, repository,
category, rule, and location fields only; it is not a credential hash. Reports
contain the relative path, line, scanner rule ID in redacted evidence, and the
Finding fingerprint.

False positives use either the same-line marker
`secret-watch: ignore <rule-id>` or an exact central suppression with
repository, path, line, rule, owner, and reason. Approved fixture paths are
declared centrally. A broad directory, extension, or repository suppression is
not supported.

## Failure modes

- Missing/malformed policy: one redacted `malformed-declaration` Finding and a
  blocking report; metadata and scanning do not run against partial policy.
- Metadata unavailable: explicit disabled/unavailable/partial state; blocking
  only where policy requires metadata.
- Tracked-file enumeration failure: blocking redacted coverage Finding.
- Binary/fixture/oversized/symlink: counted skip, never decoded or followed.
- GitHub unavailable: offline declaration and plaintext checks still run.

## Rollback

Revert the `audit.py`, workflow, notification, module, test, and documentation
changes on this branch. The previous dependency and contract assurance path
continues. The `atlas-infra` declaration can remain as inert reviewed policy.
Rollback never mutates a GitHub or provider secret.

## Migration order

Merge the `atlas-infra` policy branch first, then rebase this branch so the
workflow's canonical checkout resolves `policy/secret-watch.json`. Run fixture
mode before adding the optional names-only token. The initial declaration
covers `atlas-infra` and `atlas-dep-audit`; other local repositories receive
plaintext scanning, while live name comparison is added only through later
owner-attested policy entries.
