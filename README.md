# Counterbranch GitHub Action

This source-free composite Action acquires a public, publisher-attested
Counterbranch CLI release and prepares the separately pinned OPA runtime before
comparing two exact commits in automatic OPA mode. Configured mode also accepts
the existing HTTP, Cedar, and OpenFGA project workflows with a separately
prepared binary and operator-reviewed configuration. [Discovery mode](#discovery-mode)
acquires the Sigstore-signed paired kit and runs a static Discovery comparison.
Its export contains the Action metadata, installer, preparer, kit extractor and
Python helpers, this guide, its Apache-2.0 `LICENSE`, and exact
manifests. It contains no engine source.

Each export carries a `release-manifest.json`. A `publisher-approval-pending`
manifest, as checked into the source repository, makes automatic acquisition
fail closed. An approved manifest pins a release in `counterbranch/releases` and
lists CLI archives (`assets`), paired Discovery kits (`kits`), or both. A
Discovery-only release has no `assets`, so automatic policy mode stops with
an error and only [Discovery mode](#discovery-mode) runs. With approved CLI
archives, the customer workflow is:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    ref: ${{ github.event.pull_request.head.sha }}
    fetch-depth: 0
    persist-credentials: false
- uses: counterbranch/counterbranch-action@<APPROVED_FULL_ACTION_COMMIT_SHA>
  id: counterbranch
  with:
    repository: ${{ github.workspace }}
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
    select: |
      policy/main.rego
      policy/helpers.rego
    engine: opa
```

The checkout must contain both exact commits. Trusted workflow control stays
outside candidate revisions, checkout credentials are not persisted, and the
comparison receives neither product source nor release credentials. Trusted
preparation uses the normal `github.token` with `contents: read` in an isolated
GitHub CLI configuration directory to access public releases. It does not use a
private release token or expose the token to the installed CLI. Comparison and
report validation receive only required host paths, the Counterbranch cache and
locale settings; ambient job credentials are removed.

`acquire.py` supports only `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu`. It streams the exact manifest-named asset within its
reviewed size, checks size and SHA-256, invokes `gh release verify-asset` for the
manifest repository and tag, then independently requires the GitHub release
predicate and an exact subject name/digest binding. Any pending approval,
unsupported target, malformed evidence or mismatch stops before installation.
`--archive` runs an already available local archive through the same digest and
attestation checks. Mocked tests exercise that control flow but do not establish
real publisher authentication.

The existing configured form remains supported:

```yaml
- uses: counterbranch/counterbranch-action@<APPROVED_FULL_ACTION_COMMIT_SHA>
  with:
    binary: /absolute/path/to/counterbranch
    config: /absolute/path/to/project.json
```

Provide exactly one form. Automatic mode requires `repository`, `base`, and
`head`; configured mode requires `binary` and `config`. Selectors are passed as
literal repository-relative arguments. The Action exposes `outcome`,
`has_incomplete`, `engine`, `report`, `markdown_report`, `run_directory`, and an
optional `revisions` path. It requires both report files and validates the JSON
through the CLI. Missing, incomplete or inconsistent delivery fails the step and
emits `UNKNOWN` with `has_incomplete=true` where output files are available.
The optional `engine` input accepts `http`, `opa`, `cedar`, or `openfga` and
rejects a delivered report from a different engine.
Delivered `VIOLATION`, `INCOMPLETE`, and `NEEDS_OWNER_REVIEW` assessments remain
advisory; callers choose and document their gate.

## Discovery mode

`discovery: "true"` runs `counterbranch discovery` for one exact pair instead
of a policy comparison. It produces static, advisory discovery evidence, not a
policy decision or an application observation. It runs only on Linux x86_64 and
macOS arm64 runners. The Linux kit is built and qualified on `ubuntu-24.04`
(glibc 2.39); older runner images and distributions are unqualified and may lack
the glibc symbols it needs:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      ref: ${{ github.event.pull_request.head.sha }}
      fetch-depth: 0
      persist-credentials: false
  - uses: counterbranch/counterbranch-action@<APPROVED_FULL_ACTION_COMMIT_SHA>
    id: counterbranch
    with:
      discovery: "true"
      repository: ${{ github.workspace }}
      base: ${{ github.event.pull_request.base.sha }}
      head: ${{ github.event.pull_request.head.sha }}
      profile: default
```

Discovery mode requires `repository`, `base`, and `head` as exact lowercase
40-character commit IDs present in a complete clone. It rejects `binary`,
`config`, `select`, and `engine`. `profile` accepts `default`, `large`, or `xl`
and is rejected outside discovery mode. `large` and `xl` scans may need a
larger `timeout-seconds`, up to 3600. The Action installs cosign v3.0.6 with
`sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6` (v4.1.2),
only in this mode. `acquire.py --kit` downloads the manifest's
`counterbranch-alpha-<target>.tar.gz` kit and its `.sigstore.json` bundle through
the same bounded release download. Before extraction it checks both sizes and
SHA-256 digests against the manifest `kits` entry, then runs the GitHub release
attestation check on the kit. Last, it verifies the Sigstore bundle with an
empty cosign home:

```sh
cosign verify-blob --bundle <bundle> \
  --certificate-identity https://github.com/counterbranch/counterbranch/.github/workflows/publish.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <kit>
```

Any failure stops before extraction. `kit.py` then checks the kit's digest and
inventory and extracts it into a fresh `$RUNNER_TEMP` prefix. OPA is not
prepared. The CLI finds `bin/discovery` and
`share/counterbranch/discovery-artifact.json` in that prefix and writes to a new
`$RUNNER_TEMP` directory, which becomes `run_directory`, with the same
credential-free environment, timeout, and cancellation handling. Exit 0 from
`counterbranch discovery` means only that `index.md` was delivered. The Action
also requires exactly one `<head-short-sha>/comparison.json` with `report.md`
and validates the JSON with `counterbranch report --format json` under the
72 MiB Discovery interchange limit. The validated `base`/`candidate`
revisions must equal the requested commits. It then exposes `engine=discovery`,
`outcome` (`CLEAN`, `NEEDS_OWNER_REVIEW`, or `INCOMPLETE`), `has_incomplete`,
`report` (`comparison.json`), and `markdown_report` (`report.md`). A `FAILED`
or interrupted pair, a nonzero exit, a timeout, or missing, extra, or mismatched
output fails the step with `UNKNOWN` and `has_incomplete=true`. `CLEAN` is not
merge approval. The job summary includes `report.md` when it fits GitHub's
1 MiB summary limit. After a failure it includes `index.md`, when delivered, and
exposes only `run_directory` so the failed pair can be inspected or uploaded.

The Action does not post pull-request comments. Posting is a separate, explicit
`counterbranch comment --input <report>` step with its own authorization.
Discovery mode needs an approved manifest with a `kits` entry for the runner's
target; otherwise acquisition fails before anything is installed.

## Hosted acceptance and tests

`hosted-candidate.yml` is an inactive Linux x86_64 GNU acceptance job outside
`.github/workflows`. It creates a deterministic synthetic OPA repository and
asserts the full baseline, change, and missing-corpus commit IDs. It then exercises
the customer install path, complete and incomplete outcomes, corrupted archive
rejection, and SIGTERM during an observed real `opa eval`; the cancellation gate
requires the OPA process and owned engine temporary directory to be gone. It
retains reports for one day. Its impossible Action pin must be replaced by an
approved repository and reviewed full SHA. Before dispatch, the operator must
verify runner availability, permissions, allowance, and cost authorization; the
job timeout does not prevent billing. No hosted run or publication has occurred.

Run the dependency-free tests with:

```sh
python3 -m unittest discover -s distribution/github-action -p 'test_*.py'
```
