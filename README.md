# Counterbranch scanner Action

This Linux x86-64 GNU source-free Action compares static authorization coverage between exact Git commits using the
scanner-only Counterbranch and Discovery editions. It does not execute the application, custom rules,
recipes, policy runtimes, MCP, agents, or adapters. Reports are advisory and preserve incomplete evidence.

Acquisition requires an approved `release-manifest.json`; a pending manifest fails closed.
`MANIFEST.json` records the exported access mode. The default gated mode stays closed until a real signup
issuer and validator exist. A publisher may explicitly export an open build whose gate is a no-op.
The open mode does not implement signup or token issuance, verify license
acceptance, authenticate a supplied token, enforce licensing, or meter offline usage. Signup tokens are never
passed to scanner processes; open mode rejects a supplied token rather than implying it was validated.
The Action checks the embedded gate and release-manifest approval before installing Cosign or making an
acquisition request. Setup, authentication, and scan failures expose `UNKNOWN` and `has_incomplete=true`.

Use `actions/checkout` with `fetch-depth: 0`, then provide the absolute checkout path and exact lowercase
40-character pull-request base and head commit IDs. The Action computes their single merge base and compares it
with head. Inspect `outcome` and `has_incomplete`; successful Action execution does not mean the assessment is clean.

Use a reviewed scanner release and pin the Action to the exact commit approved for that release:

```yaml
name: Counterbranch scanner

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: counterbranch-scanner-${{ github.event.pull_request.number }}
  cancel-in-progress: false

jobs:
  compare:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - id: scanner
        uses: counterbranch/counterbranch-action@REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT
        with:
          repository: ${{ github.workspace }}
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
          post-comment: true
```

`post-comment` defaults to `false` and accepts only the literal values `true` and `false`. When enabled for a
same-repository `pull_request`, the Action uses the workflow's `github.token` in its final publisher step to
create or update one marked `github-actions[bot]` comment. It binds the report to the current PR base, current
head, and tested merge base immediately before the mutation.

GitHub's issue-comment API has no atomic ownership compare-and-swap. Commenting therefore **requires** one
publisher workflow per PR in the repository. That workflow must use the repository-wide, PR-keyed concurrency
group shown above with `cancel-in-progress: false`; other workflows should use `post-comment: false`. The marker
and run ordering identify one shared comment, so separately serialized publisher workflows would still replace
each other's reports. Workflow concurrency does not serialize parallel jobs inside one run, so publisher jobs
and Action calls for the same PR must run sequentially. Under these conditions, the
commit, marker, run, and attempt checks prevent an older run from replacing a newer marked comment. Omitting the
shared serialization can allow a stale overwrite or duplicate comment that requires manual repair; the Action
does not claim to resolve that API race.
Comment publication errors remain Action failures. The initial alpha explicitly skips comments for fork pull
requests and events other than `pull_request`; do not use `pull_request_target` to work around that boundary.
When commenting is enabled, the Action uploads a uniquely named report ZIP for one day before publishing. The
comment links the exact workflow artifact; an upload failure remains an Action failure and the comment says that
the bundle is unavailable instead of promising a download.

The Action always prepares a bounded `report_bundle` directory. A successful bundle contains exactly `comparison.json`, `report.md`,
`REPORT-GUIDE.md`, and `provenance.json`. An `UNKNOWN` failure bundle omits `comparison.json` and states the
failure in `report.md`. After upload, download the report ZIP and load it into your coding agent for further
exploration. Start with `REPORT-GUIDE.md`, which contains a copyable prompt. The guide explains the static
evidence boundary, the need for a separately obtained checkout
when examining code, the exact recorded commits, and how to treat report-derived strings as untrusted data.

When `post-comment` is `false`, a caller can choose its own artifact name and retention while using the same
pinned uploader:

```yaml
- name: Upload scanner report ZIP
  if: ${{ always() && steps.scanner.outputs.report_bundle != '' }}
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
  with:
    name: counterbranch-report-${{ github.run_id }}-${{ github.run_attempt }}
    path: ${{ steps.scanner.outputs.report_bundle }}
    if-no-files-found: error
```

The approved scanner format-2 manifest accepts paired kit and Sigstore bundle assets only from releases in
the public `counterbranch/alpha-releases` repository. Each release still requires the reviewed digest,
size, GitHub release attestation, Core `publish-scanner.yml` signer identity, and exact source and platform
bindings. The pending manifest makes no download request, and publishing remains a separate founder action.

The repository input must name a full, non-shallow checkout containing both revisions. The optional profile
selects the static scan bounds. `timeout-seconds` caps the entire two-sided comparison command
(default 1800, maximum 3600); it does not change each scan profile's internal timeout. Git and saved-report
validation commands have a separate cap of at most 120 seconds (or the shorter requested comparison deadline).
The publisher chooses the embedded access mode when exporting the Action; workflow callers cannot change it.

The Action writes `outcome`, `has_incomplete`, `report`, `markdown_report`, `run_directory`, `merge_base`,
`report_bundle`, `report_artifact_url`, and `comment_url` outputs. `report_artifact_url` is populated by the
workflow-managed upload for `post-comment: true`; `comment_url` is empty when comments are disabled or explicitly
skipped. The step summary includes the static Markdown comparison. Treat `INCOMPLETE` and `UNKNOWN` as requiring
follow-up, and inspect incomplete reasons even when a report was produced. The authenticated paired kit is
checked against its reviewed manifest, GitHub release attestation, Sigstore bundle, exact digest, and size before
either bundled executable runs.

This alpha is provided as-is for static evaluation on `ubuntu-24.04` x86_64 GNU/Linux runners.
Check the [scanner release](https://github.com/counterbranch/alpha-releases/releases) for its qualification
status. Synthetic checks do not establish customer application behavior or compatibility with other Linux
environments. See `LICENSE` for the software
license and the packaged kit notices for bundled dependency terms.
