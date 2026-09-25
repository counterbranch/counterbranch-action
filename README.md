# Counterbranch Action

See what a pull request newly allows or denies before it ships. The Action
compares the pull request's base and head commits and puts the report in the
job summary.

## Quick start

Add `.github/workflows/counterbranch.yml`:

```yaml
name: Counterbranch
on: pull_request

permissions:
  contents: read

jobs:
  discovery:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          persist-credentials: false
      - uses: counterbranch/counterbranch-action@<commit-sha> # vX.Y.Z
        with:
          discovery: "true"
          repository: ${{ github.workspace }}
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
```

Replace `<commit-sha>` with the full commit SHA of a
[release tag](https://github.com/counterbranch/counterbranch-action/tags):

```sh
git ls-remote https://github.com/counterbranch/counterbranch-action 'refs/tags/vX.Y.Z^{}'
```

That's it. Open a pull request and read the report in the run's summary.

## Requirements

- **Runner:** `ubuntu-24.04` (x86_64) or macOS on Apple silicon. Older Ubuntu
  images may lack the glibc the kit needs.
- **Full clone:** `fetch-depth: 0`, so both commits are present.
- **Permissions:** `contents: read`. The Action downloads a public release with
  the job's `github.token` and passes no credentials to the scan.

## Reading the result

The step succeeds whenever it delivers a validated report, whatever the report
says. Use the `outcome` output to decide what to do:

| `outcome` | Meaning |
| --- | --- |
| `CLEAN` | No access changes found. Not a merge approval. |
| `NEEDS_OWNER_REVIEW` | Access changes someone should look at. |
| `VIOLATION` | Policy mode only: a decision breaks an approved expectation. |
| `INCOMPLETE` | Part of the comparison couldn't be checked. |
| `UNKNOWN` | The run failed. The step fails too. |

To fail the job on anything but `CLEAN`, give the step an `id` and add:

```yaml
      - if: steps.counterbranch.outputs.outcome != 'CLEAN'
        run: exit 1
```

To keep the full reports, upload the run directory:

```yaml
      - if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: counterbranch
          path: ${{ steps.counterbranch.outputs.run_directory }}
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `discovery` | `"false"` | `"true"` runs a Discovery comparison. |
| `repository` | | Path to the clone. |
| `base`, `head` | | Full 40-character commit SHAs to compare. |
| `profile` | `default` | Discovery scan size: `default`, `large` or `xl`. |
| `timeout-seconds` | `900` | Limit per CLI run, 1 to 3600. Raise it for `large` and `xl`. |
| `select` | | Policy mode only: newline-separated policy files. |
| `engine` | | Policy mode only: expected engine (`http`, `opa`, `cedar`, `openfga`). |
| `binary`, `config` | | Configured mode only: a preinstalled CLI and project config. |

## Outputs

| Output | Description |
| --- | --- |
| `outcome` | See [Reading the result](#reading-the-result). |
| `has_incomplete` | `true` if any evidence is incomplete. |
| `report` | Path to the JSON report. |
| `markdown_report` | Path to the Markdown report. |
| `run_directory` | Directory with every file the run wrote. |
| `engine` | Engine that produced the report, such as `discovery`. |
| `revisions` | Path to `revisions.json` (policy projects only). |

## Discovery mode

Discovery is a static, advisory scan of the code in both commits. It is not a
policy decision and doesn't run your application. It rejects `binary`,
`config`, `select` and `engine`. It never reports `VIOLATION`.

## Policy mode

Without `discovery`, the Action compares policy files with an engine such as
OPA:

```yaml
      - uses: counterbranch/counterbranch-action@<commit-sha> # vX.Y.Z
        with:
          repository: ${{ github.workspace }}
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
          select: |
            policy/main.rego
          engine: opa
```

Policy mode needs a release that includes the Counterbranch CLI archives.
Current releases ship only the Discovery kits, so policy mode stops with an
error that points you to `discovery: "true"`.

Configured mode runs a CLI you installed yourself against a project config:

```yaml
      - uses: counterbranch/counterbranch-action@<commit-sha> # vX.Y.Z
        with:
          binary: /absolute/path/to/counterbranch
          config: /absolute/path/to/project.json
```

## What the Action verifies

Each Action commit pins one release of
[`counterbranch/releases`](https://github.com/counterbranch/releases) in
`release-manifest.json`, by name, size and SHA-256. Before running anything,
the Action:

1. downloads the kit for the runner and checks its size and SHA-256 against
   the manifest;
2. checks GitHub's release attestation with `gh release verify-asset`;
3. verifies the kit's Sigstore signature with cosign v3.0.6, which it installs.
   The signature must come from the Counterbranch `Publish` workflow:

   ```sh
   cosign verify-blob --bundle <kit>.sigstore.json \
     --certificate-identity https://github.com/counterbranch/counterbranch/.github/workflows/publish.yml@refs/heads/main \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com <kit>
   ```

Any failure stops the step before the kit is extracted. The scan gets only `PATH`,
`HOME`, the cache and temp directories and locale settings, so it never sees
the job's token.

The Action doesn't comment on pull requests. To post the report, run
`counterbranch comment --input <report>` in a separate step with its own
permissions.

## License

Apache-2.0. See [LICENSE](LICENSE).
