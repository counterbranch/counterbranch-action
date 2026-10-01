# Counterbranch scanner Action

This source-free Action compares static authorization coverage between exact Git commits using the
scanner-only Counterbranch and Discovery editions. It does not execute the application, custom rules,
recipes, policy runtimes, MCP, agents, or adapters. Reports are advisory and preserve incomplete evidence.

The checked-in release manifest remains publisher-approval-pending, so acquisition fails closed. A reviewed
export is gated by default until a real signup issuer and validator exist. A publisher may explicitly export
an open build whose gate is a no-op. The open mode does not implement signup or token issuance, verify license
acceptance, authenticate a supplied token, enforce licensing, or meter offline usage. Signup tokens are never
passed to scanner processes; open mode rejects a supplied token rather than implying it was validated.
The Action checks the embedded gate and release-manifest approval before installing Cosign or making an
acquisition request. Setup, authentication, and scan failures expose `UNKNOWN` and `has_incomplete=true`.

Use `actions/checkout` with `fetch-depth: 0`, then provide the absolute checkout path and exact lowercase
40-character `base` and `head` commit IDs. The Action computes their single merge base and compares it with
head. Inspect `outcome` and `has_incomplete`; successful Action execution does not mean the assessment is clean.

Publication is currently held. After a reviewed release is published, pin the Action to the exact published
commit rather than a moving branch or tag:

```yaml
- uses: counterbranch/counterbranch-action@REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT
  with:
    repository: ${{ github.workspace }}
    base: REPLACE_WITH_EXACT_BASE_COMMIT
    head: ${{ github.sha }}
```

The repository input must name a full, non-shallow checkout containing both revisions. The optional profile
selects the static scan bounds. `timeout-seconds` caps the entire two-sided comparison command
(default 1800, maximum 3600); it does not change each scan profile's internal timeout. Git and saved-report
validation commands have a separate cap of at most 120 seconds (or the shorter requested comparison deadline).
The publisher chooses the embedded access mode when exporting the Action; workflow callers cannot change it.

The Action writes `outcome`, `has_incomplete`, `report`, `markdown_report`, `run_directory`, and `merge_base`
outputs. The step summary includes the static Markdown comparison. Treat `INCOMPLETE` and `UNKNOWN` as requiring
follow-up, and inspect incomplete reasons even when a report was produced. The authenticated paired kit is
checked against its reviewed manifest, GitHub release attestation, Sigstore bundle, exact digest, and size before
either bundled executable runs.

This alpha is provided as-is for static evaluation. The supported build targets are macOS arm64 and Linux x86-64 GNU.
Each target still requires release qualification; synthetic checks do not establish customer application behavior. See `LICENSE` for
the software license and the packaged kit notices for bundled dependency terms.
