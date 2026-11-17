# Standalone builds and periodic releases

Veksel is released as a directly compiled standalone application. The release
system does not build containers, installers, or platform-specific product
integrations. GitHub Actions is the automation boundary; the underlying matrix,
tag allocation, packaging, checksum, manifest, and verification logic is the
locally testable `cmd/veksel-release` command backed by `pkg/releasebuild`.

## Continuous integration

`.github/workflows/ci.yml` runs for pull requests targeting `main` and manual
dispatches. Direct pushes do not trigger CI. Its token has read-only repository
access and it has exactly one runner job with a ten-minute ceiling. That job
checks changed Go files with `gofmt`, runs the short/fail-fast unit suite, and
compile-checks the scenario-heavy SMTP, API, end-to-end, and load-test packages.

Fast CI does not run vet, compile binaries, select a build profile, or build any
platform/feature matrix. Superseded pull-request runs remain cancellable, but
the primary cost bound is structural: every invocation can allocate only one
runner. Pull requests cannot create tags or releases.

The fast suite deliberately executes scenario-heavy tests only in daily/manual
release validation instead of on every rapidly superseded pull-request update;
it does not delete or weaken them. The complete `go test ./...` and `go vet
./...` run is mandatory before any of the 48 release builds. Run the fast suite
locally with `./scripts/test-unit`.

Run the equivalent local checks with:

```sh
make quality
make unit-test
make release-test
make release-ci-matrix
```

## Release matrix

The scheduled and manually dispatchable workflow builds every combination in
this table with `CGO_ENABLED=0`:

| Operating system | Architectures |
|---|---|
| Linux | amd64, arm64 |
| FreeBSD | amd64, arm64 |
| OpenBSD | amd64, arm64 |
| NetBSD | amd64, arm64 |
| Windows | amd64, arm64 |
| macOS (`darwin`) | amd64, arm64 |

Every target is built in four variants:

| Variant | Build tags | Exchange protocols included |
|---|---|---|
| `full` | none | Exchange ActiveSync and Exchange Web Services |
| `noeas` | `noeas` | Exchange Web Services |
| `noews` | `noews` | Exchange ActiveSync |
| `noexchange` | `noeas,noews` | neither |

`make release-matrix` prints the canonical 48-entry matrix. Tests reject
duplicates, omissions, unsupported targets, and feature metadata that differs
from this contract.

## Artifact and provenance contract

Release tags are monotonic `rNNNN` values. Archive names are explicit, for
example:

```text
veksel_r0042_linux_amd64_full.tar.gz
veksel_r0042_windows_arm64_noexchange.zip
```

Unix archives retain an executable `veksel`; Windows archives contain
`veksel.exe`. Every archive also contains `BUILD-INFO.json` with:

- manifest schema, tag, full source commit, and UTC build time;
- exact Go toolchain and GitHub workflow run identity;
- GOOS, GOARCH, variant, build tags, and enabled feature names;
- SHA-256 of the uncompressed binary.

The public release additionally contains `manifest.json` and `SHA256SUMS`.
Assembly opens every archive, validates its two-file layout and executable
mode, recomputes the embedded binary hash, validates all 48 fragments against
the canonical matrix, and recomputes every archive size and SHA-256 before a
release can be created. Builds use `-trimpath`, disable VCS auto-stamping, omit
the Go build ID, and inject Veksel' existing version/commit/build-time variables.
For a native target the builder executes `veksel --version` and compares the
result with the requested provenance before packaging it.

To verify downloaded assets locally:

```sh
go run ./cmd/veksel-release verify-checksums --dir /path/to/assets
```

## Allocation, serialization, and reruns

`.github/workflows/release.yml` runs daily at 03:17 UTC or by manual dispatch.
All invocations share one non-canceling concurrency group, so only one can
allocate or publish at a time. A cheap read-only gate compares the triggering
commit with the tag of the latest published GitHub release. It classifies files
with the tested release source-change policy. When a scheduled run has no
relevant source, dependency, compatibility, build-script, or workflow change,
it stops before identity allocation, tests, or builds; skipped jobs never obtain
runners.

When work is required, the release path runs the complete tests and all 48
builds on one Ubuntu runner with four bounded workers. It uploads one internal
part bundle for the unchanged assembly and publication stage. The public 48
archives, names, embedded provenance, manifest, checksums, verification, tag,
and idempotent publication contract are unchanged. Only release preparation and
publication receive `contents: write`; validation and build jobs remain read-
only.

Allocation scans exact `rNNNN` tags and creates the next annotated tag against
the triggering source commit. Its annotation records the workflow run ID and
exact Go patch version. Creating the tag before the build gives a failed run a
durable identity. A GitHub rerun retains its run ID, recognizes the tag,
verifies that it still points to the same commit, and rebuilds with the pinned
toolchain and tag timestamp. A later run receives the next number and can never
claim or overwrite the earlier tag.

Publishing first assembles all 48 parts. If the GitHub release already exists,
the workflow downloads it and succeeds only when the asset names and bytes are
exactly identical. Otherwise it creates one release from the already verified
tag. No workflow force-moves tags or replaces assets.

## Manual validation and release

Both workflows remain manually dispatchable without editing YAML:

- **CI → Run workflow** runs the same bounded formatting and fast-unit check
  used for pull requests. It never builds binaries.
- **Periodic release → Run workflow** defaults to `validate`. It runs the full
  test/vet suite, all 48 builds, assembly, and checksum validation with
  disposable `r0000` provenance, but cannot create a tag or release. Choose
  `release` explicitly to allocate the next immutable tag and publish.
- Manual dispatch always bypasses the scheduled no-change gate. A complete
  validation or release can therefore be forced when source is unchanged.

For a local non-publishing gate check, provide a name-only diff to the tested
classifier:

```sh
git diff --name-only BASE HEAD | go run ./cmd/veksel-release changes
```

It prints `false` for documentation-only diffs. `actionlint` validates both
workflow files, while `pkg/releasebuild` tests lock the one-job/no-build CI
topology, release change gate, bounded builds, complete matrix, and publication
dependency.

## Expected Actions usage

The August 2026 baseline contained 64 CI runs and one periodic release. GitHub's
job API reports 818 jobs and 1,854 rounded Linux minutes (the billing view's
slightly earlier snapshot was approximately 805 jobs / 1,815 minutes): 64
quality jobs used 412 minutes, 688 matrix jobs used 1,376, and 66 setup or
publication jobs used 66.

At the observed direct-push cadence, those 64 pushes now consume zero CI runner
minutes. A month with one changed daily release and 29 unchanged scheduled gates
is estimated at about 40–45 minutes: one rounded gate minute per day plus roughly
10–15 minutes for the changed full release. Each pull-request update or manual
CI check adds one to three rounded minutes; the locally cold-test-cache fast
suite completes in 31.5 seconds before hosted checkout/toolchain overhead.

That is an expected 97–98% overall reduction from the 1,854-minute baseline
before any optional pull-request/manual checks, and eliminates every automatic
commit-triggered CI minute. A source-changing release every day costs more than
the same-cadence estimate, but still performs the complete matrix only once per
day on one build runner rather than on every commit or 48 separately rounded
jobs. Actual billing should be reviewed after a month. The structural limits are
deterministic: zero CI jobs for direct pushes, one non-build job per pull-request
or manual CI invocation, one job for unchanged schedules, three for manual
validation, and four for a changed or explicitly forced release.

## Failure recovery

1. If preparation or a build fails, use **Re-run all jobs** on that same
   workflow run. Do not start a replacement manual run merely to reuse its
   number; the original run owns the annotated tag.
2. If publishing failed before creating a GitHub release, rerun the same run.
   The tag, build time, source commit, and Go version will be reused.
3. If GitHub contains a partial release, delete the GitHub release **without
   deleting its tag**, then rerun the original workflow. The rebuilt assets are
   verified from scratch.
4. If an existing release differs from a rerun, stop and inspect it. Never use
   an overwrite or force-tag operation as recovery.
5. An orphan tag may be removed only after confirming that it has no GitHub
   release and that its owning workflow can no longer be rerun. This is manual
   repository maintenance, not an automated workflow action.
