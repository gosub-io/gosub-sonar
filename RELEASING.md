# Releasing gosub-sonar

A release is one crates.io publish plus a `vX.Y.Z` git tag. Nothing is automated; every step
below is run by hand.

## Choosing the version

Pre-1.0, so cargo treats a minor bump as the breaking one.

- **Breaking** bumps the minor (0.6.3 -> 0.7.0): a removed or renamed public item, a new or
  changed enum variant on a type that is not `#[non_exhaustive]`, a changed field or signature,
  a different error variant for an existing failure.
- **Everything else** bumps the patch (0.6.2 -> 0.6.3): new API, fixes, behaviour changes that
  keep the same types.

A changed variant counts as breaking even when nothing in this crate constructed it, because a
downstream `match` stops compiling.

## 1. Branch

```sh
git switch -c release-X.Y.Z
```

Feature commits for the release land on this branch too, the way 0.6.1 through 0.6.3 did, with
the prep commit below last so the release-only changes stay reviewable on their own.

## 2. CHANGELOG.md

Entries accumulate under `## [Unreleased]` as the work lands. Preparing the release stamps them:

1. Insert `## [X.Y.Z] - YYYY-MM-DD` directly below `## [Unreleased]`, leaving the existing
   `### Added` / `### Changed` / `### Fixed` sections underneath it. `## [Unreleased]` stays,
   empty, at the top.
2. At the bottom of the file, re-point the `[Unreleased]` compare link at the new tag and add a
   line for the release:

   ```
   [Unreleased]: https://github.com/gosub-io/gosub-sonar/compare/vX.Y.Z...HEAD
   [X.Y.Z]: https://github.com/gosub-io/gosub-sonar/compare/vPREV...vX.Y.Z
   ```

Mark every breaking entry `**Breaking:**` and say what a caller has to change: there is no
separate migration guide.

## 3. Version numbers

Three places:

- `Cargo.toml` - `version = "X.Y.Z"`.
- `Cargo.lock` - any cargo command rewrites it; `cargo check` is enough. It must be in the
  commit.
- `README.md` - the usage snippet carries a caret range (`gosub-sonar = "0.7"`). Only a minor
  bump needs this, which is why it gets missed: several patch releases in a row leave it alone,
  then a minor release ships a README pointing at the old line. 0.7.0 nearly did.

Nothing else in the repo pins a version.

## 4. Run the CI gates locally

The workflow sets `RUSTFLAGS: -D warnings` and `RUSTDOCFLAGS: -D warnings`. Export both, or
something clean locally will fail on the PR.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features
cargo doc --no-deps --all-features
cargo check --target wasm32-unknown-unknown
cargo test --features test-support
cargo test --all-features
cargo +1.88 test --features test-support        # MSRV, matches rust-version in Cargo.toml
```

Both test invocations are needed: `test_support` compiles under `cfg(test)` whether or not the
feature is on, and each build activates dependencies the other does not.

docs.rs builds with `all-features` (see `[package.metadata.docs.rs]`), so a broken intra-doc link
in feature-gated code only shows up after the publish, when that version can no longer be fixed.
That is what `cargo doc` here is for.

CI also runs the test job on macOS and Windows, which is what the PR is for.

## 5. Dry-run the publish

```sh
cargo publish --dry-run
```

This packages and then builds the packaged copy, which catches a file the package excludes but
the build needs. Run it before opening the PR, not after merging.

## 6. PR, CI, merge

Push the branch, open a PR against `main`, and wait for all four jobs (check, wasm, test x3,
msrv). Merge with a merge commit; the history reads
`Merge pull request #N from gosub-io/release-X.Y.Z`.

## 7. Tag

Tag on `main` after the merge, not on the branch:

```sh
git switch main && git pull
git tag vX.Y.Z
git push origin vX.Y.Z
```

Tags only. This repo publishes no GitHub Releases, and the changelog compare links depend on the
tag existing.

## 8. Publish

```sh
cargo publish
```

A published version can never be replaced, only yanked. If something is wrong, fix it forward in
the next patch release.
