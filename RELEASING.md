# Releasing

How a Quipu-Log version gets cut and published. Publishing itself is automated —
pushing a `v*` tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which tests and then publishes all five crates to crates.io in dependency order.
Your job is to prepare the release commit and push the tag.

## One-time setup

The release workflow publishes with a crates.io token stored as a repository
secret:

1. Create a token at <https://crates.io/settings/tokens> (scope: `publish-update`,
   plus `publish-new` for the first publish of a crate).
2. Add it under **Settings → Secrets and variables → Actions** as
   `CRATES_IO_TOKEN`.

The account must have a verified email (crates.io rejects publishing otherwise).

## Cutting a release

All five crates share one version (`[workspace.package] version` in the root
`Cargo.toml`), so they release together.

1. **Land everything on `main`.** Each change rides its own `feat/*` branch,
   merged via PR with CI green (fmt, clippy, test, fuzz smoke). `main` should be
   green before you start.
2. **Bump the version** in the root `Cargo.toml` (`[workspace.package] version`).
   Follow SemVer; pre-1.0, breaking changes bump the minor (0.x).
3. **Cut the changelog.** In `CHANGELOG.md`, rename the `## [Unreleased]` heading
   to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above it.
   A format/DLQ/API contract change is a breaking change — see the compatibility
   policy at the top of the changelog.
4. **Update docs if needed** — README (EN/KO), crate docs.
5. **Commit** (`chore(release): vX.Y.Z`) and merge to `main`.
6. **Dry-run locally** (optional but cheap):
   ```sh
   cargo publish --dry-run -p quipu-core
   ```
   Dependent crates can't fully dry-run until their deps are on crates.io — that
   "no matching package" error is expected, not a packaging problem.
7. **Tag and push:**
   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
   The `release` workflow checks the tag matches the workspace version, runs the
   tests, and publishes `quipu-core → quipu-middleware → quipu-client →
   quipu-server → quipu-mcp`.
8. **Verify** the run is green and the versions appear on crates.io / docs.rs.

## Notes

- **Order matters and is automated.** `cargo publish` waits for each crate to be
  available in the index before the next, so dependents resolve their
  just-published deps.
- **A published version is permanent.** You can `cargo yank` a bad release but
  never overwrite or delete it — bump the patch and release again.
- **`quipu-mcp` has no internal crate deps** (it talks to `quipu-server` over
  HTTP), so it could publish anytime; it's last only for tidiness.
- The `fuzz/` crate is intentionally outside the workspace and is never
  published.
