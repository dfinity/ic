---
name: crate-upgrade
description: Use when upgrading a Rust crate / third-party dependency to a new version — especially non-trivial bumps where the new version removes previously-deprecated APIs, moves modules into separate crates, renames items, or otherwise has a broad blast radius across many crates. Covers reading the changelog, picking the version deliberately, splitting the migration into aspects, and migrating incrementally.
---

# Upgrading a Rust crate dependency

Most version bumps are trivial: edit the version in `Cargo.toml`, mirror it in
`bazel/rust.MODULE.bazel`, repin, build. This skill is for the **non-trivial**
ones — where the new version removes APIs, splits modules into new crates,
renames items, or the change ripples across many crates.

Work through the steps in order. Steps 3–6 are the ones that keep a large
migration from turning into an unreviewable, half-broken mess.

## 1. Read the release notes first

Before touching any code, read the changelog for **every** version between the
current and target version.

- Classify each change: **deprecated** vs **removed**, and in which version.
  Note module moves and module→separate-crate splits — those are easy to miss
  because they aren't "deprecations".
- Estimate the blast radius: grep the repo for the affected APIs (paths, macros,
  type names) to see how many crates/files are involved.

## 2. Pick the version deliberately — don't jump across a removal boundary

If the target version **removes** APIs that were only **deprecated** in an
earlier version, do not bump straight to it in one leap.

- Prefer the highest version where the old and new APIs still **coexist**
  (typically the last version before the removal). Migrate the code to the new
  APIs there — while everything still compiles and the old APIs are merely
  deprecated — and only bump to the target version once the code no longer
  references anything that version removed.
- Example: if `X` was deprecated in 0.18 and removed in 0.20, do the migration
  on 0.19 first, then bump to 0.20.

## 3. For non-trivial migrations, list the aspects and get human sign-off

Most upgrades are straightforward and you can just do them. But when a migration
spans several distinct **aspects / areas** — e.g. renamed accessor functions, a
new inter-canister call API, a reject/error-type change, a module that became a
separate crate — do **not** start coding.

- After reading the release notes and understanding the blast radius, enumerate
  the aspects, and for each note the API involved and the files/crates it
  touches.
- Present that split to a human and get it confirmed before starting.
- (A trivial single-aspect upgrade can skip this.)

## 4. Migrate one aspect at a time

- Do a single aspect across the codebase, and leave **every other aspect** on
  the existing (deprecated-but-working) API.
- Each step should compile and pass tests on its own — a small, self-contained,
  reviewable change.
- If an aspect's blast radius turns out far larger than expected (e.g. it hits
  production canisters or needs a brand-new dependency), that's a signal to stop
  and reassess the approach with a human, not to plow ahead.

## 5. Adopt the new names directly — no aliases or shims

Aim for the cleanest end state; the code should read as if it had always been
written against the new API.

- When a symbol is renamed, update the call sites to the new name.
- Do **not** introduce `use new::path::Thing as OldName` aliases, wrapper
  functions, or other compatibility shims just to avoid touching call sites.
  They leave the codebase looking backwards instead of forward.

## 6. Don't abstract mid-migration

- Favor mechanical, localized edits, even when they produce boilerplate or
  duplication. Duplicating a small amount of code (e.g. a local type that
  preserves a Candid interface) is fine when it avoids re-architecting.
- Do **not** introduce new helpers/abstractions to smooth the migration while it
  is in flight.
- Only **after** the migration is fully done — it compiles, passes tests, and
  has been approved by a human — reassess whether the accumulated
  boilerplate/duplication is worth factoring out.

## 7. Keep Cargo and Bazel in sync

- Edit `Cargo.toml` first, then mirror the version in `bazel/rust.MODULE.bazel`
  (the `crate.spec(...)` for the crate). A new crate must be added to both.
- Repin the Bazel crate index: `./bin/bazel-pin.sh`.
- Then follow the repo's standard Rust workflow: `rustfmt` → `cargo check` →
  `cargo clippy` → `bazel build` → `bazel test` (see the project `CLAUDE.md`).
- See the **check-bazel-files** skill after editing Bazel files, and
  **run-in-dev-container** for running builds/tests inside the dev container.
