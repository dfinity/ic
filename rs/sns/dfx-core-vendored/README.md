# `dfx-core-vendored`

A subset of the [`dfx-core`](https://crates.io/crates/dfx-core) crate, kept
in-tree because [`dfx`](https://github.com/dfinity/sdk) is deprecated. It covers
only what SNS tooling (`ic-sns-cli`, `ic-sns-testing`) needs: resolving a dfx
identity + network into an [`ic_agent::Agent`], and resolving a dfx identity name
to its principal.

## Motivation

`dfx` is deprecated. Once the [`dfinity/sdk`](https://github.com/dfinity/sdk)
repository is archived, no new `dfx-core` releases can be cut — and that is a
problem here because `dfx-core` re-exports `ic-agent` in its public API, so its
**major version is bumped in lockstep with `ic-agent`**. Depending on the
published crate therefore ties this monorepo's `ic-agent` upgrades to the cadence
of `dfx-core` releases, which would eventually block this monorepo from upgrading
`ic-agent` again.

Keeping the small slice we use in-tree removes that coupling while preserving
behaviour for the supported cases: dfx identities keep working
(`~/.config/dfx/identity/...` is untouched) and the SNS CLI behaves exactly as
before. There is no user-facing change.

## Maintenance policy

**This crate is frozen. No new code should depend on it, and it should not
grow.** Its only consumers, `ic-sns-cli` and `ic-sns-testing`, are in
maintenance mode (bug fixes only), and this crate exists solely to preserve
their existing behaviour.

- Do not add features or extend the surface to cover more of `dfx-core`. If a
  broader dfx integration is ever needed, the intended path is an `icp sns`
  subcommand on the `icp-cli` extension system, not growing this crate.
- The only expected changes are the mechanical adjustments required to keep it
  compiling against future `ic-agent` majors (the reason it exists), plus any
  bug fix that also applies to `ic-sns-cli`.

## Relationship to upstream

Derived from **`dfx-core 0.4.0`**, which depends on `ic-agent 0.47` — the
version used throughout this workspace. Conceptually this crate is:

```sh
cp -R sdk/src/dfx-core/src ic/rs/sns/dfx-core-vendored/src   # then delete what SNS doesn't need
```

Most modules are copied at the **same relative path** as upstream and trimmed to
the identity **loading** path and the `ic` / `local` / URL network cases
(identity creation, wallets, extensions, and general dfx project/network config
parsing are dropped). Because paths and contents line up, they can be checked
against upstream directly:

```sh
diff -ur sdk/src/dfx-core/src ic/rs/sns/dfx-core-vendored/src
```

Two files are **reimplementations** rather than trimmed copies, so they do not
diff cleanly and are the only files a reviewer needs to read in full:

- `network.rs` — a compact resolver replacing `dfx-core`'s `network/` +
  `config/` machinery. Handles the built-in `ic` (mainnet) network, the `local`
  network (shared or project, honouring a running replica's `webserver-port`,
  mirroring `LocalBindDetermination::ApplyRunningWebserverPort`), and an explicit
  IC HTTP endpoint URL. `is_ic` and the default binds/gateways match upstream;
  playground, `networks.json`-defined networks, and full `dfx.json` parsing are
  dropped.
- `lib.rs` — replaces `interface/builder.rs` + `interface/dfx.rs`
  (`DfxInterface`/`DfxInterfaceBuilder`, unused externally) with two functions,
  `get_agent` and `get_identity_principal`, plus the private
  `build_identity`/`build_agent` that mirror `DfxInterfaceBuilder`'s
  non-anonymous identity and agent construction.

[`ic_agent::Agent`]: https://docs.rs/ic-agent/0.47/ic_agent/struct.Agent.html
