# `dfx-core-vendored`

A minimal, in-tree vendoring of the parts of the external
[`dfx-core`](https://crates.io/crates/dfx-core) crate that SNS tooling
(`ic-sns-cli`, `ic-sns-testing`) depends on: resolving a dfx identity + network
into an [`ic_agent::Agent`], and resolving a dfx identity name to its principal.

## Motivation

`dfx-core` re-exports `ic-agent` in its public API, so its **major version is
bumped in lockstep with `ic-agent`**. Depending on the published crate ties this
monorepo's `ic-agent` upgrades to the cadence of `dfx-core` releases: every time
we bump `ic-agent` to a new major, we would need a matching `dfx-core` release.

Once the [`dfinity/sdk`](https://github.com/dfinity/sdk) repository is archived,
those `dfx-core` releases can no longer be cut — which would block this monorepo
from ever upgrading `ic-agent` again. Vendoring the small slice we actually use
removes that coupling, while keeping behaviour identical for the supported
cases: dfx identities keep working (`~/.config/dfx/identity/...` is untouched),
and the SNS CLI behaves exactly as before. There is no user-facing change.

This crate was derived from **`dfx-core` `0.3.0`**, which depended on
`ic-agent 0.45` — the version used throughout this workspace at the time of
vendoring, so the initial copy compiled against the same API with no
adaptation. That version pairing was only the starting point, not a lasting
constraint: because the code now lives in-tree, it moves with this workspace's
`ic-agent` and is expected to be upgraded to future majors (`0.46`, `0.47`, …)
in place, alongside the rest of the monorepo, with no dependency on any further
`dfx-core` release.

## Maintenance expectation

**We do not expect to modify this crate going forward.** Its only consumers,
`ic-sns-cli` and `ic-sns-testing`, are in maintenance mode (bug fixes only), and
this crate exists solely to preserve their existing behaviour. It should be
treated as frozen vendored code:

- Do not add features or extend the surface to cover more of `dfx-core`. If a
  broader dfx integration is ever needed, the intended path is an `icp sns`
  subcommand on the `icp-cli` extension system, not growing this crate.
- The only expected changes are the mechanical adjustments required to keep it
  compiling against future `ic-agent` majors (which is the entire reason it
  exists), plus any bug fixes that also apply to `ic-sns-cli`.

## What is kept vs. dropped

Compared to `dfx-core 0.3.0`. Only identity **loading** and the `ic` / `local` /
URL network cases are retained; identity creation, wallets, extensions, and
general dfx project/network config parsing are not. The identity modules are
copied close to verbatim so they can be diffed against upstream; the network
resolution is a compact reimplementation.

| This crate | `dfx-core 0.3.0` origin | Difference |
| --- | --- | --- |
| `lib.rs` | `interface/builder.rs`, `interface/dfx.rs` | Rewritten. Replaces `DfxInterface`/`DfxInterfaceBuilder` (unused externally) with two functions, `get_agent` and `get_identity_principal`, plus private `build_identity`/`build_agent` that mirror `DfxInterfaceBuilder`'s non-anonymous identity and agent construction. |
| `network.rs` | `network/provider.rs`, `network/root_key.rs`, `config/model/{network_descriptor,local_server_descriptor,dfinity}.rs` | Rewritten. Compact resolver for `ic` (mainnet), `local` (shared or project, honouring a running replica's `webserver-port`, mirroring `LocalBindDetermination::ApplyRunningWebserverPort`), and an explicit IC HTTP endpoint URL. Playground, `networks.json`-defined named networks, and full `dfx.json` parsing (beyond the `local` bind) are dropped. `is_ic` and the default binds/gateways are kept identical to upstream. |
| `identity/mod.rs` | `identity/mod.rs` | Trimmed. Keeps `Identity` (anonymous / basic / secp256k1 / hardware / `new`), its `ic_agent::Identity` impl, and `IdentityType`. Drops all wallet handling (`WalletGlobalConfig`, load/save wallet config, `map_wallets_to_renamed_identity`), `CallSender`, and `display_linked_wallets`. |
| `identity/identity_manager.rs` | `identity/identity_manager.rs` | Trimmed to the **load** path: `new`, `instantiate_selected_identity`, `instantiate_identity_from_name`, `load_identity`, `require_identity_exists`, `get_identity_config_or_default`, config accessors. Drops identity creation (`create_new_identity`, `initialize`, key/mnemonic generation → also drops the `bip32`/`bip39`/`sec1`/`ring` deps), rename, remove, export, `use_identity_named`, `get_identity_names`, `IdentityCreationParameters`, `IdentityStorageMode`, and now-unused struct fields. `InitializeIdentity` is retained for API compatibility but `Allow` no longer auto-creates a default identity (dfx's job); SNS only ever passes `Disallow`. |
| `identity/pem_safekeeping.rs` | `identity/pem_safekeeping.rs` | Trimmed to the **load** path: `load_pem`, `load_pem_from_file`, `maybe_decrypt_pem`, `decrypt`, password prompt. Drops all saving/encrypting (`save_pem`, `write_pem_to_file`, `maybe_encrypt_pem`, `encrypt`). |
| `identity/keyring_mock.rs` | `identity/keyring_mock.rs` | Trimmed to the **load** path: `load_pem_from_keyring` and the `DFX_CI_MOCK_KEYRING_LOCATION` test hook. Drops `write_pem_to_keyring`, `delete_pem_from_keyring`, and `keyring_available`. |
| `identity/identity_file_locations.rs` | `identity/identity_file_locations.rs` | Verbatim, minus the unused `root()` accessor. |
| `config/directories.rs` | `config/directories.rs` | Trimmed. Keeps `project_dirs`, `get_shared_network_data_directory`, `get_user_dfx_config_dir`, and `DFX_CONFIG_ROOT`. Drops `get_shared_wallet_config_path` (wallets). |
| `foundation.rs` | `foundation/mod.rs` | Trimmed to `get_user_home` (drops `get_current_exe`). |
| `fs/mod.rs`, `fs/composite.rs` | `fs/mod.rs`, `fs/composite.rs` | Trimmed to the read-side helpers used by the load paths (`read`, `read_to_string`, `create_dir_all`, `ensure_dir_exists`). Drops archive extraction, all write/permission helpers, and `canonicalize` (→ also drops the `tar`/`flate2`/`dunce` deps). |
| `json.rs` | `json/mod.rs`, `json/structure.rs` | Trimmed to `load_json_file` (drops `save_json_file` and `structure.rs`). |
| `error/*.rs` | `error/*.rs` | Consolidated from 27 error modules to 7 (`config`, `encryption`, `fs`, `get_user_home`, `identity`, `keyring`, `structured_file`), keeping only the enums and variants reachable on the retained load/resolve paths. Messages are preserved for the retained variants. |

[`ic_agent::Agent`]: https://docs.rs/ic-agent/0.45/ic_agent/struct.Agent.html
