//! The main functionalities in [the IC management canister][1].
//!
//! Most of the functions are for managing canister lifecycle.
//! [raw_rand] is also included in this module.
//!
//! [1]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister

use crate::api::call::{call, call_with_payment128, CallResult};
use candid::Principal;

mod types;
pub use types::*;

/// Cycles cost to create a canister.
///
/// https://internetcomputer.org/docs/current/developer-docs/deploy/computation-and-storage-costs
pub const CREATE_CANISTER_CYCLES: u128 = 100_000_000_000u128;

/// Register a new canister and get its canister id.
///
/// Note: This call charges [CREATE_CANISTER_CYCLES] from the caller canister.
///
/// See [IC method `create_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister).
pub async fn create_canister(arg: CreateCanisterArgument) -> CallResult<(CanisterIdRecord,)> {
    call_with_payment128(
        Principal::management_canister(),
        "create_canister",
        (arg,),
        CREATE_CANISTER_CYCLES,
    )
    .await
}

/// [create_canister] and specify extra cycles to the new canister.
///
/// Note: This call charges [CREATE_CANISTER_CYCLES] and the specified extra cycles from the caller canister.
///
/// See [IC method `create_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister).
pub async fn create_canister_with_extra_cycles(
    arg: CreateCanisterArgument,
    cycles: u128,
) -> CallResult<(CanisterIdRecord,)> {
    call_with_payment128(
        Principal::management_canister(),
        "create_canister",
        (arg,),
        CREATE_CANISTER_CYCLES + cycles,
    )
    .await
}

/// Update the settings of a canister.
///
/// See [IC method `update_settings`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-update_settings).
pub async fn update_settings(arg: UpdateSettingsArgument) -> CallResult<()> {
    call(Principal::management_canister(), "update_settings", (arg,)).await
}

/// Install code into a canister.
///
/// See [IC method `install_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code).
pub async fn install_code(arg: InstallCodeArgument) -> CallResult<()> {
    call(Principal::management_canister(), "install_code", (arg,)).await
}

/// Remove a canister's code and state, making the canister empty again.
///
/// See [IC method `uninstall_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-uninstall_code)
pub async fn uninstall_code(arg: CanisterIdRecord) -> CallResult<()> {
    call(Principal::management_canister(), "uninstall_code", (arg,)).await
}

/// Start a canister if the canister status was `stopped` or `stopping`.
///
/// See [IC method `start_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-start_canister)
pub async fn start_canister(arg: CanisterIdRecord) -> CallResult<()> {
    call(Principal::management_canister(), "start_canister", (arg,)).await
}

/// Stop a canister.
///
/// See [IC method `stop_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-stop_canister)
pub async fn stop_canister(arg: CanisterIdRecord) -> CallResult<()> {
    call(Principal::management_canister(), "stop_canister", (arg,)).await
}

/// Get status information about the canister.
///
/// See [IC method `canister_status`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_status)
pub async fn canister_status(arg: CanisterIdRecord) -> CallResult<(CanisterStatusResponse,)> {
    call(Principal::management_canister(), "canister_status", (arg,)).await
}

/// Delete a canister from the IC.
///
/// See [IC method `delete_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-delete_canister)
pub async fn delete_canister(arg: CanisterIdRecord) -> CallResult<()> {
    call(Principal::management_canister(), "delete_canister", (arg,)).await
}

/// Deposit cycles into the specified canister.
///
/// Note that, beyond the argument as specified in the interface description,
/// there is a second parameter `cycles` which is the amount of cycles to be deposited.
///
/// See [IC method `deposit_cycles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-deposit_cycles)
pub async fn deposit_cycles(arg: CanisterIdRecord, cycles: u128) -> CallResult<()> {
    call_with_payment128(
        Principal::management_canister(),
        "deposit_cycles",
        (arg,),
        cycles,
    )
    .await
}

/// Get 32 pseudo-random bytes.
///
/// See [IC method `raw_rand`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-raw_rand)
pub async fn raw_rand() -> CallResult<(Vec<u8>,)> {
    call(Principal::management_canister(), "raw_rand", ()).await
}
