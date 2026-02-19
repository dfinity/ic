//! Functions and types for interacting with the [IC management canister](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister).
//!
//! # Type Definitions
//!
//! This module defines the types of arguments and results for the management canister entry points.
//! Most of these types are re-exported from the `ic-management-canister-types` crate.
//!
//! The only exception is that for the argument types that has a `sender_canister_version` field, this module provides reduced versions instead.
//! The reduced versions don't need the `sender_canister_version` field as it is set automatically in the corresponding functions.
//!
//! # Call
//!
//! The majority of the functions in this module are for making calls to the management canister.
//!
//! ## Bounded-wait vs. Unbounded-wait
//!
//! Interacting with the IC management canister involves making inter-canister calls,
//! which can be either [bounded-wait](crate::call::Call::bounded_wait) or [unbounded-wait](crate::call::Call::unbounded_wait).
//! This module selects the appropriate type of wait call for each method based on the characteristics of the entry point.
//!
//! The strategy for choosing the type of wait call is as follows:
//! - Unbounded-wait call by default because the management canister is universally trusted.
//! - Bounded-wait call (with the default 300s timeout) for methods that only read state.
//!
//! Please check the documentation of each function for the type of wait call it uses.
//!
//! If the default behavior is not suitable for a particular use case, the [`Call`] struct can be used directly to make the call.
//!
//! For example, [`sign_with_ecdsa`] makes an unbounded-wait call. If a bounded-wait call is preferred, the call can be made as follows:
//! ```rust, no_run
//! # use ic_cdk::management_canister::{cost_sign_with_ecdsa, SignCallError, SignWithEcdsaArgs, SignWithEcdsaResult};
//! # use ic_cdk::call::Call;
//! # use candid::Principal;
//! # async fn example() -> Result<SignWithEcdsaResult, SignCallError> {
//! let callee = Principal::management_canister();
//! let arg = SignWithEcdsaArgs::default();
//! let cycles = cost_sign_with_ecdsa(&arg)?;
//! let res: SignWithEcdsaResult = Call::bounded_wait(callee, "sign_with_ecdsa")
//!     .with_arg(&arg)
//!     .with_cycles(cycles)
//!     .await?
//!     .candid()?;
//! # Ok(res)
//! # }
//! ```
//!
//! ## Cycle Cost
//!
//! Some management canister entry points require cycles to be attached to the call.
//! The functions for calling management canister automatically calculate the required cycles and attach them to the call.
//!
//! For completeness, this module also provides functions to calculate the cycle cost:
//! - [`cost_http_request`]
//! - [`cost_sign_with_ecdsa`]
//! - [`cost_sign_with_schnorr`]
//! - [`cost_vetkd_derive_key`]

use crate::api::{
    SignCostError, canister_version, cost_create_canister,
    cost_http_request as ic0_cost_http_request, cost_sign_with_ecdsa as ic0_cost_sign_with_ecdsa,
    cost_sign_with_schnorr as ic0_cost_sign_with_schnorr,
    cost_vetkd_derive_key as ic0_cost_vetkd_derive_key,
};
use crate::call::{Call, CallFailed, CallResult, CandidDecodeFailed};
use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize};

// Re-export types from the `ic-management-canister-types` crate.
pub use ic_management_canister_types::{
    Bip341, CanisterId, CanisterIdRecord, CanisterInfoArgs, CanisterInfoResult,
    CanisterInstallMode, CanisterMetadataArgs, CanisterMetadataResult, CanisterSettings,
    CanisterStatusArgs, CanisterStatusResult, CanisterStatusType, CanisterTimer, Change,
    ChangeDetails, ChangeOrigin, ChunkHash, ClearChunkStoreArgs, CodeDeploymentMode,
    CodeDeploymentRecord, ControllersChangeRecord, CreateCanisterResult, CreationRecord,
    DefiniteCanisterSettings, DeleteCanisterArgs, DeleteCanisterSnapshotArgs, DepositCyclesArgs,
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, EcdsaPublicKeyResult, EnvironmentVariable,
    FromCanisterRecord, FromUserRecord, HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult,
    ListCanisterSnapshotsArgs, ListCanisterSnapshotsResult, LoadSnapshotRecord, LogVisibility,
    MemoryMetrics, NodeMetrics, NodeMetricsHistoryArgs, NodeMetricsHistoryRecord,
    NodeMetricsHistoryResult, OnLowWasmMemoryHookStatus, ProvisionalCreateCanisterWithCyclesResult,
    ProvisionalTopUpCanisterArgs, QueryStats, RawRandResult, ReadCanisterSnapshotDataArgs,
    ReadCanisterSnapshotDataResult, ReadCanisterSnapshotMetadataArgs,
    ReadCanisterSnapshotMetadataResult, SchnorrAlgorithm, SchnorrAux, SchnorrKeyId,
    SchnorrPublicKeyArgs, SchnorrPublicKeyResult, SignWithEcdsaArgs, SignWithEcdsaResult,
    SignWithSchnorrArgs, SignWithSchnorrResult, Snapshot, SnapshotDataKind, SnapshotDataOffset,
    SnapshotId, SnapshotMetadataGlobal, SnapshotSource, StartCanisterArgs, StopCanisterArgs,
    StoredChunksArgs, StoredChunksResult, SubnetInfoArgs, SubnetInfoResult,
    TakeCanisterSnapshotArgs, TakeCanisterSnapshotResult, TransformArgs, TransformContext,
    TransformFunc, UpgradeFlags, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadCanisterSnapshotMetadataResult, UploadChunkArgs,
    UploadChunkResult, VetKDCurve, VetKDDeriveKeyArgs, VetKDDeriveKeyResult, VetKDKeyId,
    VetKDPublicKeyArgs, VetKDPublicKeyResult, WasmMemoryPersistence, WasmModule,
};

// Following Args types contain `sender_canister_version` field which is set automatically in the corresponding functions.
// We provide reduced versions of these types to avoid duplication of the field.
use ic_management_canister_types::{
    CreateCanisterArgs as CreateCanisterArgsComplete,
    InstallChunkedCodeArgs as InstallChunkedCodeArgsComplete,
    InstallCodeArgs as InstallCodeArgsComplete,
    LoadCanisterSnapshotArgs as LoadCanisterSnapshotArgsComplete,
    ProvisionalCreateCanisterWithCyclesArgs as ProvisionalCreateCanisterWithCyclesArgsComplete,
    UninstallCodeArgs as UninstallCodeArgsComplete,
    UpdateSettingsArgs as UpdateSettingsArgsComplete,
};

/// The error type for the [`sign_with_ecdsa`] and [`sign_with_schnorr`] functions.
#[derive(thiserror::Error, Debug, Clone)]
pub enum SignCallError {
    /// The signature cost calculation failed.
    #[error(transparent)]
    SignCostError(#[from] SignCostError),
    /// Failed to make the inter-canister call to the management canister.
    #[error(transparent)]
    CallFailed(#[from] CallFailed),
    /// Failed to decode the response from the management canister.
    #[error(transparent)]
    CandidDecodeFailed(#[from] CandidDecodeFailed),
}

/// Creates a new canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `create_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister).
///
/// # Note
///
/// Canister creation costs cycles. That amount will be deducted from the newly created canister.
/// This method will only attach the required cycles for the canister creation (detemined by [`cost_create_canister`]).
/// The new canister will have a 0 cycle balance.
///
/// To ensure the new canister has extra cycles after creation, use [`create_canister_with_extra_cycles`] instead.
///
/// Cycles can also be deposited to the new canister using [`deposit_cycles`].
///
/// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost#canister-creation) for more details.
pub async fn create_canister(arg: &CreateCanisterArgs) -> CallResult<CreateCanisterResult> {
    let complete_arg = CreateCanisterArgsComplete {
        settings: arg.settings.clone(),
        sender_canister_version: Some(canister_version()),
    };
    let cycles = cost_create_canister();
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "create_canister")
            .with_arg(&complete_arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Creates a new canister with extra cycles.
///
/// **Unbounded-wait call**
///
/// See [IC method `create_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister).
///
/// # Note
///
/// Canister creation costs cycles. That amount will be deducted from the newly created canister.
/// This method will attach the required cycles for the canister creation (detemined by [`cost_create_canister`]) plus the `extra_cycles` to the call.
/// The new cansiter will have a cycle balance of `extra_cycles`.
///
/// To simply create a canister with 0 cycle balance, use [`create_canister`] instead.
///
/// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost#canister-creation) for more details.
pub async fn create_canister_with_extra_cycles(
    arg: &CreateCanisterArgs,
    extra_cycles: u128,
) -> CallResult<CreateCanisterResult> {
    let complete_arg = CreateCanisterArgsComplete {
        settings: arg.settings.clone(),
        sender_canister_version: Some(canister_version()),
    };
    let cycles = cost_create_canister() + extra_cycles;
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "create_canister")
            .with_arg(&complete_arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Argument type of [`create_canister`] and [`create_canister_with_extra_cycles`].
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::CreateCanisterArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`create_canister`] and [`create_canister_with_extra_cycles`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct CreateCanisterArgs {
    /// See [`CanisterSettings`].
    pub settings: Option<CanisterSettings>,
}

/// Updates the settings of a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `update_settings`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-update_settings).
pub async fn update_settings(arg: &UpdateSettingsArgs) -> CallResult<()> {
    let complete_arg = UpdateSettingsArgsComplete {
        canister_id: arg.canister_id,
        settings: arg.settings.clone(),
        sender_canister_version: Some(canister_version()),
    };
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "update_settings")
            .with_arg(&complete_arg)
            .await?
            .candid()?,
    )
}

/// Argument type of [`update_settings`]
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::UpdateSettingsArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`update_settings`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UpdateSettingsArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// See [`CanisterSettings`].
    pub settings: CanisterSettings,
}

/// Uploads a chunk to the chunk store of a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `upload_chunk`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-upload_chunk).
pub async fn upload_chunk(arg: &UploadChunkArgs) -> CallResult<UploadChunkResult> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "upload_chunk")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Clears the chunk store of a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `clear_chunk_store`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-clear_chunk_store).
pub async fn clear_chunk_store(arg: &ClearChunkStoreArgs) -> CallResult<()> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "clear_chunk_store")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Gets the hashes of all chunks stored in the chunk store of a canister.
///
/// **Bounded-wait call**
///
/// See [IC method `stored_chunks`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-stored_chunks).
pub async fn stored_chunks(arg: &StoredChunksArgs) -> CallResult<StoredChunksResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "stored_chunks")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Installs code into a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `install_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code).
pub async fn install_code(arg: &InstallCodeArgs) -> CallResult<()> {
    let complete_arg = InstallCodeArgsComplete {
        mode: arg.mode,
        canister_id: arg.canister_id,
        wasm_module: arg.wasm_module.clone(),
        arg: arg.arg.clone(),
        sender_canister_version: Some(canister_version()),
    };
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "install_code")
            .with_arg(&complete_arg)
            .await?
            .candid()?,
    )
}

/// Argument type of [`install_code`].
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::InstallCodeArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`install_code`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct InstallCodeArgs {
    /// See [`CanisterInstallMode`].
    pub mode: CanisterInstallMode,
    /// Canister ID.
    pub canister_id: CanisterId,
    /// Code to be installed.
    pub wasm_module: WasmModule,
    /// The argument to be passed to `canister_init` or `canister_post_upgrade`.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
}

/// Installs code into a canister where the code has previously been uploaded in chunks.
///
/// **Unbounded-wait call**
///
/// See [IC method `install_chunked_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_chunked_code).
pub async fn install_chunked_code(arg: &InstallChunkedCodeArgs) -> CallResult<()> {
    let complete_arg = InstallChunkedCodeArgsComplete {
        mode: arg.mode,
        target_canister: arg.target_canister,
        store_canister: arg.store_canister,
        chunk_hashes_list: arg.chunk_hashes_list.clone(),
        wasm_module_hash: arg.wasm_module_hash.clone(),
        arg: arg.arg.clone(),
        sender_canister_version: Some(canister_version()),
    };
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "install_chunked_code")
            .with_arg(&complete_arg)
            .await?
            .candid()?,
    )
}

/// Argument type of [`install_chunked_code`].
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::InstallChunkedCodeArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`install_chunked_code`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct InstallChunkedCodeArgs {
    /// See [`CanisterInstallMode`].
    pub mode: CanisterInstallMode,
    /// Principal of the canister being installed.
    pub target_canister: CanisterId,
    /// The canister in whose chunk storage the chunks are stored (defaults to `target_canister` if not specified).
    pub store_canister: Option<CanisterId>,
    /// The list of chunks that make up the canister wasm.
    pub chunk_hashes_list: Vec<ChunkHash>,
    /// The sha256 hash of the wasm.
    #[serde(with = "serde_bytes")]
    pub wasm_module_hash: Vec<u8>,
    /// The argument to be passed to `canister_init` or `canister_post_upgrade`.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
}

/// Removes a canister's code and state, making the canister empty again.
///
/// **Unbounded-wait call**
///
/// See [IC method `uninstall_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-uninstall_code).
pub async fn uninstall_code(arg: &UninstallCodeArgs) -> CallResult<()> {
    let complete_arg = UninstallCodeArgsComplete {
        canister_id: arg.canister_id,
        sender_canister_version: Some(canister_version()),
    };
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "uninstall_code")
            .with_arg(&complete_arg)
            .await?
            .candid()?,
    )
}

/// Argument type of [`uninstall_code`].
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::UninstallCodeArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`uninstall_code`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UninstallCodeArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

/// Starts a canister if the canister status was `stopped` or `stopping`.
///
/// **Unbounded-wait call**
///
/// See [IC method `start_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-start_canister).
pub async fn start_canister(arg: &StartCanisterArgs) -> CallResult<()> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "start_canister")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Stops a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `stop_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-stop_canister).
pub async fn stop_canister(arg: &StopCanisterArgs) -> CallResult<()> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "stop_canister")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Gets status information about the canister.
///
/// **Bounded-wait call**
///
/// See [IC method `canister_status`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_status).
pub async fn canister_status(arg: &CanisterStatusArgs) -> CallResult<CanisterStatusResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "canister_status")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Gets public information about the canister.
///
/// **Bounded-wait call**
///
/// See [IC method `canister_info`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_info).
pub async fn canister_info(arg: &CanisterInfoArgs) -> CallResult<CanisterInfoResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "canister_info")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}
/// Gets canister's metadata contained in custom sections whose names have the form `icp:public <name>` or `icp:private <name>`
///
/// **Bounded-wait call**
///
/// See [IC method `canister_metadata`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_metadata).
pub async fn canister_metadata(arg: &CanisterMetadataArgs) -> CallResult<CanisterMetadataResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "canister_metadata")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Deletes a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `delete_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-delete_canister).
pub async fn delete_canister(arg: &DeleteCanisterArgs) -> CallResult<()> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "delete_canister")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Deposits cycles to a canister.
///
/// **Unbounded-wait call**
///
/// See [IC method `deposit_cycles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-deposit_cycles).
pub async fn deposit_cycles(arg: &DepositCyclesArgs, cycles: u128) -> CallResult<()> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "deposit_cycles")
            .with_arg(arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Gets 32 pseudo-random bytes.
///
/// **Bounded-wait call**
///
/// See [IC method `raw_rand`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-raw_rand).
pub async fn raw_rand() -> CallResult<RawRandResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "raw_rand")
            .await?
            .candid()?,
    )
}

/// Calculates the cost of making an HTTP outcall with the given [`HttpRequestArgs`].
///
/// [`http_request`] and [`http_request_with_closure`] invoke this method internally and attach the required cycles to the call.
///
/// # Note
///
/// Alternatively, [`api::cost_http_request`][ic0_cost_http_request] requires manually calculating the request size and the maximum response size.
/// This method handles the calculation internally.
pub fn cost_http_request(arg: &HttpRequestArgs) -> u128 {
    let request_size = (arg.url.len()
        + arg
            .headers
            .iter()
            .map(|h| h.name.len() + h.value.len())
            .sum::<usize>()
        + arg.body.as_ref().map_or(0, |b| b.len())
        + arg
            .transform
            .as_ref()
            .map_or(0, |t| t.context.len() + t.function.0.method.len()))
        as u64;
    // As stated here: https://internetcomputer.org/docs/references/ic-interface-spec#ic-http_request:
    // "The upper limit on the maximal size for the response is 2MB (2,000,000B) and this value also applies if no maximal size value is specified."
    let max_res_bytes = arg.max_response_bytes.unwrap_or(2_000_000);
    ic0_cost_http_request(request_size, max_res_bytes)
}

/// Makes an HTTP outcall.
///
/// **Unbounded-wait call**
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
///
/// # Note
///
/// HTTP outcall costs cycles which varies with the request size and the maximum response size.
/// This method attaches the required cycles (detemined by [`cost_http_request`]) to the call.
///
/// Check [HTTPS outcalls cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost#https-outcalls) for more details.
pub async fn http_request(arg: &HttpRequestArgs) -> CallResult<HttpRequestResult> {
    let cycles = cost_http_request(arg);
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "http_request")
            .with_arg(arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Constructs a [`TransformContext`] from a query method name and context.
pub fn transform_context_from_query(
    candid_function_name: String,
    context: Vec<u8>,
) -> TransformContext {
    TransformContext {
        context,
        function: TransformFunc(candid::Func {
            method: candid_function_name,
            principal: crate::api::canister_self(),
        }),
    }
}

#[cfg(feature = "transform-closure")]
mod transform_closure {
    use super::{
        CallResult, HttpRequestArgs, HttpRequestResult, Principal, TransformArgs, http_request,
        transform_context_from_query,
    };
    use candid::{decode_one, encode_one};
    use slotmap::{DefaultKey, Key, KeyData, SlotMap};
    use std::cell::RefCell;

    thread_local! {
        #[allow(clippy::type_complexity)]
        static TRANSFORMS: RefCell<SlotMap<DefaultKey, Box<dyn FnOnce(HttpRequestResult) -> HttpRequestResult>>> = RefCell::default();
    }

    #[cfg_attr(
        target_family = "wasm",
        unsafe(export_name = "canister_query <ic-cdk internal> http_transform")
    )]
    #[cfg_attr(
        not(target_family = "wasm"),
        unsafe(export_name = "canister_query_ic_cdk_internal.http_transform")
    )]
    extern "C" fn http_transform() {
        ic_cdk_executor::in_tracking_query_executor_context(|| {
            use crate::api::{msg_arg_data, msg_caller, msg_reply};
            if msg_caller() != Principal::management_canister() {
                crate::trap(
                    "This function is internal to ic-cdk and should not be called externally.",
                );
            }
            let arg_bytes = msg_arg_data();
            let transform_args: TransformArgs = decode_one(&arg_bytes).unwrap();
            let int = u64::from_be_bytes(transform_args.context[..].try_into().unwrap());
            let key = DefaultKey::from(KeyData::from_ffi(int));
            let func = TRANSFORMS.with(|transforms| transforms.borrow_mut().remove(key));
            let Some(func) = func else {
                crate::trap(format!("Missing transform function for request {int}"));
            };
            let transformed = func(transform_args.response);
            let encoded = encode_one(transformed).unwrap();
            msg_reply(encoded);
        });
    }

    /// Makes an HTTP outcall and transforms the response using a closure.
    ///
    /// **Unbounded-wait call**
    ///
    /// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
    ///
    /// # Panics
    ///
    /// This method will panic if the `transform` field in `arg` is not `None`,
    /// as it would conflict with the transform function provided by the closure.
    ///
    /// # Note
    ///
    /// This method provides a straightforward way to transform the HTTP outcall result.
    /// If you need to specify a custom transform [`context`](`ic_management_canister_types::TransformContext::context`),
    /// please use [`http_request`] instead.
    ///
    /// HTTP outcall costs cycles which varies with the request size and the maximum response size.
    /// This method attaches the required cycles (detemined by [`cost_http_request`](crate::api::cost_http_request)) to the call.
    ///
    /// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost) for more details.
    #[cfg_attr(docsrs, doc(cfg(feature = "transform-closure")))]
    pub async fn http_request_with_closure(
        arg: &HttpRequestArgs,
        transform_func: impl FnOnce(HttpRequestResult) -> HttpRequestResult + 'static,
    ) -> CallResult<HttpRequestResult> {
        assert!(
            arg.transform.is_none(),
            "The `transform` field in `HttpRequestArgs` must be `None` when using a closure"
        );
        let transform_func = Box::new(transform_func) as _;
        let key = TRANSFORMS.with(|transforms| transforms.borrow_mut().insert(transform_func));
        struct DropGuard(DefaultKey);
        impl Drop for DropGuard {
            fn drop(&mut self) {
                TRANSFORMS.with(|transforms| transforms.borrow_mut().remove(self.0));
            }
        }
        let key = DropGuard(key);
        let context = key.0.data().as_ffi().to_be_bytes().to_vec();
        let arg = HttpRequestArgs {
            transform: Some(transform_context_from_query(
                "<ic-cdk internal> http_transform".to_string(),
                context,
            )),
            ..arg.clone()
        };
        http_request(&arg).await
    }
}

#[cfg(feature = "transform-closure")]
pub use transform_closure::http_request_with_closure;

/// Gets a SEC1 encoded ECDSA public key for the given canister using the given derivation path.
///
/// **Bounded-wait call**
///
/// See [IC method `ecdsa_public_key`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-ecdsa_public_key).
pub async fn ecdsa_public_key(arg: &EcdsaPublicKeyArgs) -> CallResult<EcdsaPublicKeyResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "ecdsa_public_key")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Calculates the cost of ECDSA signanature with the given [`SignWithEcdsaArgs`].
///
/// [`sign_with_ecdsa`] invokes this method internally and attaches the required cycles to the call.
///
/// # Note
///
/// Alternatively, [`api::cost_sign_with_ecdsa`][ic0_cost_sign_with_ecdsa] takes the numeric representation of the curve.
pub fn cost_sign_with_ecdsa(arg: &SignWithEcdsaArgs) -> Result<u128, SignCostError> {
    ic0_cost_sign_with_ecdsa(&arg.key_id.name, arg.key_id.curve.into())
}

/// Gets a new ECDSA signature of the given `message_hash` with a user-specified amount of cycles.
///
/// **Unbounded-wait call**
///
/// The signature can be separately verified against a derived ECDSA public key.
///
/// See [IC method `sign_with_ecdsa`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-sign_with_ecdsa).
///
/// # Errors
///
/// This method returns an error of type [`SignCallError`].
///
/// The signature cost calculation may fail before the inter-canister call is made, resulting in a [`SignCallError::SignCostError`].
///
/// Since the call argument is constructed as [`SignWithEcdsaArgs`], the `ecdsa_curve` field is guaranteed to be valid.
/// Therefore, [`SignCostError::InvalidCurveOrAlgorithm`] should not occur. If it does, it is likely an issue with the IC. Please report it.
///
/// # Note
///
/// Signature costs cycles which varies for different curves and key names.
/// This method attaches the required cycles (detemined by [`cost_sign_with_ecdsa`]) to the call.
///
/// Check [Threshold signatures](https://internetcomputer.org/docs/current/references/t-sigs-how-it-works/#api-fees) for more details.
pub async fn sign_with_ecdsa(
    arg: &SignWithEcdsaArgs,
) -> Result<SignWithEcdsaResult, SignCallError> {
    let cycles = cost_sign_with_ecdsa(arg)?;
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "sign_with_ecdsa")
            .with_arg(arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Gets a SEC1 encoded Schnorr public key for the given canister using the given derivation path.
///
/// **Bounded-wait call**
///
/// See [IC method `schnorr_public_key`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-schnorr_public_key).
pub async fn schnorr_public_key(arg: &SchnorrPublicKeyArgs) -> CallResult<SchnorrPublicKeyResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "schnorr_public_key")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Calculates the cost of Schnorr signanature with the given [`SignWithSchnorrArgs`].
///
/// [`sign_with_schnorr`] invokes this method internally and attaches the required cycles to the call.
///
/// # Note
///
/// Alternatively, [`api::cost_sign_with_schnorr`][ic0_cost_sign_with_schnorr] takes the numeric representation of the algorithm.
pub fn cost_sign_with_schnorr(arg: &SignWithSchnorrArgs) -> Result<u128, SignCostError> {
    ic0_cost_sign_with_schnorr(&arg.key_id.name, arg.key_id.algorithm.into())
}

/// Gets a new Schnorr signature of the given message with a user-specified amount of cycles.
///
/// **Unbounded-wait call**
///
/// The signature can be separately verified against a derived Schnorr public key.
///
/// See [IC method `sign_with_schnorr`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-sign_with_schnorr).
///
/// # Errors
///
/// This method returns an error of type [`SignCallError`].
///
/// The signature cost calculation may fail before the inter-canister call is made, resulting in a [`SignCallError::SignCostError`].
///
/// Since the call argument is constructed as [`SignWithSchnorrArgs`], the `algorithm` field is guaranteed to be valid.
/// Therefore, [`SignCostError::InvalidCurveOrAlgorithm`] should not occur. If it does, it is likely an issue with the IC. Please report it.
///
/// # Note
///
/// Signature costs cycles which varies for different algorithms and key names.
/// This method attaches the required cycles (detemined by [`cost_sign_with_schnorr`]) to the call.
///
/// Check [Threshold signatures](https://internetcomputer.org/docs/current/references/t-sigs-how-it-works/#api-fees) for more details.
pub async fn sign_with_schnorr(
    arg: &SignWithSchnorrArgs,
) -> Result<SignWithSchnorrResult, SignCallError> {
    let cycles = cost_sign_with_schnorr(arg)?;
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "sign_with_schnorr")
            .with_arg(arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Gets a VetKD public key.
///
/// **Bounded-wait call**
///
/// As of 2025-05-01, the vetKD feature is not yet available on the IC mainnet.
/// The lastest PocketIC with the `with_nonmainnet_features(true)` flag can be used to test it.
///
/// See [IC method `vetkd_public_key`](https://github.com/dfinity/portal/pull/3763).
///
/// Later, the description will be available in [the interface spec](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-vetkd_public_key).
pub async fn vetkd_public_key(arg: &VetKDPublicKeyArgs) -> CallResult<VetKDPublicKeyResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "vetkd_public_key")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Calculates the cost of VetKD key derivation with the given [`VetKDDeriveKeyArgs`].
///
/// [`vetkd_derive_key`] invokes this method internally and attaches the required cycles to the call.
///
/// # Note
///
/// Alternatively, [`api::cost_vetkd_derive_key`][ic0_cost_vetkd_derive_key] takes the numeric representation of the algorithm.
pub fn cost_vetkd_derive_key(arg: &VetKDDeriveKeyArgs) -> Result<u128, SignCostError> {
    ic0_cost_vetkd_derive_key(&arg.key_id.name, arg.key_id.curve.into())
}

/// Derives a key from the given input.
///
/// **Unbounded-wait call**
///
/// The returned encrypted key can be separately decrypted using the private secret key corresponding to the transport public key provided in the request, and the derivation correctness can be verified against the input and context provided in the request. See the [`ic_vetkeys` frontend library](https://github.com/dfinity/vetkd-devkit/tree/main/frontend/ic_vetkeys) for more details.
///
/// As of 2025-05-01, the vetKD feature is not yet available on the IC mainnet.
/// The lastest PocketIC with the `with_nonmainnet_features(true)` flag can be used to test it.
///
/// See [IC method `vetkd_derive_key`](https://github.com/dfinity/portal/pull/3763) for the API specification.
///
/// Later, the description will be available in [the interface spec](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-vetkd_derive_key).
///
/// # Errors
///
/// This method returns an error of type [`SignCallError`].
///
/// The signature cost calculation may fail before the inter-canister call is made, resulting in a [`SignCallError::SignCostError`].
///
/// Since the call argument is constructed as [`VetKDDeriveKeyArgs`], the `curve` field is guaranteed to be valid.
/// Therefore, [`SignCostError::InvalidCurveOrAlgorithm`] should not occur. If it does, it is likely an issue with the IC. Please report it.
///
/// # Note
///
/// VetKD key derivation costs cycles which varies for different algorithms and key names.
/// This method attaches the required cycles (detemined by [`cost_vetkd_derive_key`]) to the call.
///
/// Check [Threshold signatures](https://internetcomputer.org/docs/current/references/t-sigs-how-it-works/#api-fees) for more details.
pub async fn vetkd_derive_key(
    arg: &VetKDDeriveKeyArgs,
) -> Result<VetKDDeriveKeyResult, SignCallError> {
    let cycles = cost_vetkd_derive_key(arg)?;
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "vetkd_derive_key")
            .with_arg(arg)
            .with_cycles(cycles)
            .await?
            .candid()?,
    )
}

/// Gets a time series of subnet's node metrics.
///
/// **Bounded-wait call**
///
/// See [IC method `node_metrics_history`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-node_metrics_history).
pub async fn node_metrics_history(
    arg: &NodeMetricsHistoryArgs,
) -> CallResult<NodeMetricsHistoryResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "node_metrics_history")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Gets the metadata about a subnet.
///
/// **Bounded-wait call**
///
/// See [IC method `subnet_info`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-subnet_info).
pub async fn subnet_info(arg: &SubnetInfoArgs) -> CallResult<SubnetInfoResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "subnet_info")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Creates a new canister with specified amount of cycles balance.
///
/// **Unbounded-wait call**
///
/// # Note
///
/// This method is only available in local development instances.
///
/// See [IC method `provisional_create_canister_with_cycles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-provisional_create_canister_with_cycles).
pub async fn provisional_create_canister_with_cycles(
    arg: &ProvisionalCreateCanisterWithCyclesArgs,
) -> CallResult<ProvisionalCreateCanisterWithCyclesResult> {
    let complete_arg = ProvisionalCreateCanisterWithCyclesArgsComplete {
        amount: arg.amount.clone(),
        settings: arg.settings.clone(),
        specified_id: arg.specified_id,
        sender_canister_version: Some(canister_version()),
    };
    Ok(Call::unbounded_wait(
        Principal::management_canister(),
        "provisional_create_canister_with_cycles",
    )
    .with_arg(&complete_arg)
    .await?
    .candid()?)
}

/// Argument type of [`provisional_create_canister_with_cycles`].
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::ProvisionalCreateCanisterWithCyclesArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`provisional_create_canister_with_cycles`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    /// The created canister will have this amount of cycles.
    pub amount: Option<Nat>,
    /// Canister settings.
    pub settings: Option<CanisterSettings>,
    /// If set, the canister will be created under this id.
    pub specified_id: Option<CanisterId>,
}

/// Adds cycles to a canister.
///
/// **Unbounded-wait call**
///
/// # Note
///
/// This method is only available in local development instances.
///
/// See [IC method `provisional_top_up_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-provisional_top_up_canister).
pub async fn provisional_top_up_canister(arg: &ProvisionalTopUpCanisterArgs) -> CallResult<()> {
    Ok(Call::unbounded_wait(
        Principal::management_canister(),
        "provisional_top_up_canister",
    )
    .with_arg(arg)
    .await?
    .candid()?)
}

/// Takes a snapshot of the specified canister.
///
/// **Unbounded-wait call**
///
/// A snapshot consists of the wasm memory, stable memory, certified variables, wasm chunk store and wasm binary.
///
/// See [IC method `take_canister_snapshot`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-take_canister_snapshot).
pub async fn take_canister_snapshot(
    arg: &TakeCanisterSnapshotArgs,
) -> CallResult<TakeCanisterSnapshotResult> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "take_canister_snapshot")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Loads a snapshot onto the canister.
///
/// **Unbounded-wait call**
///
/// It fails if no snapshot with the specified `snapshot_id` can be found.
///
/// See [IC method `load_canister_snapshot`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-load_canister_snapshot).
pub async fn load_canister_snapshot(arg: &LoadCanisterSnapshotArgs) -> CallResult<()> {
    let complete_arg = LoadCanisterSnapshotArgsComplete {
        canister_id: arg.canister_id,
        snapshot_id: arg.snapshot_id.clone(),
        sender_canister_version: Some(canister_version()),
    };
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "load_canister_snapshot")
            .with_arg(&complete_arg)
            .await?
            .candid()?,
    )
}

/// Argument type of [`load_canister_snapshot`].
///
/// # Note
///
/// This type is a reduced version of [`ic_management_canister_types::LoadCanisterSnapshotArgs`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`load_canister_snapshot`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct LoadCanisterSnapshotArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// ID of the snapshot to be loaded.
    pub snapshot_id: SnapshotId,
}

/// Reads metadata of a snapshot of a canister.
///
/// **Bounded-wait call**
///
/// See [IC method `read_canister_snapshot_metadata`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-read_canister_snapshot_metadata).
pub async fn read_canister_snapshot_metadata(
    arg: &ReadCanisterSnapshotMetadataArgs,
) -> CallResult<ReadCanisterSnapshotMetadataResult> {
    Ok(Call::bounded_wait(
        Principal::management_canister(),
        "read_canister_snapshot_metadata",
    )
    .with_arg(arg)
    .await?
    .candid()?)
}

/// Reads data of a snapshot of a canister.
///
/// **Bounded-wait call**
///
/// See [IC method `read_canister_snapshot_data`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-read_canister_snapshot_data).
pub async fn read_canister_snapshot_data(
    arg: &ReadCanisterSnapshotDataArgs,
) -> CallResult<ReadCanisterSnapshotDataResult> {
    Ok(Call::bounded_wait(
        Principal::management_canister(),
        "read_canister_snapshot_data",
    )
    .with_arg(arg)
    .await?
    .candid()?)
}

/// Creates a snapshot of that canister by uploading the snapshot's metadata.
///
/// **Bounded-wait call**
///
/// See [IC method `upload_canister_snapshot_metadata`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-upload_canister_snapshot_metadata).
pub async fn upload_canister_snapshot_metadata(
    arg: &UploadCanisterSnapshotMetadataArgs,
) -> CallResult<UploadCanisterSnapshotMetadataResult> {
    Ok(Call::bounded_wait(
        Principal::management_canister(),
        "upload_canister_snapshot_metadata",
    )
    .with_arg(arg)
    .await?
    .candid()?)
}

/// Uploads data to a snapshot of that canister.
///
/// **Bounded-wait call**
///
/// See [IC method `upload_canister_snapshot_data`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-upload_canister_snapshot_data).
pub async fn upload_canister_snapshot_data(arg: &UploadCanisterSnapshotDataArgs) -> CallResult<()> {
    Ok(Call::bounded_wait(
        Principal::management_canister(),
        "upload_canister_snapshot_data",
    )
    .with_arg(arg)
    .await?
    .candid()?)
}

/// Lists the snapshots of the canister.
///
/// **Bounded-wait call**
///
/// See [IC method `list_canister_snapshots`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-list_canister_snapshots).
pub async fn list_canister_snapshots(
    arg: &ListCanisterSnapshotsArgs,
) -> CallResult<ListCanisterSnapshotsResult> {
    Ok(
        Call::bounded_wait(Principal::management_canister(), "list_canister_snapshots")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}

/// Deletes a specified snapshot that belongs to an existing canister.
///
/// **Unbounded-wait call**
///
/// An error will be returned if the snapshot is not found.
///
/// See [IC method `delete_canister_snapshot`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-delete_canister_snapshot).
pub async fn delete_canister_snapshot(arg: &DeleteCanisterSnapshotArgs) -> CallResult<()> {
    Ok(
        Call::unbounded_wait(Principal::management_canister(), "delete_canister_snapshot")
            .with_arg(arg)
            .await?
            .candid()?,
    )
}
