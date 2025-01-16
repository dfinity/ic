//! Functions and types for calling [the IC management canister][1].
//!
//! This module is a direct translation from its Candid interface description.
//!
//! The functions and types defined in this module serves these purposes:
//! * Make it easy to construct correct request data.
//! * Handle the response ergonomically.
//! * For those calls require cycles payments, the cycles amount is an explicit argument.
//!
//! [1]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister

use crate::api::canister_version;
use crate::call::{Call, CallResult, ConfigurableCall, SendableCall};
use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize};

/// Canister ID.
pub type CanisterId = Principal;

/// Chunk hash.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ChunkHash {
    /// The hash of an uploaded chunk
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

/// Log Visibility.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub enum LogVisibility {
    /// Controllers.
    #[default]
    #[serde(rename = "controllers")]
    Controllers,
    /// Public.
    #[serde(rename = "public")]
    Public,
    /// Allowed viewers.
    #[serde(rename = "allowed_viewers")]
    AllowedViewers(Vec<Principal>),
}

/// Canister settings.
///
/// The settings are optional. If they are not explicitly set, the default values will be applied automatically.
///
/// See [`settings`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct CanisterSettings {
    /// A list of at most 10 principals.
    ///
    /// The principals in this list become the *controllers* of the canister.
    ///
    /// Default value: A list containing only the caller of the create_canister call.
    pub controllers: Option<Vec<Principal>>,
    /// Must be a number between 0 and 100, inclusively.
    ///
    /// It indicates how much compute power should be guaranteed to this canister,
    /// expressed as a percentage of the maximum compute power that a single canister can allocate.
    ///
    /// If the IC cannot provide the requested allocation,
    /// for example because it is oversubscribed, the call will be **rejected**.
    ///
    /// Default value: 0
    pub compute_allocation: Option<Nat>,
    /// Must be a number between 0 and 2<sup>48</sup> (i.e 256TB), inclusively.
    ///
    /// It indicates how much memory the canister is allowed to use in total.
    ///
    /// If the IC cannot provide the requested allocation,
    /// for example because it is oversubscribed, the call will be **rejected**.
    ///
    /// If set to 0, then memory growth of the canister will be best-effort and subject to the available memory on the IC.
    ///
    /// Default value: 0
    pub memory_allocation: Option<Nat>,
    /// Must be a number between 0 and 2<sup>64</sup>-1, inclusively.
    ///
    /// It indicates a length of time in seconds.
    ///
    /// Default value: 2592000 (approximately 30 days).
    pub freezing_threshold: Option<Nat>,
    /// Must be a number between 0 and 2<sup>128</sup>-1, inclusively.
    ///
    /// It indicates the upper limit on `reserved_cycles` of the canister.
    ///
    /// Default value: 5_000_000_000_000 (5 trillion cycles).
    pub reserved_cycles_limit: Option<Nat>,
    /// Defines who is allowed to read the canister's logs.
    ///
    /// Default value: Controllers
    pub log_visibility: Option<LogVisibility>,
    /// Must be a number between 0 and 2<sup>48</sup>-1 (i.e 256TB), inclusively.
    ///
    /// It indicates the upper limit on the WASM heap memory consumption of the canister.
    ///
    /// Default value: 3_221_225_472 (3 GiB).
    pub wasm_memory_limit: Option<Nat>,
}

/// Like [`CanisterSettings`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct DefiniteCanisterSettings {
    /// Controllers of the canister.
    pub controllers: Vec<Principal>,
    /// Compute allocation.
    pub compute_allocation: Nat,
    /// Memory allocation.
    pub memory_allocation: Nat,
    /// Freezing threshold.
    pub freezing_threshold: Nat,
    /// Reserved cycles limit.
    pub reserved_cycles_limit: Nat,
    /// Visibility of canister logs.
    pub log_visibility: LogVisibility,
    /// The Wasm memory limit.
    pub wasm_memory_limit: Nat,
}

// create_canister ------------------------------------------------------------

/// Register a new canister and get its canister id.
///
/// See [IC method `create_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-create_canister).
///
/// This call requires cycles payment. The required cycles varies according to the subnet size (number of nodes).
/// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost) for more details.
pub async fn create_canister(
    arg: CreateCanisterArgs,
    cycles: u128,
) -> CallResult<CreateCanisterResult> {
    let complete_arg = CreateCanisterArgsComplete {
        settings: arg.settings,
        sender_canister_version: Some(canister_version()),
    };
    Call::new(Principal::management_canister(), "create_canister")
        .with_arg(complete_arg)
        .with_guaranteed_response()
        .with_cycles(cycles)
        .call()
        .await
}

/// Argument type of [`create_canister`].
///
/// Please note that this type is a reduced version of [`CreateCanisterArgsComplete`].
/// The `sender_canister_version` field is removed as it is set automatically in [`create_canister`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct CreateCanisterArgs {
    /// See [`CanisterSettings`].
    pub settings: Option<CanisterSettings>,
}

/// Complete argument type of `create_canister`.
///
/// Please note that this type is not used directly as the argument of [`create_canister`].
/// The function [`create_canister`] takes [`CreateCanisterArgs`] instead.
///
/// If you want to manually call `create_canister` (construct and invoke a [`Call`]), you should use this complete type.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct CreateCanisterArgsComplete {
    /// See [`CanisterSettings`].
    pub settings: Option<CanisterSettings>,
    /// sender_canister_version must be set to [`canister_version`].
    pub sender_canister_version: Option<u64>,
}

/// Result type of [`create_canister`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
pub struct CreateCanisterResult {
    /// Canister ID.
    pub canister_id: CanisterId,
}

// create_canister END --------------------------------------------------------

// update_settings ------------------------------------------------------------

/// Update the settings of a canister.
///
/// See [IC method `update_settings`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-update_settings).
pub async fn update_settings(arg: UpdateSettingsArgs) -> CallResult<()> {
    let complete_arg = UpdateSettingsArgsComplete {
        canister_id: arg.canister_id,
        settings: arg.settings,
        sender_canister_version: Some(canister_version()),
    };
    Call::new(Principal::management_canister(), "update_settings")
        .with_arg(complete_arg)
        .call()
        .await
}

/// Argument type of [`update_settings`]
///
/// Please note that this type is a reduced version of [`UpdateSettingsArgsComplete`].
///
/// The `sender_canister_version` field is removed as it is set automatically in [`update_settings`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UpdateSettingsArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// See [CanisterSettings].
    pub settings: CanisterSettings,
}

/// Complete argument type of `update_settings`.
///
/// Please note that this type is not used directly as the argument of [`update_settings`].
/// The function [`update_settings`] takes [`UpdateSettingsArgs`] instead.
///
/// If you want to manually call `update_settings` (construct and invoke a [Call]), you should use this complete type.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UpdateSettingsArgsComplete {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// See [CanisterSettings].
    pub settings: CanisterSettings,
    /// sender_canister_version must be set to [`canister_version`].
    pub sender_canister_version: Option<u64>,
}

// update_settings END --------------------------------------------------------

// upload_chunk ---------------------------------------------------------------

/// Upload a chunk to the chunk store of a canister.
///
/// See [IC method `upload_chunk`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-upload_chunk).
pub async fn upload_chunk(arg: UploadChunkArgs) -> CallResult<UploadChunkResult> {
    Call::new(Principal::management_canister(), "upload_chunk")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`upload_chunk`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UploadChunkArgs {
    /// The canister whose chunk store the chunk will be uploaded to.
    pub canister_id: CanisterId,
    /// The chunk bytes (max size 1MB).
    #[serde(with = "serde_bytes")]
    pub chunk: Vec<u8>,
}

/// Result type of [`upload_chunk`].
pub type UploadChunkResult = ChunkHash;

// upload_chunk END -----------------------------------------------------------

// clear_chunk_store ----------------------------------------------------------

/// Clear the chunk store of a canister.
///
/// See [IC method `clear_chunk_store`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-clear_chunk_store).
pub async fn clear_chunk_store(arg: ClearChunkStoreArgs) -> CallResult<()> {
    Call::new(Principal::management_canister(), "clear_chunk_store")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`clear_chunk_store`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ClearChunkStoreArgs {
    /// The canister whose chunk store will be cleared.
    pub canister_id: CanisterId,
}

// clear_chunk_store END ------------------------------------------------------

// stored_chunks --------------------------------------------------------------

/// Get the hashes of all chunks stored in the chunk store of a canister.
///
/// See [IC method `stored_chunks`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-stored_chunks).
pub async fn stored_chunks(arg: StoredChunksArgs) -> CallResult<StoredChunksResult> {
    Call::new(Principal::management_canister(), "stored_chunks")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`stored_chunks`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct StoredChunksArgs {
    /// The canister whose chunk store will be queried.
    pub canister_id: CanisterId,
}

/// Result type of [`stored_chunks`].
pub type StoredChunksResult = Vec<ChunkHash>;

// stored_chunks END ----------------------------------------------------------

// install_code ---------------------------------------------------------------

/// Install code into a canister.
///
/// See [IC method `install_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code).
pub async fn install_code(arg: InstallCodeArgs) -> CallResult<()> {
    let complete_arg = InstallCodeArgsComplete {
        mode: arg.mode,
        canister_id: arg.canister_id,
        wasm_module: arg.wasm_module,
        arg: arg.arg,
        sender_canister_version: Some(canister_version()),
    };
    Call::new(Principal::management_canister(), "install_code")
        .with_arg(complete_arg)
        .call()
        .await
}

/// The mode with which a canister is installed.
///
/// This second version of the mode allows someone to specify the
/// optional `SkipPreUpgrade` parameter in case of an upgrade
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub enum CanisterInstallMode {
    /// A fresh install of a new canister.
    #[default]
    #[serde(rename = "install")]
    Install,
    /// Reinstalling a canister that was already installed.
    #[serde(rename = "reinstall")]
    Reinstall,
    /// Upgrade an existing canister.
    #[serde(rename = "upgrade")]
    Upgrade(Option<UpgradeFlags>),
}

/// Flags for canister installation with [`CanisterInstallMode::Upgrade`].
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub struct UpgradeFlags {
    /// If set to `true`, the `pre_upgrade` step will be skipped during the canister upgrade.
    pub skip_pre_upgrade: Option<bool>,
    /// If set to `Keep`, the WASM heap memory will be preserved instead of cleared.
    pub wasm_memory_persistence: Option<WasmMemoryPersistence>,
}

/// Wasm memory persistence setting for [`UpgradeFlags`].
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub enum WasmMemoryPersistence {
    /// Preserve heap memory.
    #[serde(rename = "keep")]
    Keep,
    /// Clear heap memory.
    #[default]
    #[serde(rename = "replace")]
    Replace,
}

/// WASM module.
pub type WasmModule = Vec<u8>;

/// Argument type of [`install_code`].
///
/// Please note that this type is a reduced version of [`InstallCodeArgsComplete`].
/// The `sender_canister_version` field is removed as it is set automatically in [`install_code`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct InstallCodeArgs {
    /// See [CanisterInstallMode].
    pub mode: CanisterInstallMode,
    /// Canister ID.
    pub canister_id: CanisterId,
    /// Code to be installed.
    pub wasm_module: WasmModule,
    /// The argument to be passed to `canister_init` or `canister_post_upgrade`.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
}

/// Complete argument type of `install_code`.
///
/// Please note that this type is not used directly as the argument of [`install_code`].
/// The function [`install_code`] takes [`InstallCodeArgs`] instead.
///
/// If you want to manually call `install_code` (construct and invoke a [`Call`]), you should use this complete type.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct InstallCodeArgsComplete {
    /// See [`CanisterInstallMode`].
    pub mode: CanisterInstallMode,
    /// Canister ID.
    pub canister_id: CanisterId,
    /// Code to be installed.
    pub wasm_module: WasmModule,
    /// The argument to be passed to `canister_init` or `canister_post_upgrade`.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    /// sender_canister_version must be set to [`canister_version`].
    pub sender_canister_version: Option<u64>,
}

// install_code END -----------------------------------------------------------

// install_chunked_code -------------------------------------------------------

/// Install code into a canister where the code has previously been uploaded in chunks.
///
/// See [IC method `install_chunked_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_chunked_code).
pub async fn install_chunked_code(arg: InstallChunkedCodeArgs) -> CallResult<()> {
    let complete_arg = InstallChunkedCodeArgsComplete {
        mode: arg.mode,
        target_canister: arg.target_canister,
        store_canister: arg.store_canister,
        chunk_hashes_list: arg.chunk_hashes_list,
        wasm_module_hash: arg.wasm_module_hash,
        arg: arg.arg,
        sender_canister_version: Some(canister_version()),
    };
    Call::new(Principal::management_canister(), "install_chunked_code")
        .with_arg(complete_arg)
        .call()
        .await
}

/// Argument type of [`install_chunked_code`].
///
/// Please note that this type is a reduced version of [`InstallChunkedCodeArgsComplete`].
/// The `sender_canister_version` field is removed as it is set automatically in [`install_chunked_code`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct InstallChunkedCodeArgs {
    /// See [`CanisterInstallMode`].
    pub mode: CanisterInstallMode,
    /// Principal of the canister being installed.
    pub target_canister: CanisterId,
    /// The canister in whose chunk storage the chunks are stored (defaults to target_canister if not specified).
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

/// Complete argument type of `install_chunked_code`.
///
/// Please note that this type is not used directly as the argument of [`install_chunked_code`].
/// The function [`install_chunked_code`] takes [`InstallChunkedCodeArgs`] instead.
///
/// If you want to manually call `install_chunked_code` (construct and invoke a [`Call`]), you should use this complete type.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct InstallChunkedCodeArgsComplete {
    /// See [`CanisterInstallMode`].
    pub mode: CanisterInstallMode,
    /// Principal of the canister being installed.
    pub target_canister: CanisterId,
    /// The canister in whose chunk storage the chunks are stored (defaults to target_canister if not specified).
    pub store_canister: Option<CanisterId>,
    /// The list of chunks that make up the canister wasm.
    pub chunk_hashes_list: Vec<ChunkHash>,
    /// The sha256 hash of the wasm.
    #[serde(with = "serde_bytes")]
    pub wasm_module_hash: Vec<u8>,
    /// The argument to be passed to `canister_init` or `canister_post_upgrade`.
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    /// sender_canister_version must be set to [`canister_version`].
    pub sender_canister_version: Option<u64>,
}

// install_chunked_code END ---------------------------------------------------

// uninstall_code -------------------------------------------------------------

/// Remove a canister's code and state, making the canister empty again.
///
/// See [IC method `uninstall_code`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-uninstall_code).
pub async fn uninstall_code(arg: UninstallCodeArgs) -> CallResult<()> {
    let complete_arg = UninstallCodeArgsComplete {
        canister_id: arg.canister_id,
        sender_canister_version: Some(canister_version()),
    };
    Call::new(Principal::management_canister(), "uninstall_code")
        .with_arg(complete_arg)
        .call()
        .await
}

/// Argument type of [`uninstall_code`].
///
/// Please note that this type is a reduced version of [`UninstallCodeArgsComplete`].
/// The `sender_canister_version` field is removed as it is set automatically in [`uninstall_code`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UninstallCodeArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

/// Complete argument type of `uninstall_code`.
///
/// Please note that this type is not used directly as the argument of [`uninstall_code`].
/// The function [`uninstall_code`] takes [`UninstallCodeArgs`] instead.
///
/// If you want to manually call `uninstall_code` (construct and invoke a [Call]), you should use this complete type.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct UninstallCodeArgsComplete {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// sender_canister_version must be set to [`canister_version`].
    pub sender_canister_version: Option<u64>,
}

// uninstall_code END ---------------------------------------------------------

// start_canister -------------------------------------------------------------

/// Start a canister if the canister status was `stopped` or `stopping`.
///
/// See [IC method `start_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-start_canister).
pub async fn start_canister(arg: StartCanisterArgs) -> CallResult<()> {
    Call::new(Principal::management_canister(), "start_canister")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`start_canister`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct StartCanisterArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

// start_canister END ---------------------------------------------------------

// stop_canister --------------------------------------------------------------

/// Stop a canister.
///
/// See [IC method `stop_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-stop_canister).
pub async fn stop_canister(arg: StopCanisterArgs) -> CallResult<()> {
    Call::new(Principal::management_canister(), "stop_canister")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`stop_canister`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct StopCanisterArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

// stop_canister END ----------------------------------------------------------

// canister_status ------------------------------------------------------------

/// Get status information about the canister.
///
/// See [IC method `canister_status`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_status).
pub async fn canister_status(arg: CanisterStatusArgs) -> CallResult<CanisterStatusResult> {
    Call::new(Principal::management_canister(), "canister_status")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`canister_status`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CanisterStatusArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

/// Return type of [`canister_status`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CanisterStatusResult {
    /// See [CanisterStatusType].
    pub status: CanisterStatusType,
    /// See [DefiniteCanisterSettings].
    pub settings: DefiniteCanisterSettings,
    /// A SHA256 hash of the module installed on the canister. This is null if the canister is empty.
    pub module_hash: Option<Vec<u8>>,
    /// The memory size taken by the canister.
    pub memory_size: Nat,
    /// The cycle balance of the canister.
    pub cycles: Nat,
    /// The reserved cycles balance of the canister.
    /// These are cycles that are reserved by the resource reservation mechanism
    /// on storage allocation. See also the `reserved_cycles_limit` parameter in
    /// canister settings.
    pub reserved_cycles: Nat,
    /// Amount of cycles burned per day.
    pub idle_cycles_burned_per_day: Nat,
    /// Query statistics.
    pub query_stats: QueryStats,
}

/// Status of a canister.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
pub enum CanisterStatusType {
    /// The canister is running.
    #[serde(rename = "running")]
    Running,
    /// The canister is stopping.
    #[serde(rename = "stopping")]
    Stopping,
    /// The canister is stopped.
    #[serde(rename = "stopped")]
    Stopped,
}

/// Query statistics, returned by [`canister_status`].
#[derive(
    CandidType, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct QueryStats {
    /// Total number of query calls.
    pub num_calls_total: Nat,
    /// Total number of instructions executed by query calls.
    pub num_instructions_total: Nat,
    /// Total number of payload bytes use for query call requests.
    pub request_payload_bytes_total: Nat,
    /// Total number of payload bytes use for query call responses.
    pub response_payload_bytes_total: Nat,
}

// canister_status END --------------------------------------------------------

// canister_info --------------------------------------------------------------

/// Get public information about the canister.
///
/// See [IC method `canister_info`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_info).
pub async fn canister_info(arg: CanisterInfoArgs) -> CallResult<CanisterInfoResult> {
    Call::new(Principal::management_canister(), "canister_info")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`canister_info`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CanisterInfoArgs {
    /// Canister ID.
    pub canister_id: Principal,
    /// Number of most recent changes requested to be retrieved from canister history.
    /// No changes are retrieved if this field is null.
    pub num_requested_changes: Option<u64>,
}

/// Return type of [`canister_info`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CanisterInfoResult {
    /// Total number of changes ever recorded in canister history.
    /// This might be higher than the number of canister changes in `recent_changes`
    /// because the IC might drop old canister changes from its history
    /// (with `20` most recent canister changes to always remain in the list).
    pub total_num_changes: u64,
    /// The canister changes stored in the order from the oldest to the most recent.
    pub recent_changes: Vec<CanisterChange>,
    /// A SHA256 hash of the module installed on the canister. This is null if the canister is empty.
    pub module_hash: Option<Vec<u8>>,
    /// Controllers of the canister.
    pub controllers: Vec<Principal>,
}

/// Details about a canister change initiated by a user.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct FromUserRecord {
    /// Principal of the user.
    pub user_id: Principal,
}

/// Details about a canister change initiated by a canister (called _originator_).
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct FromCanisterRecord {
    /// Canister ID of the originator.
    pub canister_id: Principal,
    /// Canister version of the originator when the originator initiated the change.
    /// This is null if the original does not include its canister version
    /// in the field `sender_canister_version` of the management canister payload.
    pub canister_version: Option<u64>,
}

/// Provides details on who initiated a canister change.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub enum CanisterChangeOrigin {
    /// See [`FromUserRecord`].
    #[serde(rename = "from_user")]
    FromUser(FromUserRecord),
    /// See [`FromCanisterRecord`].
    #[serde(rename = "from_canister")]
    FromCanister(FromCanisterRecord),
}

/// Details about a canister creation.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CreationRecord {
    /// Initial set of canister controllers.
    pub controllers: Vec<Principal>,
}

/// The mode with which a canister is installed.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
pub enum CodeDeploymentMode {
    /// A fresh install of a new canister.
    #[serde(rename = "install")]
    Install,
    /// Reinstalling a canister that was already installed.
    #[serde(rename = "reinstall")]
    Reinstall,
    /// Upgrade an existing canister.
    #[serde(rename = "upgrade")]
    Upgrade,
}

/// Details about a canister code deployment.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CodeDeploymentRecord {
    /// See [`CodeDeploymentMode`].
    pub mode: CodeDeploymentMode,
    /// A SHA256 hash of the new module installed on the canister.
    #[serde(with = "serde_bytes")]
    pub module_hash: Vec<u8>,
}

/// Details about loading canister snapshot.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct LoadSnapshotRecord {
    /// The version of the canister at the time that the snapshot was taken
    pub canister_version: u64,
    /// The ID of the snapshot that was loaded.
    pub snapshot_id: SnapshotId,
    /// The timestamp at which the snapshot was taken.
    pub taken_at_timestamp: u64,
}

/// Details about updating canister controllers.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ControllersChangeRecord {
    /// The full new set of canister controllers.
    pub controllers: Vec<Principal>,
}

/// Provides details on the respective canister change.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub enum CanisterChangeDetails {
    /// See [`CreationRecord`].
    #[serde(rename = "creation")]
    Creation(CreationRecord),
    /// Uninstalling canister's module.
    #[serde(rename = "code_uninstall")]
    CodeUninstall,
    /// See [`CodeDeploymentRecord`].
    #[serde(rename = "code_deployment")]
    CodeDeployment(CodeDeploymentRecord),
    /// See [`LoadSnapshotRecord`].
    #[serde(rename = "load_snapshot")]
    LoadSnapshot(LoadSnapshotRecord),
    /// See [`ControllersChangeRecord`].
    #[serde(rename = "controllers_change")]
    ControllersChange(ControllersChangeRecord),
}

/// Represents a canister change as stored in the canister history.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct CanisterChange {
    /// The system timestamp (in nanoseconds since Unix Epoch) at which the change was performed.
    pub timestamp_nanos: u64,
    /// The canister version after performing the change.
    pub canister_version: u64,
    /// The change's origin (a user or a canister).
    pub origin: CanisterChangeOrigin,
    /// The change's details.
    pub details: CanisterChangeDetails,
}

// canister_info END ----------------------------------------------------------

// delete_canister ------------------------------------------------------------

/// Delete a canister.
///
/// See [IC method `delete_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-delete_canister).
pub async fn delete_canister(arg: DeleteCanisterArgs) -> CallResult<()> {
    Call::new(Principal::management_canister(), "delete_canister")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`delete_canister`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct DeleteCanisterArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

// delete_canister END --------------------------------------------------------

// deposit_cycles -------------------------------------------------------------

/// Deposit cycles to a canister.
///
/// See [IC method `deposit_cycles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-deposit_cycles).
pub async fn deposit_cycles(arg: DepositCyclesArgs, cycles: u128) -> CallResult<()> {
    Call::new(Principal::management_canister(), "deposit_cycles")
        .with_arg(arg)
        .with_guaranteed_response()
        .with_cycles(cycles)
        .call()
        .await
}

/// Argument type of [`deposit_cycles`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct DepositCyclesArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

// deposit_cycles END ---------------------------------------------------------

// raw_rand -------------------------------------------------------------------

// Get 32 pseudo-random bytes.
///
/// See [IC method `raw_rand`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-raw_rand).
pub async fn raw_rand() -> CallResult<Vec<u8>> {
    Call::new(Principal::management_canister(), "raw_rand")
        .call()
        .await
}

// raw_rand END ---------------------------------------------------------------

// http_request ---------------------------------------------------------------

/// Make an HTTP request to a given URL and return the HTTP response, possibly after a transformation.
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
///
/// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
/// Check [HTTPS outcalls cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost#https-outcalls) for more details.
pub async fn http_request(arg: HttpRequestArgs, cycles: u128) -> CallResult<HttpRequestResult> {
    Call::new(Principal::management_canister(), "http_request")
        .with_arg(arg)
        .with_guaranteed_response()
        .with_cycles(cycles)
        .call()
        .await
}

/// Argument type of [`http_request`].
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HttpRequestArgs {
    /// The requested URL.
    pub url: String,
    /// The maximal size of the response in bytes. If None, 2MiB will be the limit.
    /// This value affects the cost of the http request and it is highly recommended
    /// to set it as low as possible to avoid unnecessary extra costs.
    /// See also the [pricing section of HTTP outcalls documentation](https://internetcomputer.org/docs/current/developer-docs/integrations/http_requests/http_requests-how-it-works#pricing).
    pub max_response_bytes: Option<u64>,
    /// The method of HTTP request.
    pub method: HttpMethod,
    /// List of HTTP request headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// Optionally provide request body.
    pub body: Option<Vec<u8>>,
    /// Name of the transform function which is `func (transform_args) -> (http_response) query`.
    /// Set to `None` if you are using `http_request_with` or `http_request_with_cycles_with`.
    pub transform: Option<TransformContext>,
}

/// The returned HTTP response.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct HttpRequestResult {
    /// The response status (e.g., 200, 404).
    pub status: candid::Nat,
    /// List of HTTP response headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// The response’s body.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

/// HTTP method.
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub enum HttpMethod {
    /// GET
    #[default]
    #[serde(rename = "get")]
    GET,
    /// POST
    #[serde(rename = "post")]
    POST,
    /// HEAD
    #[serde(rename = "head")]
    HEAD,
}
/// HTTP header.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct HttpHeader {
    /// Name
    pub name: String,
    /// Value
    pub value: String,
}

/// ```text
/// record {
///     function : func(record { response : http_request_result; context : blob }) -> (http_request_result) query;
///     context : blob;
/// };
/// ```
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransformContext {
    /// `func(record { response : http_request_result; context : blob }) -> (http_request_result) query;`.
    pub function: TransformFunc,

    /// Context to be passed to `transform` function to transform HTTP response for consensus
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

impl TransformContext {
    /// Constructs a [`TransformContext`] from a query method name and context.
    /// The principal is assumed to be the ID of current canister.
    pub fn from_name(candid_function_name: String, context: Vec<u8>) -> Self {
        Self {
            context,
            function: TransformFunc(candid::Func {
                method: candid_function_name,
                principal: crate::api::canister_self(),
            }),
        }
    }
}

mod transform_func {
    #![allow(missing_docs)]
    use super::{HttpRequestResult, TransformArgs};
    candid::define_function!(pub TransformFunc : (TransformArgs) -> (HttpRequestResult) query);
}

/// "transform" function of type: `func(record { response : http_request_result; context : blob }) -> (http_request_result) query`
pub use transform_func::TransformFunc;

/// Type used for encoding/decoding:
/// `record {
///     response : http_response;
///     context : blob;
/// }`
#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransformArgs {
    /// Raw response from remote service, to be transformed
    pub response: HttpRequestResult,

    /// Context for response transformation
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

#[cfg(feature = "transform-closure")]
mod transform_closure {
    use super::{
        http_request, CallResult, HttpRequestArgs, HttpRequestResult, Principal, TransformArgs,
        TransformContext,
    };
    use candid::{decode_one, encode_one};
    use slotmap::{DefaultKey, Key, KeyData, SlotMap};
    use std::cell::RefCell;

    thread_local! {
        #[allow(clippy::type_complexity)]
        static TRANSFORMS: RefCell<SlotMap<DefaultKey, Box<dyn FnOnce(HttpRequestResult) -> HttpRequestResult>>> = RefCell::default();
    }

    #[export_name = "canister_query <ic-cdk internal> http_transform"]
    extern "C" fn http_transform() {
        use crate::api::{msg_arg_data, msg_caller, msg_reply};
        if msg_caller() != Principal::management_canister() {
            crate::trap("This function is internal to ic-cdk and should not be called externally.");
        }
        crate::setup();
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
    }

    /// Make an HTTP request to a given URL and return the HTTP response, after a transformation.
    ///
    /// Do not set the `transform` field of `arg`. To use a Candid function, call [`http_request`] instead.
    ///
    /// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
    ///
    /// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
    /// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost) for more details.
    #[cfg_attr(docsrs, doc(cfg(feature = "transform-closure")))]
    pub async fn http_request_with_closure(
        arg: HttpRequestArgs,
        cycles: u128,
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
            transform: Some(TransformContext::from_name(
                "<ic-cdk internal> http_transform".to_string(),
                context,
            )),
            ..arg
        };
        http_request(arg, cycles).await
    }
}

#[cfg(feature = "transform-closure")]
pub use transform_closure::http_request_with_closure;

// http_request END -----------------------------------------------------------

// # Threshold ECDSA signature ================================================

/// ECDSA KeyId.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct EcdsaKeyId {
    /// See [`EcdsaCurve`].
    pub curve: EcdsaCurve,
    /// Name.
    pub name: String,
}

/// ECDSA Curve.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy,
)]
pub enum EcdsaCurve {
    /// secp256k1
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl Default for EcdsaCurve {
    fn default() -> Self {
        Self::Secp256k1
    }
}

// ecdsa_public_key -----------------------------------------------------------

/// Return a SEC1 encoded ECDSA public key for the given canister using the given derivation path.
///
/// See [IC method `ecdsa_public_key`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-ecdsa_public_key).
pub async fn ecdsa_public_key(arg: EcdsaPublicKeyArgs) -> CallResult<EcdsaPublicKeyResult> {
    Call::new(Principal::management_canister(), "ecdsa_public_key")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`ecdsa_public_key`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct EcdsaPublicKeyArgs {
    /// Canister id, default to the canister id of the caller if None.
    pub canister_id: Option<CanisterId>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [EcdsaKeyId].
    pub key_id: EcdsaKeyId,
}

/// Response Type of [`ecdsa_public_key`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct EcdsaPublicKeyResult {
    /// An ECDSA public key encoded in SEC1 compressed form.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Can be used to deterministically derive child keys of the public_key.
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>,
}

// ecda_public_key END --------------------------------------------------------

// sign_with_ecdsa ------------------------------------------------------------

/// Return a new ECDSA signature of the given message_hash that can be separately verified against a derived ECDSA public key.
///
/// See [IC method `sign_with_ecdsa`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-sign_with_ecdsa).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [Threshold signatures](https://internetcomputer.org/docs/current/references/t-sigs-how-it-works) for more details.
pub async fn sign_with_ecdsa(arg: SignWithEcdsaArgs) -> CallResult<SignWithEcdsaResult> {
    Call::new(Principal::management_canister(), "sign_with_ecdsa")
        .with_arg(arg)
        .with_guaranteed_response()
        .with_cycles(SIGN_WITH_ECDSA_FEE)
        .call()
        .await
}

/// https://internetcomputer.org/docs/current/references/t-sigs-how-it-works#fees-for-the-t-ecdsa-production-key
const SIGN_WITH_ECDSA_FEE: u128 = 26_153_846_153;

/// Argument type of [`sign_with_ecdsa`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithEcdsaArgs {
    /// Hash of the message with length of 32 bytes.
    #[serde(with = "serde_bytes")]
    pub message_hash: Vec<u8>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [EcdsaKeyId].
    pub key_id: EcdsaKeyId,
}

/// Response type of [`sign_with_ecdsa`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithEcdsaResult {
    /// Encoded as the concatenation of the SEC1 encodings of the two values r and s.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

// sign_with_ecdsa END --------------------------------------------------------

// # Threshold ECDSA signature END ============================================

// # Threshold Schnorr signature ==============================================

/// Schnorr KeyId.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SchnorrKeyId {
    /// See [`SchnorrAlgorithm`].
    pub algorithm: SchnorrAlgorithm,
    /// Name.
    pub name: String,
}

/// Schnorr Algorithm.
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub enum SchnorrAlgorithm {
    /// BIP-340 secp256k1.
    #[serde(rename = "bip340secp256k1")]
    #[default]
    Bip340secp256k1,
    /// ed25519.
    #[serde(rename = "ed25519")]
    Ed25519,
}

// schnorr_public_key ----------------------------------------------------------

/// Return a SEC1 encoded Schnorr public key for the given canister using the given derivation path.
///
/// See [IC method `schnorr_public_key`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-schnorr_public_key).
pub async fn schnorr_public_key(arg: SchnorrPublicKeyArgs) -> CallResult<SchnorrPublicKeyResult> {
    Call::new(Principal::management_canister(), "schnorr_public_key")
        .with_arg(arg)
        .call()
        .await
}

/// Argument Type of [`schnorr_public_key`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SchnorrPublicKeyArgs {
    /// Canister id, default to the canister id of the caller if None.
    pub canister_id: Option<CanisterId>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [SchnorrKeyId].
    pub key_id: SchnorrKeyId,
}

/// Response Type of [`schnorr_public_key`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SchnorrPublicKeyResult {
    /// An Schnorr public key encoded in SEC1 compressed form.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Can be used to deterministically derive child keys of the public_key.
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>,
}

// schnorr_public_key END -----------------------------------------------------

// sign_with_schnorr ----------------------------------------------------------

/// Return a new Schnorr signature of the given message that can be separately verified against a derived Schnorr public key.
///
/// See [IC method `sign_with_schnorr`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-sign_with_schnorr).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [Threshold signatures](https://internetcomputer.org/docs/current/references/t-sigs-how-it-works) for more details.
pub async fn sign_with_schnorr(arg: SignWithSchnorrArgs) -> CallResult<SignWithSchnorrResult> {
    Call::new(Principal::management_canister(), "sign_with_schnorr")
        .with_arg(arg)
        .with_guaranteed_response()
        .with_cycles(SIGN_WITH_SCHNORR_FEE)
        .call()
        .await
}

/// https://internetcomputer.org/docs/current/references/t-sigs-how-it-works/#fees-for-the-t-schnorr-production-key
const SIGN_WITH_SCHNORR_FEE: u128 = 26_153_846_153;

/// Argument Type of [`sign_with_schnorr`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithSchnorrArgs {
    /// Message to be signed.
    #[serde(with = "serde_bytes")]
    pub message: Vec<u8>,
    /// A vector of variable length byte strings.
    pub derivation_path: Vec<Vec<u8>>,
    /// See [SchnorrKeyId].
    pub key_id: SchnorrKeyId,
}

/// Response Type of [`sign_with_schnorr`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct SignWithSchnorrResult {
    /// The encoding of the signature depends on the key ID's algorithm.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

// sign_with_schnorr END ------------------------------------------------------

// # Threshold Schnorr signature END ==========================================

// node_metrics_history -------------------------------------------------------

/// Get a time series of node metrics of a subnet.
///
/// See [IC method `node_metrics_history`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-node-metrics-history).
pub async fn node_metrics_history(
    arg: NodeMetricsHistoryArgs,
) -> CallResult<NodeMetricsHistoryResult> {
    Call::new(Principal::management_canister(), "node_metrics_history")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`node_metrics_history`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct NodeMetricsHistoryArgs {
    /// Subnet ID.
    pub subnet_id: Principal,
    /// The returned time series will start at this timestamp.
    pub start_at_timestamp_nanos: u64,
}

/// Return type of [`node_metrics_history`].
pub type NodeMetricsHistoryResult = Vec<NodeMetricsHistoryRecord>;

/// A record in [`NodeMetricsHistoryResult`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct NodeMetricsHistoryRecord {
    /// The timestamp of the record.
    pub timestamp_nanos: u64,
    /// The metrics of the nodes.
    pub node_metrics: Vec<NodeMetrics>,
}

/// Node metrics.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct NodeMetrics {
    /// The principal characterizing a node.
    pub node_id: Principal,
    /// The number of blocks proposed by this node.
    pub num_blocks_proposed_total: u64,
    /// The number of failed block proposals by this node.
    pub num_blocks_failures_total: u64,
}

// node_metrics_history END ---------------------------------------------------

// subnet_info ----------------------------------------------------------------

/// Get subnet metadata.
///
/// See [IC method `subnet_info`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-subnet-info).
pub async fn subnet_info(arg: SubnetInfoArgs) -> CallResult<SubnetInfoResult> {
    Call::new(Principal::management_canister(), "subnet_info")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`subnet_info`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct SubnetInfoArgs {
    /// Subnet ID.
    pub subnet_id: Principal,
}

/// Result type of [`subnet_info`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct SubnetInfoResult {
    /// Replica version of the subnet.
    pub replica_version: String,
}

// subnet_info END ------------------------------------------------------------

// # provisional interfaces for the pre-ledger world ==========================

// provisional_create_canister_with_cycles ------------------------------------

/// Create a new canister with specified amount of cycles balance.
///
/// This method is only available in local development instances.
///
/// See [IC method `provisional_create_canister_with_cycles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-provisional_create_canister_with_cycles).
pub async fn provisional_create_canister_with_cycles(
    arg: ProvisionalCreateCanisterWithCyclesArgs,
) -> CallResult<ProvisionalCreateCanisterWithCyclesResult> {
    Call::new(
        Principal::management_canister(),
        "provisional_create_canister_with_cycles",
    )
    .with_arg(arg)
    .with_guaranteed_response()
    .call()
    .await
}

/// Argument type of [`provisional_create_canister_with_cycles`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    /// The created canister will have this amount of cycles.
    pub amount: Option<Nat>,
    /// See [CanisterSettings].
    pub settings: Option<CanisterSettings>,
}

/// Result type of [`provisional_create_canister_with_cycles`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ProvisionalCreateCanisterWithCyclesResult {
    /// Canister ID of the created canister.
    pub canister_id: CanisterId,
}

// provisional_delete_canister_with_cycles END --------------------------------

// provisional_top_up_canister ------------------------------------------------

/// Add cycles to a canister.
///
/// This method is only available in local development instances.
///
/// See [IC method `provisional_top_up_canister`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-provisional_top_up_canister).
pub async fn provisional_top_up_canister(arg: ProvisionalTopUpCanisterArgs) -> CallResult<()> {
    Call::new(
        Principal::management_canister(),
        "provisional_top_up_canister",
    )
    .with_arg(arg)
    .with_guaranteed_response()
    .call()
    .await
}

/// Argument type of [`provisional_top_up_canister`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ProvisionalTopUpCanisterArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// Amount of cycles to be added.
    pub amount: Nat,
}

// provisional_top_up_canister END --------------------------------------------

// # provisional interfaces for the pre-ledger world END ======================

// # Canister snapshots =======================================================

/// Snapshot ID.
pub type SnapshotId = Vec<u8>;

/// A snapshot of the state of the canister at a given point in time.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct Snapshot {
    /// ID of the snapshot.
    pub id: SnapshotId,
    /// The timestamp at which the snapshot was taken.
    pub taken_at_timestamp: u64,
    /// The size of the snapshot in bytes.
    pub total_size: u64,
}

// take_canister_snapshot -----------------------------------------------------

/// Take a snapshot of the specified canister.
///
/// A snapshot consists of the wasm memory, stable memory, certified variables, wasm chunk store and wasm binary.
///
/// See [IC method `take_canister_snapshot`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-take_canister_snapshot).
pub async fn take_canister_snapshot(
    arg: TakeCanisterSnapshotArgs,
) -> CallResult<TakeCanisterSnapshotReturn> {
    Call::new(Principal::management_canister(), "take_canister_snapshot")
        .with_arg(arg)
        .with_guaranteed_response()
        .call()
        .await
}

/// Argument type of [`take_canister_snapshot`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct TakeCanisterSnapshotArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// An optional snapshot ID to be replaced by the new snapshot.
    ///
    /// The snapshot identified by the specified ID will be deleted once a new snapshot has been successfully created.
    pub replace_snapshot: Option<SnapshotId>,
}

/// Return type of [`take_canister_snapshot`].
pub type TakeCanisterSnapshotReturn = Snapshot;

// take_canister_snapshot END -------------------------------------------------

// load_canister_snapshot -----------------------------------------------------

/// Load a snapshot onto the canister.
///
/// It fails if no snapshot with the specified `snapshot_id` can be found.
///
/// See [IC method `load_canister_snapshot`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-load_canister_snapshot).
pub async fn load_canister_snapshot(arg: LoadCanisterSnapshotArgs) -> CallResult<()> {
    let complete_arg = LoadCanisterSnapshotArgsComplete {
        canister_id: arg.canister_id,
        snapshot_id: arg.snapshot_id,
        sender_canister_version: Some(canister_version()),
    };
    Call::new(Principal::management_canister(), "load_canister_snapshot")
        .with_arg(complete_arg)
        .with_guaranteed_response()
        .call()
        .await
}

/// Argument type of [`load_canister_snapshot`].
///
/// Please note that this type is a reduced version of [`LoadCanisterSnapshotArgsComplete`].
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

/// Complete argument type of [`load_canister_snapshot`].
///
/// Please note that this type is not used directly as the argument of [`load_canister_snapshot`].
/// The function [`load_canister_snapshot`] takes [`LoadCanisterSnapshotArgs`] instead.
///
/// If you want to manually call `load_canister_snapshot` (construct and invoke a [`Call`]), you should use this complete type.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct LoadCanisterSnapshotArgsComplete {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// ID of the snapshot to be loaded.
    pub snapshot_id: SnapshotId,
    /// sender_canister_version must be set to [`canister_version`].
    pub sender_canister_version: Option<u64>,
}

// load_canister_snapshot END -------------------------------------------------

// list_canister_snapshots ----------------------------------------------------

/// List the snapshots of the canister.
///
/// See [IC method `list_canister_snapshots`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-list_canister_snapshots).
pub async fn list_canister_snapshots(
    arg: ListCanisterSnapshotsArgs,
) -> CallResult<ListCanisterSnapshotsReturn> {
    Call::new(Principal::management_canister(), "list_canister_snapshots")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`list_canister_snapshots`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ListCanisterSnapshotsArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

/// Return type of [`list_canister_snapshots`].
pub type ListCanisterSnapshotsReturn = Vec<Snapshot>;

// list_canister_snapshots END ------------------------------------------------

// delete_canister_snapshot ---------------------------------------------------

/// Delete a specified snapshot that belongs to an existing canister.
///
/// An error will be returned if the snapshot is not found.
///
/// See [IC method `delete_canister_snapshot`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-delete_canister_snapshot).
pub async fn delete_canister_snapshot(arg: DeleteCanisterSnapshotArgs) -> CallResult<()> {
    Call::new(Principal::management_canister(), "delete_canister_snapshot")
        .with_arg(arg)
        .call()
        .await
}

/// Argument type of [`delete_canister_snapshot`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct DeleteCanisterSnapshotArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// ID of the snapshot to be deleted.
    pub snapshot_id: SnapshotId,
}

// delete_canister_snapshot END -----------------------------------------------

// # Canister snapshots END ===================================================
