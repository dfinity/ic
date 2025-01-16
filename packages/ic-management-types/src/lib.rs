//! Types for calling [the IC management canister][1].
//!
//! This module is a direct translation from its Candid interface description.
//!
//! [1]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister

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

/// Argument type of [`deposit_cycles`].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct DepositCyclesArgs {
    /// Canister ID.
    pub canister_id: CanisterId,
}

// deposit_cycles END ---------------------------------------------------------

// http_request ---------------------------------------------------------------

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
