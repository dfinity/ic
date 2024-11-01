use candid::{CandidType, Deserialize, Principal};

pub type CanisterId = Principal;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterIdRecord {
    pub canister_id: CanisterId,
}

// canister settings

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum LogVisibility {
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct DefiniteCanisterSettings {
    pub freezing_threshold: candid::Nat,
    pub controllers: Vec<Principal>,
    pub reserved_cycles_limit: candid::Nat,
    pub log_visibility: LogVisibility,
    pub wasm_memory_limit: candid::Nat,
    pub memory_allocation: candid::Nat,
    pub compute_allocation: candid::Nat,
}

#[derive(CandidType, Deserialize, Debug, Clone, Default)]
pub struct CanisterSettings {
    pub freezing_threshold: Option<candid::Nat>,
    pub controllers: Option<Vec<Principal>>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibility>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub compute_allocation: Option<candid::Nat>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct UpdateSettingsArgs {
    pub canister_id: CanisterId,
    pub settings: CanisterSettings,
    pub sender_canister_version: Option<u64>,
}

// canister status

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum CanisterStatusResultStatus {
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "running")]
    Running,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterStatusResultQueryStats {
    pub response_payload_bytes_total: candid::Nat,
    pub num_instructions_total: candid::Nat,
    pub num_calls_total: candid::Nat,
    pub request_payload_bytes_total: candid::Nat,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterStatusResult {
    pub status: CanisterStatusResultStatus,
    pub memory_size: candid::Nat,
    pub cycles: candid::Nat,
    pub settings: DefiniteCanisterSettings,
    pub query_stats: CanisterStatusResultQueryStats,
    pub idle_cycles_burned_per_day: candid::Nat,
    pub module_hash: Option<Vec<u8>>,
    pub reserved_cycles: candid::Nat,
}

// canister creation

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CreateCanisterArgs {
    pub settings: Option<CanisterSettings>,
    pub sender_canister_version: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    pub settings: Option<CanisterSettings>,
    pub specified_id: Option<CanisterId>,
    pub amount: Option<candid::Nat>,
    pub sender_canister_version: Option<u64>,
}

// canister code installation

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum CanisterInstallModeUpgradeInnerWasmMemoryPersistenceInner {
    #[serde(rename = "keep")]
    Keep,
    #[serde(rename = "replace")]
    Replace,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterInstallModeUpgradeInner {
    pub wasm_memory_persistence: Option<CanisterInstallModeUpgradeInnerWasmMemoryPersistenceInner>,
    pub skip_pre_upgrade: Option<bool>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum CanisterInstallMode {
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade(Option<CanisterInstallModeUpgradeInner>),
    #[serde(rename = "install")]
    Install,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InstallCodeArgs {
    pub arg: Vec<u8>,
    pub wasm_module: Vec<u8>,
    pub mode: CanisterInstallMode,
    pub canister_id: CanisterId,
    pub sender_canister_version: Option<u64>,
}

// canister code uninstallation

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct UninstallCodeArgs {
    pub canister_id: CanisterId,
    pub sender_canister_version: Option<u64>,
}

// canister chunks

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ChunkHash {
    pub hash: Vec<u8>,
}

pub type StoredChunksResult = Vec<ChunkHash>;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct UploadChunkArgs {
    pub canister_id: CanisterId,
    pub chunk: Vec<u8>,
}

pub type UploadChunkResult = ChunkHash;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InstallChunkedCodeArgs {
    pub arg: Vec<u8>,
    pub wasm_module_hash: Vec<u8>,
    pub mode: CanisterInstallMode,
    pub chunk_hashes_list: Vec<ChunkHash>,
    pub target_canister: CanisterId,
    pub store_canister: Option<CanisterId>,
    pub sender_canister_version: Option<u64>,
}

// canister snapshots

pub type SnapshotId = Vec<u8>;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub total_size: u64,
    pub taken_at_timestamp: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct DeleteCanisterSnapshotArgs {
    pub canister_id: CanisterId,
    pub snapshot_id: SnapshotId,
}

pub type ListCanisterSnapshotsResult = Vec<Snapshot>;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct LoadCanisterSnapshotArgs {
    pub canister_id: CanisterId,
    pub sender_canister_version: Option<u64>,
    pub snapshot_id: SnapshotId,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct TakeCanisterSnapshotArgs {
    pub replace_snapshot: Option<SnapshotId>,
    pub canister_id: CanisterId,
}

pub type TakeCanisterSnapshotResult = Snapshot;

// canister logs

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterLogRecord {
    pub idx: u64,
    pub timestamp_nanos: u64,
    pub content: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct FetchCanisterLogsResult {
    pub canister_log_records: Vec<CanisterLogRecord>,
}

// canister http

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum HttpRequestArgsMethod {
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "head")]
    Head,
    #[serde(rename = "post")]
    Post,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct HttpHeader {
    pub value: String,
    pub name: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct HttpRequestArgsTransformInnerFunctionArg {
    pub context: Vec<u8>,
    pub response: HttpRequestResult,
}

candid::define_function!(pub HttpRequestArgsTransformInnerFunction : (
    HttpRequestArgsTransformInnerFunctionArg,
  ) -> (HttpRequestResult) query);

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct HttpRequestArgsTransformInner {
    pub function: HttpRequestArgsTransformInnerFunction,
    pub context: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct HttpRequestArgs {
    pub url: String,
    pub method: HttpRequestArgsMethod,
    pub max_response_bytes: Option<u64>,
    pub body: Option<Vec<u8>>,
    pub transform: Option<HttpRequestArgsTransformInner>,
    pub headers: Vec<HttpHeader>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct HttpRequestResult {
    pub status: candid::Nat,
    pub body: Vec<u8>,
    pub headers: Vec<HttpHeader>,
}

// ecdsa

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256K1,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct EcdsaPublicKeyArgsKeyId {
    pub name: String,
    pub curve: EcdsaCurve,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct EcdsaPublicKeyArgs {
    pub key_id: EcdsaPublicKeyArgsKeyId,
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct EcdsaPublicKeyResult {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithEcdsaArgsKeyId {
    pub name: String,
    pub curve: EcdsaCurve,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithEcdsaArgs {
    pub key_id: SignWithEcdsaArgsKeyId,
    pub derivation_path: Vec<Vec<u8>>,
    pub message_hash: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithEcdsaResult {
    pub signature: Vec<u8>,
}

// schnorr

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256K1,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SchnorrPublicKeyArgsKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SchnorrPublicKeyArgs {
    pub key_id: SchnorrPublicKeyArgsKeyId,
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SchnorrPublicKeyResult {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithSchnorrArgsKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithSchnorrArgs {
    pub key_id: SignWithSchnorrArgsKeyId,
    pub derivation_path: Vec<Vec<u8>>,
    pub message: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithSchnorrResult {
    pub signature: Vec<u8>,
}
