use candid::{CandidType, Deserialize, Principal};

pub type CanisterId = Principal;
pub type SubnetId = Principal;

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
    #[serde(rename = "allowed_viewers")]
    AllowedViewers(Vec<Principal>),
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

// provisional API

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    pub settings: Option<CanisterSettings>,
    pub specified_id: Option<CanisterId>,
    pub amount: Option<candid::Nat>,
    pub sender_canister_version: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ProvisionalTopUpCanisterArgs {
    pub canister_id: Principal,
    pub amount: candid::Nat,
}

// The following types can only be used in inter-canister calls, i.e.,
// these types CANNOT be used in ingress messages to the management canister.

// canister creation

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CreateCanisterArgs {
    pub settings: Option<CanisterSettings>,
    pub sender_canister_version: Option<u64>,
}

// canister info

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterInfoArgs {
    pub canister_id: CanisterId,
    pub num_requested_changes: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SubnetInfoArgs {
    pub subnet_id: SubnetId,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum ChangeOrigin {
    #[serde(rename = "from_user")]
    FromUser { user_id: Principal },
    #[serde(rename = "from_canister")]
    FromCanister {
        canister_version: Option<u64>,
        canister_id: Principal,
    },
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum ChangeDetailsCodeDeploymentMode {
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade,
    #[serde(rename = "install")]
    Install,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum ChangeDetails {
    #[serde(rename = "creation")]
    Creation { controllers: Vec<Principal> },
    #[serde(rename = "code_deployment")]
    CodeDeployment {
        mode: ChangeDetailsCodeDeploymentMode,
        module_hash: Vec<u8>,
    },
    #[serde(rename = "load_snapshot")]
    LoadSnapshot {
        canister_version: u64,
        taken_at_timestamp: u64,
        snapshot_id: SnapshotId,
    },
    #[serde(rename = "controllers_change")]
    ControllersChange { controllers: Vec<Principal> },
    #[serde(rename = "code_uninstall")]
    CodeUninstall,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct Change {
    pub timestamp_nanos: u64,
    pub canister_version: u64,
    pub origin: ChangeOrigin,
    pub details: ChangeDetails,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterInfoResult {
    pub controllers: Vec<Principal>,
    pub module_hash: Option<Vec<u8>>,
    pub recent_changes: Vec<Change>,
    pub total_num_changes: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SubnetInfoResult {
    pub replica_version: String,
}

// raw randomness

pub type RawRandResult = Vec<u8>;

// node metrics

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct NodeMetricsHistoryArgs {
    pub start_at_timestamp_nanos: u64,
    pub subnet_id: Principal,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct NodeMetrics {
    pub num_block_failures_total: u64,
    pub node_id: Principal,
    pub num_blocks_proposed_total: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct NodeMetricsHistoryResultItem {
    pub timestamp_nanos: u64,
    pub node_metrics: Vec<NodeMetrics>,
}

pub type NodeMetricsHistoryResult = Vec<NodeMetricsHistoryResultItem>;

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
    pub aux: Option<SignWithSchnorrAux>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum SignWithSchnorrAux {
    #[serde(rename = "bip341")]
    Bip341(SignWithBip341Aux),
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithBip341Aux {
    pub merkle_root_hash: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SignWithSchnorrResult {
    pub signature: Vec<u8>,
}

// bitcoin

#[derive(CandidType, Deserialize)]
pub enum BitcoinNetwork {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
}

pub type BitcoinAddress = String;

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetBalanceArgs {
    pub network: BitcoinNetwork,
    pub address: BitcoinAddress,
    pub min_confirmations: Option<u32>,
}

pub type Satoshi = u64;

pub type BitcoinGetBalanceResult = Satoshi;

#[derive(CandidType, Deserialize)]
pub enum BitcoinGetUtxosArgsFilterInner {
    #[serde(rename = "page")]
    Page(Vec<u8>),
    #[serde(rename = "min_confirmations")]
    MinConfirmations(u32),
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetUtxosArgs {
    pub network: BitcoinNetwork,
    pub filter: Option<BitcoinGetUtxosArgsFilterInner>,
    pub address: BitcoinAddress,
}

pub type BitcoinBlockHeight = u32;

pub type BitcoinBlockHash = Vec<u8>;

#[derive(CandidType, Deserialize)]
pub struct Outpoint {
    pub txid: Vec<u8>,
    pub vout: u32,
}

#[derive(CandidType, Deserialize)]
pub struct Utxo {
    pub height: u32,
    pub value: Satoshi,
    pub outpoint: Outpoint,
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetUtxosResult {
    pub next_page: Option<Vec<u8>>,
    pub tip_height: BitcoinBlockHeight,
    pub tip_block_hash: BitcoinBlockHash,
    pub utxos: Vec<Utxo>,
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinSendTransactionArgs {
    pub transaction: Vec<u8>,
    pub network: BitcoinNetwork,
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetCurrentFeePercentilesArgs {
    pub network: BitcoinNetwork,
}

pub type MillisatoshiPerByte = u64;

pub type BitcoinGetCurrentFeePercentilesResult = Vec<MillisatoshiPerByte>;

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetBlockHeadersArgs {
    pub start_height: BitcoinBlockHeight,
    pub end_height: Option<BitcoinBlockHeight>,
    pub network: BitcoinNetwork,
}

pub type BitcoinBlockHeader = Vec<u8>;

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetBlockHeadersResult {
    pub tip_height: BitcoinBlockHeight,
    pub block_headers: Vec<BitcoinBlockHeader>,
}
