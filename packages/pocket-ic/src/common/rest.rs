//! The PocketIC server and the PocketIc library interface with HTTP/JSON.
//! The types in this module are used to serialize and deserialize data
//! from and to JSON, and are used by both crates.

use crate::RejectResponse;
use candid::Principal;
use hex;
use reqwest::Response;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use strum_macros::EnumIter;

pub type InstanceId = usize;

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AutoProgressConfig {
    pub artificial_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum HttpGatewayBackend {
    Replica(String),
    PocketIcInstance(InstanceId),
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HttpsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InstanceHttpGatewayConfig {
    pub ip_addr: Option<String>,
    pub port: Option<u16>,
    pub domains: Option<Vec<String>>,
    pub https_config: Option<HttpsConfig>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HttpGatewayConfig {
    pub ip_addr: Option<String>,
    pub port: Option<u16>,
    pub forward_to: HttpGatewayBackend,
    pub domains: Option<Vec<String>>,
    pub https_config: Option<HttpsConfig>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HttpGatewayDetails {
    pub instance_id: InstanceId,
    pub port: u16,
    pub forward_to: HttpGatewayBackend,
    pub domains: Option<Vec<String>>,
    pub https_config: Option<HttpsConfig>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HttpGatewayInfo {
    pub instance_id: InstanceId,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CreateHttpGatewayResponse {
    Created(HttpGatewayInfo),
    Error { message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CreateInstanceResponse {
    Created {
        instance_id: InstanceId,
        topology: Topology,
        http_gateway_info: Option<HttpGatewayInfo>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RawTime {
    pub nanos_since_epoch: u64,
}

/// Relevant for calls to the management canister. If a subnet ID is
/// provided, the call will be sent to the management canister of that subnet.
/// If a canister ID is provided, the call will be sent to the management
/// canister of the subnet where the canister is on.
/// If None, the call will be sent to any management canister.
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema, PartialEq, Eq, Hash)]
pub enum RawEffectivePrincipal {
    None,
    SubnetId(
        #[serde(deserialize_with = "base64::deserialize")]
        #[serde(serialize_with = "base64::serialize")]
        Vec<u8>,
    ),
    CanisterId(
        #[serde(deserialize_with = "base64::deserialize")]
        #[serde(serialize_with = "base64::serialize")]
        Vec<u8>,
    ),
}

impl std::fmt::Display for RawEffectivePrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RawEffectivePrincipal::None => write!(f, "None"),
            RawEffectivePrincipal::SubnetId(subnet_id) => {
                let principal = Principal::from_slice(subnet_id);
                write!(f, "SubnetId({principal})")
            }
            RawEffectivePrincipal::CanisterId(canister_id) => {
                let principal = Principal::from_slice(canister_id);
                write!(f, "CanisterId({principal})")
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawMessageId {
    pub effective_principal: RawEffectivePrincipal,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub message_id: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawIngressStatusArgs {
    pub raw_message_id: RawMessageId,
    pub raw_caller: Option<RawPrincipalId>,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawCanisterCall {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub sender: Vec<u8>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub canister_id: Vec<u8>,
    pub effective_principal: RawEffectivePrincipal,
    pub method: String,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub enum RawCanisterResult {
    Ok(
        #[serde(deserialize_with = "base64::deserialize")]
        #[serde(serialize_with = "base64::serialize")]
        Vec<u8>,
    ),
    Err(RejectResponse),
}

impl From<Result<Vec<u8>, RejectResponse>> for RawCanisterResult {
    fn from(result: Result<Vec<u8>, RejectResponse>) -> Self {
        match result {
            Ok(data) => RawCanisterResult::Ok(data),
            Err(reject_response) => RawCanisterResult::Err(reject_response),
        }
    }
}

impl From<RawCanisterResult> for Result<Vec<u8>, RejectResponse> {
    fn from(result: RawCanisterResult) -> Self {
        match result {
            RawCanisterResult::Ok(data) => Ok(data),
            RawCanisterResult::Err(reject_response) => Err(reject_response),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawSetStableMemory {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub canister_id: Vec<u8>,
    pub blob_id: BlobId,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawStableMemory {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub blob: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct ApiError {
    message: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct StartedOrBusyResponse {
    pub state_label: String,
    pub op_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
#[serde(untagged)]
pub enum ApiResponse<T> {
    Success(T),
    Busy { state_label: String, op_id: String },
    Started { state_label: String, op_id: String },
    Error { message: String },
}

impl<T: DeserializeOwned> ApiResponse<T> {
    pub async fn from_response(resp: Response) -> Self {
        match resp.status() {
            reqwest::StatusCode::OK => {
                let result = resp.json::<T>().await;
                match result {
                    Ok(t) => ApiResponse::Success(t),
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {e}"),
                    },
                }
            }
            reqwest::StatusCode::ACCEPTED => {
                let result = resp.json::<StartedOrBusyResponse>().await;
                match result {
                    Ok(StartedOrBusyResponse { state_label, op_id }) => {
                        ApiResponse::Started { state_label, op_id }
                    }
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {e}"),
                    },
                }
            }
            reqwest::StatusCode::CONFLICT => {
                let result = resp.json::<StartedOrBusyResponse>().await;
                match result {
                    Ok(StartedOrBusyResponse { state_label, op_id }) => {
                        ApiResponse::Busy { state_label, op_id }
                    }
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {e}"),
                    },
                }
            }
            _ => {
                let result = resp.json::<ApiError>().await;
                match result {
                    Ok(e) => ApiResponse::Error { message: e.message },
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse error: {e}"),
                    },
                }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawAddCycles {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub canister_id: Vec<u8>,
    pub amount: u128,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawCycles {
    pub cycles: u128,
}

#[derive(Clone, Serialize, Eq, PartialEq, Ord, PartialOrd, Deserialize, Debug, JsonSchema)]
pub struct RawPrincipalId {
    // raw bytes of the principal
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub principal_id: Vec<u8>,
}

impl From<Principal> for RawPrincipalId {
    fn from(principal: Principal) -> Self {
        Self {
            principal_id: principal.as_slice().to_vec(),
        }
    }
}

impl From<RawPrincipalId> for Principal {
    fn from(raw_principal_id: RawPrincipalId) -> Self {
        Principal::from_slice(&raw_principal_id.principal_id)
    }
}

#[derive(Clone, Serialize, Eq, PartialEq, Ord, PartialOrd, Deserialize, Debug, JsonSchema)]
pub struct RawCanisterId {
    // raw bytes of the principal
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub canister_id: Vec<u8>,
}

impl From<Principal> for RawCanisterId {
    fn from(principal: Principal) -> Self {
        Self {
            canister_id: principal.as_slice().to_vec(),
        }
    }
}

impl From<RawCanisterId> for Principal {
    fn from(raw_canister_id: RawCanisterId) -> Self {
        Principal::from_slice(&raw_canister_id.canister_id)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema, PartialEq, Eq, Hash)]
pub struct RawSubnetId {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub subnet_id: Vec<u8>,
}

pub type SubnetId = Principal;

impl From<Principal> for RawSubnetId {
    fn from(principal: Principal) -> Self {
        Self {
            subnet_id: principal.as_slice().to_vec(),
        }
    }
}

impl From<RawSubnetId> for Principal {
    fn from(val: RawSubnetId) -> Self {
        Principal::from_slice(&val.subnet_id)
    }
}

#[derive(
    Clone, Serialize, Deserialize, Debug, JsonSchema, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct RawNodeId {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub node_id: Vec<u8>,
}

impl From<RawNodeId> for Principal {
    fn from(val: RawNodeId) -> Self {
        Principal::from_slice(&val.node_id)
    }
}

impl From<Principal> for RawNodeId {
    fn from(principal: Principal) -> Self {
        Self {
            node_id: principal.as_slice().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RawTickConfigs {
    pub blockmakers: Option<Vec<RawSubnetBlockmakers>>,
    pub first_subnet: Option<RawSubnetId>,
    pub last_subnet: Option<RawSubnetId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RawSubnetBlockmakers {
    pub subnet: RawSubnetId,
    pub blockmaker: RawNodeId,
    pub failed_blockmakers: Vec<RawNodeId>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RawVerifyCanisterSigArg {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub sig: Vec<u8>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub pubkey: Vec<u8>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub root_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BlobId(
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub Vec<u8>,
);

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BlobId{{{}}}", hex::encode(self.0.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct BinaryBlob {
    pub data: Vec<u8>,
    pub compression: BlobCompression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema)]
pub enum BlobCompression {
    Gzip,
    NoCompression,
}

// By default, serde serializes Vec<u8> to a list of numbers, which is inefficient.
// This enables serializing Vec<u8> to a compact base64 representation.
#[allow(deprecated)]
pub mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}

// ================================================================================================================= //

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    Hash,
    PartialEq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    JsonSchema,
    EnumIter,
)]
pub enum SubnetKind {
    Application,
    Bitcoin,
    Fiduciary,
    II,
    NNS,
    SNS,
    System,
    VerifiedApplication,
}

/// This represents which named subnets the user wants to create, and how
/// many of the general app/system subnets, which are indistinguishable.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub struct SubnetConfigSet {
    pub nns: bool,
    pub sns: bool,
    pub ii: bool,
    pub fiduciary: bool,
    pub bitcoin: bool,
    pub system: usize,
    pub application: usize,
    pub verified_application: usize,
}

impl SubnetConfigSet {
    pub fn validate(&self) -> Result<(), String> {
        if self.system > 0
            || self.application > 0
            || self.verified_application > 0
            || self.nns
            || self.sns
            || self.ii
            || self.fiduciary
            || self.bitcoin
        {
            return Ok(());
        }
        Err("SubnetConfigSet must contain at least one subnet".to_owned())
    }
}

impl From<SubnetConfigSet> for ExtendedSubnetConfigSet {
    fn from(
        SubnetConfigSet {
            nns,
            sns,
            ii,
            fiduciary: fid,
            bitcoin,
            system,
            application,
            verified_application,
        }: SubnetConfigSet,
    ) -> Self {
        ExtendedSubnetConfigSet {
            nns: if nns {
                Some(SubnetSpec::default())
            } else {
                None
            },
            sns: if sns {
                Some(SubnetSpec::default())
            } else {
                None
            },
            ii: if ii {
                Some(SubnetSpec::default())
            } else {
                None
            },
            fiduciary: if fid {
                Some(SubnetSpec::default())
            } else {
                None
            },
            bitcoin: if bitcoin {
                Some(SubnetSpec::default())
            } else {
                None
            },
            system: vec![SubnetSpec::default(); system],
            application: vec![SubnetSpec::default(); application],
            verified_application: vec![SubnetSpec::default(); verified_application],
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum IcpConfigFlag {
    Disabled,
    Enabled,
}

/// Specifies ICP config of this instance.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub struct IcpConfig {
    /// Beta features (disabled on the ICP mainnet).
    pub beta_features: Option<IcpConfigFlag>,
    /// Canister backtraces (enabled on the ICP mainnet).
    pub canister_backtrace: Option<IcpConfigFlag>,
    /// Limits on function name length in canister WASM (enabled on the ICP mainnet).
    pub function_name_length_limits: Option<IcpConfigFlag>,
    /// Rate-limiting of canister execution (enabled on the ICP mainnet).
    /// Canister execution refers to instructions and memory writes here.
    pub canister_execution_rate_limiting: Option<IcpConfigFlag>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub enum IcpFeaturesConfig {
    /// Default configuration of an ICP feature resembling mainnet configuration as closely as possible.
    #[default]
    DefaultConfig,
}

/// Specifies ICP features enabled by deploying their corresponding system canisters
/// when creating a PocketIC instance and keeping them up to date
/// during the PocketIC instance lifetime.
/// The subnets to which the corresponding system canisters are deployed must be empty,
/// i.e., their corresponding field in `ExtendedSubnetConfigSet` must be `None`
/// or `Some(config)` with `config.state_config = SubnetStateConfig::New`.
/// An ICP feature is enabled if its `IcpFeaturesConfig` is provided, i.e.,
/// if the corresponding field is not `None`.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub struct IcpFeatures {
    /// Deploys the NNS registry canister and keeps its content in sync with registry used internally by PocketIC.
    /// Subnets: NNS.
    pub registry: Option<IcpFeaturesConfig>,
    /// Deploys the NNS cycles minting canister, sets ICP/XDR conversion rate, and keeps its subnet lists in sync with PocketIC topology.
    /// If the `cycles_minting` feature is enabled, then the default timestamp of a PocketIC instance is set to 10 May 2021 10:00:01 AM CEST (the smallest value that is strictly larger than the default timestamp hard-coded in the CMC state).
    /// Subnets: NNS.
    pub cycles_minting: Option<IcpFeaturesConfig>,
    /// Deploys the ICP ledger and index canisters and initializes the ICP account of the anonymous principal with 1,000,000,000 ICP.
    /// Subnets: NNS.
    pub icp_token: Option<IcpFeaturesConfig>,
    /// Deploys the cycles ledger and index canisters and initializes the cycles account of the anonymous principal with 2^127 cycles.
    /// Subnets: II.
    pub cycles_token: Option<IcpFeaturesConfig>,
    /// Deploys the NNS governance and root canisters and sets up an initial NNS neuron with 1 ICP stake.
    /// The initial NNS neuron is controlled by the anonymous principal.
    /// Subnets: NNS.
    pub nns_governance: Option<IcpFeaturesConfig>,
    /// Deploys the SNS-W and aggregator canisters, sets up the SNS subnet list in the SNS-W canister according to PocketIC topology,
    /// and uploads the SNS canister WASMs to the SNS-W canister.
    /// Subnets: NNS, SNS.
    pub sns: Option<IcpFeaturesConfig>,
    /// Deploys the Internet Identity canister.
    /// Subnets: II.
    pub ii: Option<IcpFeaturesConfig>,
    /// Deploys the NNS frontend dapp. The HTTP gateway must be specified via `http_gateway_config` in `InstanceConfig`
    /// and the ICP features `cycles_minting`, `icp_token`, `nns_governance`, `sns`, `ii` must all be enabled.
    /// Subnets: NNS.
    pub nns_ui: Option<IcpFeaturesConfig>,
    /// Deploys the Bitcoin canister under the testnet canister ID `g4xu7-jiaaa-aaaan-aaaaq-cai` and configured for the regtest network.
    /// Subnets: Bitcoin.
    pub bitcoin: Option<IcpFeaturesConfig>,
    /// Deploys the Dogecoin canister under the mainnet canister ID `gordg-fyaaa-aaaan-aaadq-cai` and configured for the regtest network.
    /// Subnets: Bitcoin.
    pub dogecoin: Option<IcpFeaturesConfig>,
    /// Deploys the canister migration orchestrator canister.
    /// Subnets: NNS.
    pub canister_migration: Option<IcpFeaturesConfig>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum InitialTime {
    /// Sets the initial timestamp of the new instance to the provided value which must be at least
    /// - 10 May 2021 10:00:01 AM CEST if the `cycles_minting` feature is enabled in `icp_features`;
    /// - 06 May 2021 21:17:10 CEST otherwise.
    Timestamp(RawTime),
    /// Configures the new instance to make progress automatically,
    /// i.e., periodically update the time of the IC instance
    /// to the real time and execute rounds on the subnets.
    AutoProgress(AutoProgressConfig),
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub enum IncompleteStateFlag {
    #[default]
    Disabled,
    Enabled,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub struct InstanceConfig {
    pub subnet_config_set: ExtendedSubnetConfigSet,
    pub http_gateway_config: Option<InstanceHttpGatewayConfig>,
    pub state_dir: Option<PathBuf>,
    pub icp_config: Option<IcpConfig>,
    pub log_level: Option<String>,
    pub bitcoind_addr: Option<Vec<SocketAddr>>,
    pub dogecoind_addr: Option<Vec<SocketAddr>>,
    pub icp_features: Option<IcpFeatures>,
    pub incomplete_state: Option<IncompleteStateFlag>,
    pub initial_time: Option<InitialTime>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Default, JsonSchema)]
pub struct ExtendedSubnetConfigSet {
    pub nns: Option<SubnetSpec>,
    pub sns: Option<SubnetSpec>,
    pub ii: Option<SubnetSpec>,
    pub fiduciary: Option<SubnetSpec>,
    pub bitcoin: Option<SubnetSpec>,
    pub system: Vec<SubnetSpec>,
    pub application: Vec<SubnetSpec>,
    pub verified_application: Vec<SubnetSpec>,
}

/// Specifies various configurations for a subnet.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SubnetSpec {
    state_config: SubnetStateConfig,
    instruction_config: SubnetInstructionConfig,
}

impl SubnetSpec {
    pub fn with_state_dir(mut self, path: PathBuf) -> SubnetSpec {
        self.state_config = SubnetStateConfig::FromPath(path);
        self
    }

    pub fn with_benchmarking_instruction_config(mut self) -> SubnetSpec {
        self.instruction_config = SubnetInstructionConfig::Benchmarking;
        self
    }

    pub fn get_state_path(&self) -> Option<PathBuf> {
        self.state_config.get_path()
    }

    pub fn get_instruction_config(&self) -> SubnetInstructionConfig {
        self.instruction_config.clone()
    }

    pub fn is_supported(&self) -> bool {
        match &self.state_config {
            SubnetStateConfig::New => true,
            SubnetStateConfig::FromPath(..) => true,
            SubnetStateConfig::FromBlobStore(..) => false,
        }
    }
}

impl Default for SubnetSpec {
    fn default() -> Self {
        Self {
            state_config: SubnetStateConfig::New,
            instruction_config: SubnetInstructionConfig::Production,
        }
    }
}

/// Specifies instruction limits for canister execution on this subnet.
#[derive(
    Debug, Clone, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
pub enum SubnetInstructionConfig {
    /// Use default instruction limits as in production.
    Production,
    /// Use very high instruction limits useful for asymptotic canister benchmarking.
    Benchmarking,
}

/// Specifies whether the subnet should be created from scratch or loaded
/// from a path.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum SubnetStateConfig {
    /// Create new subnet with empty state.
    New,
    /// Load existing subnet state from the given path.
    /// The path must be on a filesystem accessible to the server process.
    FromPath(PathBuf),
    /// Load existing subnet state from blobstore. Needs to be uploaded first!
    /// Not implemented!
    FromBlobStore(BlobId),
}

impl SubnetStateConfig {
    pub fn get_path(&self) -> Option<PathBuf> {
        match self {
            SubnetStateConfig::FromPath(path) => Some(path.clone()),
            SubnetStateConfig::FromBlobStore(_) => None,
            SubnetStateConfig::New => None,
        }
    }
}

impl ExtendedSubnetConfigSet {
    // Return the configured named subnets in order.
    #[allow(clippy::type_complexity)]
    pub fn get_named(&self) -> Vec<(SubnetKind, Option<PathBuf>, SubnetInstructionConfig)> {
        use SubnetKind::*;
        vec![
            (self.nns.clone(), NNS),
            (self.sns.clone(), SNS),
            (self.ii.clone(), II),
            (self.fiduciary.clone(), Fiduciary),
            (self.bitcoin.clone(), Bitcoin),
        ]
        .into_iter()
        .filter(|(mb, _)| mb.is_some())
        .map(|(mb, kind)| {
            let spec = mb.unwrap();
            (kind, spec.get_state_path(), spec.get_instruction_config())
        })
        .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.system.is_empty()
            || !self.application.is_empty()
            || !self.verified_application.is_empty()
            || self.nns.is_some()
            || self.sns.is_some()
            || self.ii.is_some()
            || self.fiduciary.is_some()
            || self.bitcoin.is_some()
        {
            return Ok(());
        }
        Err("ExtendedSubnetConfigSet must contain at least one subnet".to_owned())
    }

    pub fn try_with_icp_features(mut self, icp_features: &IcpFeatures) -> Result<Self, String> {
        let check_empty_subnet = |subnet: &Option<SubnetSpec>, subnet_desc, icp_feature| {
            if let Some(config) = subnet
                && !matches!(config.state_config, SubnetStateConfig::New)
            {
                return Err(format!(
                    "The {subnet_desc} subnet must be empty when specifying the `{icp_feature}` ICP feature."
                ));
            }
            Ok(())
        };
        // using `let IcpFeatures { }` with explicit field names
        // to force an update after adding a new field to `IcpFeatures`
        let IcpFeatures {
            registry,
            cycles_minting,
            icp_token,
            cycles_token,
            nns_governance,
            sns,
            ii,
            nns_ui,
            bitcoin,
            dogecoin,
            canister_migration,
        } = icp_features;
        // NNS canisters
        for (flag, icp_feature_str) in [
            (registry, "registry"),
            (cycles_minting, "cycles_minting"),
            (icp_token, "icp_token"),
            (nns_governance, "nns_governance"),
            (sns, "sns"),
            (nns_ui, "nns_ui"),
            (canister_migration, "canister_migration"),
        ] {
            if flag.is_some() {
                check_empty_subnet(&self.nns, "NNS", icp_feature_str)?;
                self.nns = Some(self.nns.unwrap_or_default());
            }
        }
        // canisters on the II subnet
        for (flag, icp_feature_str) in [(cycles_token, "cycles_token"), (ii, "ii")] {
            if flag.is_some() {
                check_empty_subnet(&self.ii, "II", icp_feature_str)?;
                self.ii = Some(self.ii.unwrap_or_default());
            }
        }
        // canisters on the SNS subnet
        for (flag, icp_feature_str) in [(sns, "sns")] {
            if flag.is_some() {
                check_empty_subnet(&self.sns, "SNS", icp_feature_str)?;
                self.sns = Some(self.sns.unwrap_or_default());
            }
        }
        // canisters on the Bitcoin subnet
        for (flag, icp_feature_str) in [(bitcoin, "bitcoin"), (dogecoin, "dogecoin")] {
            if flag.is_some() {
                check_empty_subnet(&self.bitcoin, "Bitcoin", icp_feature_str)?;
                self.bitcoin = Some(self.bitcoin.unwrap_or_default());
            }
        }
        Ok(self)
    }
}

/// Configuration details for a subnet, returned by PocketIc server
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
pub struct SubnetConfig {
    pub subnet_kind: SubnetKind,
    pub subnet_seed: [u8; 32],
    /// Instruction limits for canister execution on this subnet.
    pub instruction_config: SubnetInstructionConfig,
    /// Some mainnet subnets have several disjunct canister ranges.
    pub canister_ranges: Vec<CanisterIdRange>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
pub struct CanisterIdRange {
    pub start: RawCanisterId,
    pub end: RawCanisterId,
}

impl CanisterIdRange {
    fn contains(&self, canister_id: Principal) -> bool {
        Principal::from_slice(&self.start.canister_id) <= canister_id
            && canister_id <= Principal::from_slice(&self.end.canister_id)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
pub struct Topology {
    pub subnet_configs: BTreeMap<SubnetId, SubnetConfig>,
    pub default_effective_canister_id: RawCanisterId,
}

impl Topology {
    pub fn get_subnet(&self, canister_id: Principal) -> Option<SubnetId> {
        self.subnet_configs
            .iter()
            .find(|(_, config)| {
                config
                    .canister_ranges
                    .iter()
                    .any(|r| r.contains(canister_id))
            })
            .map(|(subnet_id, _)| subnet_id)
            .copied()
    }

    pub fn get_app_subnets(&self) -> Vec<SubnetId> {
        self.find_subnets(SubnetKind::Application, None)
    }

    pub fn get_verified_app_subnets(&self) -> Vec<SubnetId> {
        self.find_subnets(SubnetKind::VerifiedApplication, None)
    }

    pub fn get_benchmarking_app_subnets(&self) -> Vec<SubnetId> {
        self.find_subnets(
            SubnetKind::Application,
            Some(SubnetInstructionConfig::Benchmarking),
        )
    }

    pub fn get_bitcoin(&self) -> Option<SubnetId> {
        self.find_subnet(SubnetKind::Bitcoin)
    }

    pub fn get_fiduciary(&self) -> Option<SubnetId> {
        self.find_subnet(SubnetKind::Fiduciary)
    }

    pub fn get_ii(&self) -> Option<SubnetId> {
        self.find_subnet(SubnetKind::II)
    }

    pub fn get_nns(&self) -> Option<SubnetId> {
        self.find_subnet(SubnetKind::NNS)
    }

    pub fn get_sns(&self) -> Option<SubnetId> {
        self.find_subnet(SubnetKind::SNS)
    }

    pub fn get_system_subnets(&self) -> Vec<SubnetId> {
        self.find_subnets(SubnetKind::System, None)
    }

    fn find_subnets(
        &self,
        kind: SubnetKind,
        instruction_config: Option<SubnetInstructionConfig>,
    ) -> Vec<SubnetId> {
        self.subnet_configs
            .iter()
            .filter(|(_, config)| {
                config.subnet_kind == kind
                    && instruction_config
                        .as_ref()
                        .map(|instruction_config| config.instruction_config == *instruction_config)
                        .unwrap_or(true)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    fn find_subnet(&self, kind: SubnetKind) -> Option<SubnetId> {
        self.subnet_configs
            .iter()
            .find(|(_, config)| config.subnet_kind == kind)
            .map(|(id, _)| *id)
    }
}

#[derive(
    Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, JsonSchema,
)]
pub enum CanisterHttpMethod {
    GET,
    POST,
    HEAD,
}

#[derive(
    Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, JsonSchema,
)]
pub struct CanisterHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawCanisterHttpRequest {
    pub subnet_id: RawSubnetId,
    pub request_id: u64,
    pub http_method: CanisterHttpMethod,
    pub url: String,
    pub headers: Vec<CanisterHttpHeader>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub body: Vec<u8>,
    pub max_response_bytes: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanisterHttpRequest {
    pub subnet_id: Principal,
    pub request_id: u64,
    pub http_method: CanisterHttpMethod,
    pub url: String,
    pub headers: Vec<CanisterHttpHeader>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub body: Vec<u8>,
    pub max_response_bytes: Option<u64>,
}

impl From<RawCanisterHttpRequest> for CanisterHttpRequest {
    fn from(raw_canister_http_request: RawCanisterHttpRequest) -> Self {
        Self {
            subnet_id: candid::Principal::from_slice(
                &raw_canister_http_request.subnet_id.subnet_id,
            ),
            request_id: raw_canister_http_request.request_id,
            http_method: raw_canister_http_request.http_method,
            url: raw_canister_http_request.url,
            headers: raw_canister_http_request.headers,
            body: raw_canister_http_request.body,
            max_response_bytes: raw_canister_http_request.max_response_bytes,
        }
    }
}

impl From<CanisterHttpRequest> for RawCanisterHttpRequest {
    fn from(canister_http_request: CanisterHttpRequest) -> Self {
        Self {
            subnet_id: canister_http_request.subnet_id.into(),
            request_id: canister_http_request.request_id,
            http_method: canister_http_request.http_method,
            url: canister_http_request.url,
            headers: canister_http_request.headers,
            body: canister_http_request.body,
            max_response_bytes: canister_http_request.max_response_bytes,
        }
    }
}

#[derive(
    Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, JsonSchema,
)]
pub struct CanisterHttpReply {
    pub status: u16,
    pub headers: Vec<CanisterHttpHeader>,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub body: Vec<u8>,
}

#[derive(
    Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, JsonSchema,
)]
pub struct CanisterHttpReject {
    pub reject_code: u64,
    pub message: String,
}

#[derive(
    Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, JsonSchema,
)]
pub enum CanisterHttpResponse {
    CanisterHttpReply(CanisterHttpReply),
    CanisterHttpReject(CanisterHttpReject),
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawMockCanisterHttpResponse {
    pub subnet_id: RawSubnetId,
    pub request_id: u64,
    pub response: CanisterHttpResponse,
    pub additional_responses: Vec<CanisterHttpResponse>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct MockCanisterHttpResponse {
    pub subnet_id: Principal,
    pub request_id: u64,
    pub response: CanisterHttpResponse,
    pub additional_responses: Vec<CanisterHttpResponse>,
}

impl From<RawMockCanisterHttpResponse> for MockCanisterHttpResponse {
    fn from(raw_mock_canister_http_response: RawMockCanisterHttpResponse) -> Self {
        Self {
            subnet_id: candid::Principal::from_slice(
                &raw_mock_canister_http_response.subnet_id.subnet_id,
            ),
            request_id: raw_mock_canister_http_response.request_id,
            response: raw_mock_canister_http_response.response,
            additional_responses: raw_mock_canister_http_response.additional_responses,
        }
    }
}

impl From<MockCanisterHttpResponse> for RawMockCanisterHttpResponse {
    fn from(mock_canister_http_response: MockCanisterHttpResponse) -> Self {
        Self {
            subnet_id: RawSubnetId {
                subnet_id: mock_canister_http_response.subnet_id.as_slice().to_vec(),
            },
            request_id: mock_canister_http_response.request_id,
            response: mock_canister_http_response.response,
            additional_responses: mock_canister_http_response.additional_responses,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawCanisterSnapshotDownload {
    pub sender: RawPrincipalId,
    pub canister_id: RawCanisterId,
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub snapshot_id: Vec<u8>,
    pub snapshot_dir: PathBuf,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawCanisterSnapshotUpload {
    pub sender: RawPrincipalId,
    pub canister_id: RawCanisterId,
    pub replace_snapshot: Option<RawCanisterSnapshotId>,
    pub snapshot_dir: PathBuf,
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub struct RawCanisterSnapshotId {
    #[serde(deserialize_with = "base64::deserialize")]
    #[serde(serialize_with = "base64::serialize")]
    pub snapshot_id: Vec<u8>,
}
