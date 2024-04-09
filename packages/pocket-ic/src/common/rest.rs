//! The PocketIC server and the PocketIc library interface with HTTP/JSON.
//! The types in this module are used to serialize and deserialize data
//! from and to JSON, and are used by both crates.

use crate::UserError;
use candid::Principal;
use hex;
use reqwest::blocking::Response;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub type InstanceId = usize;

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum HttpGatewayBackend {
    Replica(String),
    PocketIcInstance(InstanceId),
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HttpGatewayConfig {
    pub listen_at: Option<u16>,
    pub forward_to: HttpGatewayBackend,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CreateHttpGatewayResponse {
    Created { instance_id: InstanceId, port: u16 },
    Error { message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CreateInstanceResponse {
    Created {
        instance_id: InstanceId,
        topology: Topology,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, Copy, JsonSchema)]
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
    Ok(RawWasmResult),
    Err(UserError),
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
pub enum RawWasmResult {
    /// Raw response, returned in a "happy" case
    Reply(
        #[serde(deserialize_with = "base64::deserialize")]
        #[serde(serialize_with = "base64::serialize")]
        Vec<u8>,
    ),
    /// Returned with an error message when the canister decides to reject the
    /// message
    Reject(String),
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

impl<T: DeserializeOwned> From<Response> for ApiResponse<T> {
    fn from(resp: Response) -> Self {
        match resp.status() {
            reqwest::StatusCode::OK => {
                let result = resp.json::<T>();
                match result {
                    Ok(t) => ApiResponse::Success(t),
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {}", e),
                    },
                }
            }
            reqwest::StatusCode::ACCEPTED => {
                let result = resp.json::<StartedOrBusyResponse>();
                match result {
                    Ok(StartedOrBusyResponse { state_label, op_id }) => {
                        ApiResponse::Started { state_label, op_id }
                    }
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {}", e),
                    },
                }
            }
            reqwest::StatusCode::CONFLICT => {
                let result = resp.json::<StartedOrBusyResponse>();
                match result {
                    Ok(StartedOrBusyResponse { state_label, op_id }) => {
                        ApiResponse::Busy { state_label, op_id }
                    }
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {}", e),
                    },
                }
            }
            _ => {
                let result = resp.json::<ApiError>();
                match result {
                    Ok(e) => ApiResponse::Error { message: e.message },
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse error: {}", e),
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

#[derive(Clone, Serialize, Eq, PartialEq, Deserialize, Debug, JsonSchema)]
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

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum SubnetKind {
    Application,
    Bitcoin,
    Fiduciary,
    II,
    NNS,
    SNS,
    System,
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
}

impl SubnetConfigSet {
    pub fn validate(&self) -> Result<(), String> {
        if self.system > 0
            || self.application > 0
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
        }
    }
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
}

/// Specifies various configurations for a subnet.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SubnetSpec {
    state_config: SubnetStateConfig,
    instruction_config: SubnetInstructionConfig,
    dts_flag: DtsFlag,
}

impl SubnetSpec {
    pub fn with_state_dir(mut self, path: PathBuf, subnet_id: SubnetId) -> SubnetSpec {
        self.state_config = SubnetStateConfig::FromPath(path, RawSubnetId::from(subnet_id));
        self
    }

    /// DTS is disabled on benchmarking subnet by default
    /// since running update calls with very high instruction counts and DTS enabled
    /// is very slow.
    /// You can enable DTS by using `.with_dts_flag(DtsConfig::Enabled)`.
    pub fn with_benchmarking_instruction_config(mut self) -> SubnetSpec {
        self.instruction_config = SubnetInstructionConfig::Benchmarking;
        self.dts_flag = DtsFlag::Disabled;
        self
    }

    pub fn with_dts_flag(mut self, dts_flag: DtsFlag) -> SubnetSpec {
        self.dts_flag = dts_flag;
        self
    }

    pub fn get_state_path(&self) -> Option<PathBuf> {
        self.state_config.get_path()
    }

    pub fn get_dts_flag(&self) -> DtsFlag {
        self.dts_flag
    }

    pub fn get_subnet_id(&self) -> Option<RawSubnetId> {
        match &self.state_config {
            SubnetStateConfig::New => None,
            SubnetStateConfig::FromPath(_, subnet_id) => Some(subnet_id.clone()),
            SubnetStateConfig::FromBlobStore(_, subnet_id) => Some(subnet_id.clone()),
        }
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
            dts_flag: DtsFlag::Enabled,
        }
    }
}

/// Specifies instruction limits for canister execution on this subnet.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum SubnetInstructionConfig {
    /// Use default instruction limits as in production.
    Production,
    /// Use very high instruction limits useful for asymptotic canister benchmarking.
    Benchmarking,
}

/// Specifies whether DTS should be disabled on this subnet.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum DtsFlag {
    Enabled,
    Disabled,
}

/// Specifies whether the subnet should be created from scratch or loaded
/// from a path.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum SubnetStateConfig {
    /// Create new subnet with empty state.
    New,
    /// Load existing subnet state from the given path.
    /// The path must be on a filesystem accessible to the server process.
    FromPath(PathBuf, RawSubnetId),
    /// Load existing subnet state from blobstore. Needs to be uploaded first!
    /// Not implemented!
    FromBlobStore(BlobId, RawSubnetId),
}

impl SubnetStateConfig {
    pub fn get_path(&self) -> Option<PathBuf> {
        match self {
            SubnetStateConfig::FromPath(path, _) => Some(path.clone()),
            SubnetStateConfig::FromBlobStore(_, _) => None,
            SubnetStateConfig::New => None,
        }
    }
    pub fn get_subnet_id(&self) -> Option<RawSubnetId> {
        match self {
            SubnetStateConfig::FromPath(_, id) => Some(id.clone()),
            SubnetStateConfig::FromBlobStore(_, id) => Some(id.clone()),
            SubnetStateConfig::New => None,
        }
    }
}

impl ExtendedSubnetConfigSet {
    // Return the configured named subnets in order.
    pub fn get_named(
        &self,
    ) -> Vec<(
        SubnetKind,
        Option<PathBuf>,
        SubnetInstructionConfig,
        DtsFlag,
    )> {
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
            (
                kind,
                spec.get_state_path(),
                spec.get_instruction_config(),
                spec.get_dts_flag(),
            )
        })
        .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.system.is_empty()
            || !self.application.is_empty()
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

    pub fn with_dts_flag(mut self, dts_flag: DtsFlag) -> ExtendedSubnetConfigSet {
        self.nns = self.nns.map(|nns| nns.with_dts_flag(dts_flag));
        self.sns = self.sns.map(|sns| sns.with_dts_flag(dts_flag));
        self.ii = self.ii.map(|ii| ii.with_dts_flag(dts_flag));
        self.fiduciary = self
            .fiduciary
            .map(|fiduciary| fiduciary.with_dts_flag(dts_flag));
        self.bitcoin = self.bitcoin.map(|bitcoin| bitcoin.with_dts_flag(dts_flag));
        self.system = self
            .system
            .into_iter()
            .map(|conf| conf.with_dts_flag(dts_flag))
            .collect();
        self.application = self
            .application
            .into_iter()
            .map(|conf| conf.with_dts_flag(dts_flag))
            .collect();
        self
    }
}

/// Configuration details for a subnet, returned by PocketIc server
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SubnetConfig {
    pub subnet_kind: SubnetKind,
    /// Instruction limits for canister execution on this subnet.
    pub instruction_config: SubnetInstructionConfig,
    /// Number of nodes in the subnet.
    pub size: u64,
    /// Some mainnet subnets have several disjunct canister ranges.
    pub canister_ranges: Vec<CanisterIdRange>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CanisterIdRange {
    pub start: RawCanisterId,
    pub end: RawCanisterId,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Topology(pub HashMap<SubnetId, SubnetConfig>);

impl Topology {
    pub fn get_app_subnets(&self) -> Vec<SubnetId> {
        self.find_subnets(SubnetKind::Application, None)
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
        self.0
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
        self.0
            .iter()
            .find(|(_, config)| config.subnet_kind == kind)
            .map(|(id, _)| *id)
    }
}
