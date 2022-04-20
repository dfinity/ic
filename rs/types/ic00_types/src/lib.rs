//! Data types used for encoding/decoding the Candid payloads of ic:00.
use candid::{CandidType, Decode, Deserialize, Encode};
use ic_base_types::{CanisterId, NodeId, NumBytes, PrincipalId, RegistryVersion, SubnetId};
use ic_error_types::{ErrorCode, UserError};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use num_traits::cast::ToPrimitive;
use serde::Serialize;
use std::{collections::BTreeSet, convert::TryFrom, fmt, slice::Iter};
use strum_macros::{Display, EnumIter, EnumString};

/// The id of the management canister.
pub const IC_00: CanisterId = CanisterId::ic_00();
pub const MAX_CONTROLLERS: usize = 10;

/// Methods exported by ic:00.
#[derive(Debug, EnumString, EnumIter, Display, Copy, Clone)]
#[strum(serialize_all = "snake_case")]
pub enum Method {
    CanisterStatus,
    CreateCanister,
    DeleteCanister,
    DepositCycles,
    HttpRequest,
    ECDSAPublicKey,
    InstallCode,
    RawRand,
    SetController,
    SetupInitialDKG,
    SignWithECDSA,
    StartCanister,
    StopCanister,
    UninstallCode,
    UpdateSettings,
    ComputeInitialEcdsaDealings,

    // Bitcoin Testnet Canister
    BitcoinTestnetGetBalance,
    BitcoinTestnetGetUtxos,
    BitcoinTestnetSendTransaction,

    // These methods are added for the Mercury I release.
    // They should be removed afterwards.
    ProvisionalCreateCanisterWithCycles,
    ProvisionalTopUpCanister,
}

/// A trait to be implemented by all structs that are used as payloads
/// by IC00. This trait encapsulates Candid serialization so that
/// consumers of IC00 don't need to explicitly depend on Candid.
pub trait Payload<'a>: Sized + CandidType + Deserialize<'a> {
    fn encode(&self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }

    fn decode(blob: &'a [u8]) -> Result<Self, candid::Error> {
        Decode!(blob, Self)
    }
}

/// Struct used for encoding/decoding `(record {canister_id})`.
#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct CanisterIdRecord {
    canister_id: PrincipalId,
}

impl CanisterIdRecord {
    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }
}

impl Payload<'_> for CanisterIdRecord {}

impl From<CanisterId> for CanisterIdRecord {
    fn from(canister_id: CanisterId) -> Self {
        Self {
            canister_id: canister_id.into(),
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     controller : principal;
///     compute_allocation: nat;
///     memory_allocation: opt nat;
/// })`
#[derive(CandidType, Deserialize, Debug, Eq, PartialEq)]
pub struct DefiniteCanisterSettingsArgs {
    controller: PrincipalId,
    controllers: Vec<PrincipalId>,
    compute_allocation: candid::Nat,
    memory_allocation: candid::Nat,
    freezing_threshold: candid::Nat,
}

impl DefiniteCanisterSettingsArgs {
    pub fn new(
        controller: PrincipalId,
        controllers: Vec<PrincipalId>,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
    ) -> Self {
        let memory_allocation = match memory_allocation {
            None => candid::Nat::from(0),
            Some(memory) => candid::Nat::from(memory),
        };
        Self {
            controller,
            controllers,
            compute_allocation: candid::Nat::from(compute_allocation),
            memory_allocation,
            freezing_threshold: candid::Nat::from(freezing_threshold),
        }
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.controllers.clone()
    }
}

impl Payload<'_> for DefiniteCanisterSettingsArgs {}

/// The deprecated version of CanisterStatusResult that is being
/// used by NNS canisters.
#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct CanisterStatusResult {
    status: CanisterStatusType,
    module_hash: Option<Vec<u8>>,
    controller: candid::Principal,
    memory_size: candid::Nat,
    cycles: candid::Nat,
    // this is for compat with Spec 0.12/0.13
    balance: Vec<(Vec<u8>, candid::Nat)>,
}

impl CanisterStatusResult {
    pub fn new(
        status: CanisterStatusType,
        module_hash: Option<Vec<u8>>,
        controller: PrincipalId,
        memory_size: NumBytes,
        cycles: u128,
    ) -> Self {
        Self {
            status,
            module_hash,
            controller: candid::Principal::from_text(controller.to_string()).unwrap(),
            memory_size: candid::Nat::from(memory_size.get()),
            cycles: candid::Nat::from(cycles),
            // the following is spec 0.12/0.13 compat;
            // "\x00" denotes cycles
            balance: vec![(vec![0], candid::Nat::from(cycles))],
        }
    }

    pub fn status(&self) -> CanisterStatusType {
        self.status.clone()
    }

    pub fn module_hash(&self) -> Option<Vec<u8>> {
        self.module_hash.clone()
    }

    pub fn controller(&self) -> PrincipalId {
        PrincipalId::try_from(self.controller.as_slice()).unwrap()
    }

    pub fn memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_size.0.to_u64().unwrap())
    }

    pub fn cycles(&self) -> u128 {
        self.cycles.0.to_u128().unwrap()
    }
}

impl Payload<'_> for CanisterStatusResult {}

/// Struct used for encoding/decoding
/// `(record {
///     status : variant { running; stopping; stopped };
///     settings: definite_canister_settings;
///     module_hash: opt blob;
///     controller: principal;
///     memory_size: nat;
///     cycles: nat;
/// })`
#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct CanisterStatusResultV2 {
    status: CanisterStatusType,
    module_hash: Option<Vec<u8>>,
    controller: candid::Principal,
    settings: DefiniteCanisterSettingsArgs,
    memory_size: candid::Nat,
    cycles: candid::Nat,
    // this is for compat with Spec 0.12/0.13
    balance: Vec<(Vec<u8>, candid::Nat)>,
    freezing_threshold: candid::Nat,
}

impl CanisterStatusResultV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: CanisterStatusType,
        module_hash: Option<Vec<u8>>,
        controller: PrincipalId,
        controllers: Vec<PrincipalId>,
        memory_size: NumBytes,
        cycles: u128,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
    ) -> Self {
        Self {
            status,
            module_hash,
            controller: candid::Principal::from_text(controller.to_string()).unwrap(),
            memory_size: candid::Nat::from(memory_size.get()),
            cycles: candid::Nat::from(cycles),
            // the following is spec 0.12/0.13 compat;
            // "\x00" denotes cycles
            balance: vec![(vec![0], candid::Nat::from(cycles))],
            settings: DefiniteCanisterSettingsArgs::new(
                controller,
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
            ),
            freezing_threshold: candid::Nat::from(freezing_threshold),
        }
    }

    pub fn status(&self) -> CanisterStatusType {
        self.status.clone()
    }

    pub fn module_hash(&self) -> Option<Vec<u8>> {
        self.module_hash.clone()
    }

    pub fn controller(&self) -> PrincipalId {
        PrincipalId::try_from(self.controller.as_slice()).unwrap()
    }

    pub fn memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_size.0.to_u64().unwrap())
    }

    pub fn cycles(&self) -> u128 {
        self.cycles.0.to_u128().unwrap()
    }

    pub fn freezing_threshold(&self) -> u64 {
        self.freezing_threshold.0.to_u64().unwrap()
    }
}

/// Indicates whether the canister is running, stopping, or stopped.
///
/// Unlike `CanisterStatus`, it contains no additional metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, CandidType)]
pub enum CanisterStatusType {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

/// These strings are used to generate metrics -- changing any existing entries
/// will invalidate monitoring dashboards.
impl fmt::Display for CanisterStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanisterStatusType::Running => write!(f, "running"),
            CanisterStatusType::Stopping => write!(f, "stopping"),
            CanisterStatusType::Stopped => write!(f, "stopped"),
        }
    }
}

/// The mode with which a canister is installed.
#[derive(
    Clone, Debug, Deserialize, PartialEq, Serialize, Eq, EnumString, Hash, CandidType, Copy,
)]
pub enum CanisterInstallMode {
    /// A fresh install of a new canister.
    #[serde(rename = "install")]
    #[strum(serialize = "install")]
    Install,
    /// Reinstalling a canister that was already installed.
    #[serde(rename = "reinstall")]
    #[strum(serialize = "reinstall")]
    Reinstall,
    /// Upgrade an existing canister.
    #[serde(rename = "upgrade")]
    #[strum(serialize = "upgrade")]
    Upgrade,
}

impl Default for CanisterInstallMode {
    fn default() -> Self {
        CanisterInstallMode::Install
    }
}

impl CanisterInstallMode {
    pub fn iter() -> Iter<'static, CanisterInstallMode> {
        static MODES: [CanisterInstallMode; 3] = [
            CanisterInstallMode::Install,
            CanisterInstallMode::Reinstall,
            CanisterInstallMode::Upgrade,
        ];
        MODES.iter()
    }
}

/// A type to represent an error that can occur when installing a canister.
#[derive(Debug)]
pub struct CanisterInstallModeError(pub String);

impl TryFrom<String> for CanisterInstallMode {
    type Error = CanisterInstallModeError;

    fn try_from(mode: String) -> Result<Self, Self::Error> {
        let mode = mode.as_str();
        match mode {
            "install" => Ok(CanisterInstallMode::Install),
            "reinstall" => Ok(CanisterInstallMode::Reinstall),
            "upgrade" => Ok(CanisterInstallMode::Upgrade),
            _ => Err(CanisterInstallModeError(mode.to_string())),
        }
    }
}

impl From<CanisterInstallMode> for String {
    fn from(mode: CanisterInstallMode) -> Self {
        let res = match mode {
            CanisterInstallMode::Install => "install",
            CanisterInstallMode::Reinstall => "reinstall",
            CanisterInstallMode::Upgrade => "upgrade",
        };
        res.to_string()
    }
}

impl Payload<'_> for CanisterStatusResultV2 {}

/// Struct used for encoding/decoding
/// `(record {
///     mode : variant { install; reinstall; upgrade };
///     canister_id: principal;
///     wasm_module: blob;
///     arg: blob;
///     compute_allocation: opt nat;
///     memory_allocation: opt nat;
///     query_allocation: opt nat;
/// })`
#[derive(Clone, CandidType, Deserialize, Debug)]
pub struct InstallCodeArgs {
    pub mode: CanisterInstallMode,
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub query_allocation: Option<candid::Nat>,
}

impl std::fmt::Display for InstallCodeArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "InstallCodeArgs {{")?;
        writeln!(f, "  mode: {:?}", &self.mode)?;
        writeln!(f, "  canister_id: {:?}", &self.canister_id)?;
        writeln!(f, "  wasm_module: <{:?} bytes>", self.wasm_module.len())?;
        writeln!(f, "  arg: <{:?} bytes>", self.arg.len())?;
        writeln!(
            f,
            "  compute_allocation: {:?}",
            &self
                .compute_allocation
                .as_ref()
                .map(|value| format!("{}", value))
        )?;
        writeln!(
            f,
            "  memory_allocation: {:?}",
            &self
                .memory_allocation
                .as_ref()
                .map(|value| format!("{}", value))
        )?;
        writeln!(
            f,
            "  query_allocation: {:?}",
            &self
                .query_allocation
                .as_ref()
                .map(|value| format!("{}", value))
        )?;
        writeln!(f, "}}")
    }
}

impl Payload<'_> for InstallCodeArgs {}

impl InstallCodeArgs {
    pub fn new(
        mode: CanisterInstallMode,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
        query_allocation: Option<u64>,
    ) -> Self {
        Self {
            mode,
            canister_id: canister_id.into(),
            wasm_module,
            arg,
            compute_allocation: compute_allocation.map(candid::Nat::from),
            memory_allocation: memory_allocation.map(candid::Nat::from),
            query_allocation: query_allocation.map(candid::Nat::from),
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }
}

/// Represents the empty blob.
#[derive(CandidType, Deserialize)]
pub struct EmptyBlob;

// TODO(EXC-239): Implement the `Payload` interface.
impl EmptyBlob {
    pub fn encode() -> Vec<u8> {
        Encode!().unwrap()
    }

    pub fn decode(blob: &[u8]) -> Result<(), candid::Error> {
        Decode!(blob)
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     settings: canister_settings;
/// })`
#[derive(CandidType, Deserialize)]
pub struct UpdateSettingsArgs {
    pub canister_id: PrincipalId,
    pub settings: CanisterSettingsArgs,
}

impl UpdateSettingsArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }
}

impl Payload<'_> for UpdateSettingsArgs {}

/// Struct used for encoding/decoding
/// `(record {
///     controller : opt principal;
///     controllers: opt vec principal;
///     compute_allocation: opt nat;
///     memory_allocation: opt nat;
/// })`
#[derive(Default, Clone, CandidType, Deserialize, Debug)]
pub struct CanisterSettingsArgs {
    pub controller: Option<PrincipalId>,
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
}

impl Payload<'_> for CanisterSettingsArgs {}

/// Struct used for encoding/decoding
/// `(record {
///     settings : opt canister_settings;
/// })`
#[derive(Default, Clone, CandidType, Deserialize)]
pub struct CreateCanisterArgs {
    pub settings: Option<CanisterSettingsArgs>,
}

impl CreateCanisterArgs {
    pub fn encode(&self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }

    pub fn decode(blob: &[u8]) -> Result<Self, UserError> {
        let result = Decode!(blob, Self);
        match result {
            Err(_) => match EmptyBlob::decode(blob) {
                Err(_) => Err(UserError::new(
                    ErrorCode::CanisterContractViolation,
                    "Payload deserialization error.".to_string(),
                )),
                Ok(_) => Ok(CreateCanisterArgs::default()),
            },
            Ok(settings) => Ok(settings),
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     controller: principal;
/// })`
#[derive(CandidType, Deserialize)]
pub struct SetControllerArgs {
    canister_id: PrincipalId,
    new_controller: PrincipalId,
}

impl SetControllerArgs {
    pub fn new(canister_id: CanisterId, controller: PrincipalId) -> Self {
        Self {
            canister_id: canister_id.into(),
            new_controller: controller,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }

    pub fn get_new_controller(&self) -> PrincipalId {
        self.new_controller
    }
}

impl Payload<'_> for SetControllerArgs {}

/// Struct used for encoding/decoding
/// `(http_request : (record {
//     url : text;
//     headers : vec http_header;
//     method : variant { get };
//     body : opt blob;
//     transform : opt variant { function: func (http_response) -> (http_response) query };
//   })`
#[derive(CandidType, Deserialize, Debug)]
pub struct CanisterHttpRequestArgs {
    pub url: String,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
    pub http_method: HttpMethodType,
    pub transform_method_name: Option<String>,
}

impl Payload<'_> for CanisterHttpRequestArgs {}

/// Struct used for encoding/decoding
/// `(record {
/// name: text;
/// value: text;
/// })`;
#[derive(CandidType, Clone, Deserialize, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl Payload<'_> for HttpHeader {}

/// Represents the response for a canister http request.
/// Struct used for encoding/decoding
/// `(record {
/// status: nat;
/// headers: vec http_header;
/// body: blob;
/// })`;
#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponsePayload {
    pub status: u64,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl Payload<'_> for CanisterHttpResponsePayload {}

/// Struct used for encoding/decoding
/// `(record {
///     node_ids : vec principal;
///     registry_version: nat;
/// })`
#[derive(CandidType, Deserialize, Debug)]
pub struct SetupInitialDKGArgs {
    node_ids: Vec<PrincipalId>,
    registry_version: u64,
}

impl Payload<'_> for SetupInitialDKGArgs {}

impl SetupInitialDKGArgs {
    pub fn new(node_ids: Vec<NodeId>, registry_version: RegistryVersion) -> Self {
        Self {
            node_ids: node_ids.iter().map(|node_id| node_id.get()).collect(),
            registry_version: registry_version.get(),
        }
    }

    pub fn get_set_of_node_ids(&self) -> Result<BTreeSet<NodeId>, UserError> {
        let mut set = BTreeSet::<NodeId>::new();
        for node_id in self.node_ids.iter() {
            if !set.insert(NodeId::new(*node_id)) {
                return Err(UserError::new(
                    ErrorCode::CanisterContractViolation,
                    format!(
                        "Expected a set of NodeIds. The NodeId {} is repeated",
                        node_id
                    ),
                ));
            }
        }
        Ok(set)
    }

    pub fn get_registry_version(&self) -> RegistryVersion {
        RegistryVersion::new(self.registry_version)
    }
}

/// Represents the response for a request to setup an initial DKG for a new
/// subnet.
#[derive(Debug)]
pub struct SetupInitialDKGResponse {
    pub low_threshold_transcript_record: InitialNiDkgTranscriptRecord,
    pub high_threshold_transcript_record: InitialNiDkgTranscriptRecord,
    pub fresh_subnet_id: SubnetId,
    pub subnet_threshold_public_key: PublicKey,
}

impl SetupInitialDKGResponse {
    pub fn encode(&self) -> Vec<u8> {
        let serde_encoded_transcript_records = self.encode_with_serde_cbor();
        Encode!(&serde_encoded_transcript_records).unwrap()
    }

    fn encode_with_serde_cbor(&self) -> Vec<u8> {
        let transcript_records = (
            &self.low_threshold_transcript_record,
            &self.high_threshold_transcript_record,
            &self.fresh_subnet_id,
            &self.subnet_threshold_public_key,
        );
        serde_cbor::to_vec(&transcript_records).unwrap()
    }

    pub fn decode(blob: &[u8]) -> Result<Self, UserError> {
        let serde_encoded_transcript_records = Decode!(blob, Vec<u8>).map_err(|err| {
            UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("Error decoding candid: {}", err),
            )
        })?;
        match serde_cbor::from_slice::<(
            InitialNiDkgTranscriptRecord,
            InitialNiDkgTranscriptRecord,
            SubnetId,
            PublicKey,
        )>(&serde_encoded_transcript_records)
        {
            Err(err) => Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("Payload deserialization error: '{}'", err),
            )),
            Ok((
                low_threshold_transcript_record,
                high_threshold_transcript_record,
                fresh_subnet_id,
                subnet_threshold_public_key,
            )) => Ok(Self {
                low_threshold_transcript_record,
                high_threshold_transcript_record,
                fresh_subnet_id,
                subnet_threshold_public_key,
            }),
        }
    }
}

/// Struct used for encoding/decoding `(record { amount : opt nat; })`
#[derive(CandidType, Deserialize, Debug)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    pub amount: Option<candid::Nat>,
    pub settings: Option<CanisterSettingsArgs>,
}

impl ProvisionalCreateCanisterWithCyclesArgs {
    pub fn new(amount: Option<u128>) -> Self {
        Self {
            amount: amount.map(candid::Nat::from),
            settings: None,
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        match &self.amount {
            Some(amount) => amount.0.to_u128(),
            None => None,
        }
    }
}

impl Payload<'_> for ProvisionalCreateCanisterWithCyclesArgs {}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     amount: nat;
/// })`
#[derive(CandidType, Deserialize, Debug)]
pub struct ProvisionalTopUpCanisterArgs {
    canister_id: PrincipalId,
    amount: candid::Nat,
}

impl ProvisionalTopUpCanisterArgs {
    pub fn new(canister_id: CanisterId, amount: u128) -> Self {
        Self {
            canister_id: canister_id.get(),
            amount: candid::Nat::from(amount),
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        self.amount.0.to_u128()
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }
}

impl Payload<'_> for ProvisionalTopUpCanisterArgs {}

/// Represents the argument of the sign_with_ecdsa API.
/// ```text
/// (record {
///   message_hash : blob;
///   derivation_path : vec blob;
///   key_id : text;
/// })
/// ```
#[derive(CandidType, Deserialize, Debug)]
pub struct SignWithECDSAArgs {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: String,
}

impl Payload<'_> for SignWithECDSAArgs {}

/// Struct used to return an ECDSA signature.
#[derive(CandidType, Deserialize, Debug)]
pub struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

impl Payload<'_> for SignWithECDSAReply {}

/// Represents the argument of the ecdsa_public_key API.
/// ```text
/// (record {
///   canister_id : opt canister_id;
///   derivation_path : vec blob;
///   key_id : text;
/// })
/// ```
#[derive(CandidType, Deserialize, Debug)]
pub struct ECDSAPublicKeyArgs {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: String,
}

impl Payload<'_> for ECDSAPublicKeyArgs {}

/// Represents the response of the ecdsa_public_key API.
/// ```text
/// (record {
///   public_key : blob;
///   chain_code : blob;
/// })
/// ```
#[derive(CandidType, Deserialize, Debug)]
pub struct ECDSAPublicKeyResponse {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

impl Payload<'_> for ECDSAPublicKeyResponse {}

/// Argument of the compute_initial_ecdsa_dealings API.
/// `(record {
///     key_id: text;
///     nodes: vec principal;
///     registry_version: nat;
/// })`
#[derive(CandidType, Deserialize, Debug, Eq, PartialEq)]
pub struct ComputeInitialEcdsaDealingsArgs {
    pub key_id: String,
    nodes: Vec<PrincipalId>,
    registry_version: u64,
}

impl ComputeInitialEcdsaDealingsArgs {
    pub fn new(key_id: String, nodes: BTreeSet<NodeId>, registry_version: RegistryVersion) -> Self {
        Self {
            key_id,
            nodes: nodes.iter().map(|id| id.get()).collect(),
            registry_version: registry_version.get(),
        }
    }

    pub fn get_set_of_nodes(&self) -> Result<BTreeSet<NodeId>, UserError> {
        let mut set = BTreeSet::<NodeId>::new();
        for node_id in self.nodes.iter() {
            if !set.insert(NodeId::new(*node_id)) {
                return Err(UserError::new(
                    ErrorCode::CanisterContractViolation,
                    format!(
                        "Expected a set of NodeIds. The NodeId {} is repeated",
                        node_id
                    ),
                ));
            }
        }
        Ok(set)
    }

    pub fn get_registry_version(&self) -> RegistryVersion {
        RegistryVersion::new(self.registry_version)
    }
}

impl Payload<'_> for ComputeInitialEcdsaDealingsArgs {}

#[derive(Clone, Debug, PartialEq, CandidType, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethodType {
    GET,
}

impl From<&HttpMethodType> for pb_metadata::HttpMethodType {
    fn from(http_method_type: &HttpMethodType) -> Self {
        match http_method_type {
            HttpMethodType::GET => pb_metadata::HttpMethodType::Get,
        }
    }
}

impl From<pb_metadata::HttpMethodType> for HttpMethodType {
    fn from(http_method_type: pb_metadata::HttpMethodType) -> Self {
        match http_method_type {
            pb_metadata::HttpMethodType::Unspecified | pb_metadata::HttpMethodType::Get => {
                HttpMethodType::GET
            }
        }
    }
}
