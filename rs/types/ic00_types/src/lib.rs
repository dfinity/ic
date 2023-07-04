//! Data types used for encoding/decoding the Candid payloads of ic:00.
mod http;
mod provisional;
#[cfg(feature = "fuzzing_code")]
use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use candid::{CandidType, Decode, Deserialize, Encode};
pub use http::{
    CanisterHttpRequestArgs, CanisterHttpResponsePayload, HttpHeader, HttpMethod, TransformArgs,
    TransformContext, TransformFunc,
};
use ic_base_types::{CanisterId, NodeId, NumBytes, PrincipalId, RegistryVersion, SubnetId};
use ic_error_types::{ErrorCode, UserError};
use ic_protobuf::proxy::{try_decode_hash, try_from_option_field};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::subnet::v1::{InitialIDkgDealings, InitialNiDkgTranscriptRecord};
use ic_protobuf::state::canister_state_bits::v1 as pb_canister_state_bits;
use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
use ic_protobuf::{proxy::ProxyDecodeError, registry::crypto::v1 as pb_registry_crypto};
use num_traits::cast::ToPrimitive;
pub use provisional::{ProvisionalCreateCanisterWithCyclesArgs, ProvisionalTopUpCanisterArgs};
use serde::{Deserializer, Serialize};
use std::mem::size_of;
use std::{collections::BTreeSet, convert::TryFrom, error::Error, fmt, slice::Iter, str::FromStr};
use strum_macros::{Display, EnumIter, EnumString};

/// The id of the management canister.
pub const IC_00: CanisterId = CanisterId::ic_00();
pub const MAX_CONTROLLERS: usize = 10;
const WASM_HASH_LENGTH: usize = 32;
/// The maximum length of a BIP32 derivation path
///
/// The extended public key format uses a byte to represent the derivation
/// level of a key, thus BIP32 derivations with more than 255 path elements
/// are not interoperable with other software.
///
/// See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
/// for details
const MAXIMUM_DERIVATION_PATH_LENGTH: usize = 255;

/// Methods exported by ic:00.
#[derive(Debug, EnumString, EnumIter, Display, Copy, Clone, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum Method {
    CanisterStatus,
    CanisterInfo,
    CreateCanister,
    DeleteCanister,
    DepositCycles,
    HttpRequest,
    ECDSAPublicKey,
    InstallCode,
    RawRand,
    // SetController is deprecated and should not be used in new code
    SetController,
    SetupInitialDKG,
    SignWithECDSA,
    StartCanister,
    StopCanister,
    UninstallCode,
    UpdateSettings,
    ComputeInitialEcdsaDealings,

    // Bitcoin Interface.
    BitcoinGetBalance,
    BitcoinGetUtxos,
    BitcoinSendTransaction,
    BitcoinGetCurrentFeePercentiles,
    // Private APIs used exclusively by the bitcoin canisters.
    BitcoinSendTransactionInternal, // API for sending transactions to the network.
    BitcoinGetSuccessors,           // API for fetching blocks from the network.

    // These methods are only available on test IC instances where there is a
    // need to fabricate cycles without burning ICP first.
    ProvisionalCreateCanisterWithCycles,
    ProvisionalTopUpCanister,
}

fn candid_error_to_user_error(err: candid::Error) -> UserError {
    UserError::new(
        ErrorCode::InvalidManagementPayload,
        format!("Error decoding candid: {:?}", err),
    )
}

/// A trait to be implemented by all structs that are used as payloads
/// by IC00. This trait encapsulates Candid serialization so that
/// consumers of IC00 don't need to explicitly depend on Candid.
pub trait Payload<'a>: Sized + CandidType + Deserialize<'a> {
    fn encode(&self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }

    fn decode(blob: &'a [u8]) -> Result<Self, UserError> {
        Decode!(blob, Self).map_err(candid_error_to_user_error)
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

// Canister history

/// `CandidType` for user variant of `CanisterChangeOrigin`
/// ```text
/// record {
///   user_id : principal;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterChangeFromUserRecord {
    user_id: PrincipalId,
}

/// `CandidType` for canister variant of `CanisterChangeOrigin`
/// ```text
/// record {
///   canister_id : principal;
///   canister_version : opt nat64;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterChangeFromCanisterRecord {
    canister_id: PrincipalId,
    canister_version: Option<u64>,
}

/// `CandidType` for `CanisterChangeOrigin`
/// ```text
/// variant {
///   from_user : record {
///     user_id : principal;
///   };
///   from_canister : record {
///     canister_id : principal;
///     canister_version : opt nat64;
///   };
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CanisterChangeOrigin {
    #[serde(rename = "from_user")]
    CanisterChangeFromUser(CanisterChangeFromUserRecord),
    #[serde(rename = "from_canister")]
    CanisterChangeFromCanister(CanisterChangeFromCanisterRecord),
}

impl CanisterChangeOrigin {
    pub fn from_user(user_id: PrincipalId) -> CanisterChangeOrigin {
        CanisterChangeOrigin::CanisterChangeFromUser(CanisterChangeFromUserRecord { user_id })
    }

    pub fn from_canister(
        canister_id: PrincipalId,
        canister_version: Option<u64>,
    ) -> CanisterChangeOrigin {
        CanisterChangeOrigin::CanisterChangeFromCanister(CanisterChangeFromCanisterRecord {
            canister_id,
            canister_version,
        })
    }

    /// The principal (user or canister) initiating a canister change.
    pub fn origin(&self) -> PrincipalId {
        match self {
            CanisterChangeOrigin::CanisterChangeFromUser(change_from_user) => {
                change_from_user.user_id
            }
            CanisterChangeOrigin::CanisterChangeFromCanister(change_from_canister) => {
                change_from_canister.canister_id
            }
        }
    }
}

/// `CandidType` for `CanisterCreationRecord`
/// ```text
/// record {
///   controllers : vec principal;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterCreationRecord {
    controllers: Vec<PrincipalId>,
}

impl CanisterCreationRecord {
    pub fn controllers(&self) -> &[PrincipalId] {
        &self.controllers
    }
}

/// `CandidType` for `CanisterCodeDeploymentRecord`
/// ```text
/// record {
///   mode : variant {install; reinstall; upgrade};
///   module_hash : blob;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterCodeDeploymentRecord {
    mode: CanisterInstallMode,
    module_hash: [u8; WASM_HASH_LENGTH],
}

/// `CandidType` for `CanisterControllersChangeRecord`
/// ```text
/// record {
///   controllers : vec principal;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterControllersChangeRecord {
    controllers: Vec<PrincipalId>,
}

impl CanisterControllersChangeRecord {
    pub fn controllers(&self) -> &[PrincipalId] {
        &self.controllers
    }
}

/// `CandidType` for `CanisterChangeDetails`
/// ```text
/// variant {
///   creation : record {
///     controllers : vec principal;
///   };
///   code_uninstall;
///   code_deployment : record {
///     mode : variant {install; reinstall; upgrade};
///     module_hash : blob;
///   };
///   controllers_change : record {
///     controllers : vec principal;
///   };
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CanisterChangeDetails {
    #[serde(rename = "creation")]
    CanisterCreation(CanisterCreationRecord),
    #[serde(rename = "code_uninstall")]
    CanisterCodeUninstall,
    #[serde(rename = "code_deployment")]
    CanisterCodeDeployment(CanisterCodeDeploymentRecord),
    #[serde(rename = "controllers_change")]
    CanisterControllersChange(CanisterControllersChangeRecord),
}

impl CanisterChangeDetails {
    pub fn canister_creation(controllers: Vec<PrincipalId>) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterCreation(CanisterCreationRecord { controllers })
    }

    pub fn code_deployment(
        mode: CanisterInstallMode,
        module_hash: [u8; WASM_HASH_LENGTH],
    ) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterCodeDeployment(CanisterCodeDeploymentRecord {
            mode,
            module_hash,
        })
    }

    pub fn controllers_change(controllers: Vec<PrincipalId>) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterControllersChange(CanisterControllersChangeRecord {
            controllers,
        })
    }
}

/// Every canister change (canister creation, code uninstallation, code deployment, or controllers change) consists of
///
/// 1. the system timestamp (in nanoseconds since Unix Epoch) at which the change was performed,
/// 2. the canister version after performing the change,
/// 3. the change's origin (a user or a canister),
/// 4. and the change's details.
///
/// The change origin includes the principal (called _originator_ in the following) that initiated the change and,
/// if the originator is a canister, the originator's canister version when the originator initiated the change
/// (if available).
///
/// Code deployments are described by their mode (code install, code reinstall, code upgrade) and
/// the SHA-256 hash of the newly deployed canister module.
///
/// Controllers changes are described by the full new set of the canister controllers after the change.
///
/// `CandidType` for `CanisterChange`
/// ```text
/// record {
///   timestamp_nanos : nat64;
///   canister_version : nat64;
///   origin : change_origin;
///   details : change_details;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterChange {
    timestamp_nanos: u64,
    canister_version: u64,
    origin: CanisterChangeOrigin,
    details: CanisterChangeDetails,
}

impl CanisterChange {
    pub fn new(
        timestamp_nanos: u64,
        canister_version: u64,
        origin: CanisterChangeOrigin,
        details: CanisterChangeDetails,
    ) -> CanisterChange {
        CanisterChange {
            timestamp_nanos,
            canister_version,
            origin,
            details,
        }
    }

    /// Returns the number of bytes to represent a canister change in memory.
    /// The vector of controllers in `CanisterCreation` and `CanisterControllersChange`
    /// is counted separately because the controllers are stored on heap
    /// and thus not accounted for in `size_of::<CanisterChange>()`.
    pub fn count_bytes(&self) -> NumBytes {
        let controllers_memory_size = match &self.details {
            CanisterChangeDetails::CanisterCreation(canister_creation) => {
                canister_creation.controllers().len() * size_of::<PrincipalId>()
            }
            CanisterChangeDetails::CanisterControllersChange(canister_controllers_change) => {
                canister_controllers_change.controllers().len() * size_of::<PrincipalId>()
            }
            CanisterChangeDetails::CanisterCodeDeployment(_)
            | CanisterChangeDetails::CanisterCodeUninstall => 0,
        };
        NumBytes::from((size_of::<CanisterChange>() + controllers_memory_size) as u64)
    }
}

/// `CandidType` for `CanisterInfoRequest`
/// ```text
/// record {
///   canister_id : principal;
///   num_requested_changes : opt nat64;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterInfoRequest {
    canister_id: PrincipalId,
    num_requested_changes: Option<u64>,
}

impl CanisterInfoRequest {
    pub fn new(canister_id: CanisterId, num_requested_changes: Option<u64>) -> CanisterInfoRequest {
        CanisterInfoRequest {
            canister_id: canister_id.into(),
            num_requested_changes,
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }

    pub fn num_requested_changes(&self) -> Option<u64> {
        self.num_requested_changes
    }
}

impl Payload<'_> for CanisterInfoRequest {}

/// `CandidType` for `CanisterInfoRequest`
/// ```text
/// record {
///   total_num_changes : nat64;
///   recent_changes : vec change;
///   module_hash : opt blob;
///   controllers : vec principal;
/// }
/// ```
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanisterInfoResponse {
    total_num_changes: u64,
    recent_changes: Vec<CanisterChange>,
    module_hash: Option<Vec<u8>>,
    controllers: Vec<PrincipalId>,
}

impl CanisterInfoResponse {
    pub fn new(
        total_num_changes: u64,
        recent_changes: Vec<CanisterChange>,
        module_hash: Option<Vec<u8>>,
        controllers: Vec<PrincipalId>,
    ) -> Self {
        Self {
            total_num_changes,
            recent_changes,
            module_hash,
            controllers,
        }
    }

    pub fn total_num_changes(&self) -> u64 {
        self.total_num_changes
    }

    pub fn changes(&self) -> Vec<CanisterChange> {
        self.recent_changes.clone()
    }

    pub fn module_hash(&self) -> Option<Vec<u8>> {
        self.module_hash.clone()
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.controllers.clone()
    }
}

impl Payload<'_> for CanisterInfoResponse {}

impl From<&CanisterChangeOrigin> for pb_canister_state_bits::canister_change::ChangeOrigin {
    fn from(item: &CanisterChangeOrigin) -> Self {
        match item {
            CanisterChangeOrigin::CanisterChangeFromUser(change_from_user) => {
                pb_canister_state_bits::canister_change::ChangeOrigin::CanisterChangeFromUser(
                    pb_canister_state_bits::CanisterChangeFromUser {
                        user_id: Some(change_from_user.user_id.into()),
                    },
                )
            }
            CanisterChangeOrigin::CanisterChangeFromCanister(change_from_canister) => {
                pb_canister_state_bits::canister_change::ChangeOrigin::CanisterChangeFromCanister(
                    pb_canister_state_bits::CanisterChangeFromCanister {
                        canister_id: Some(change_from_canister.canister_id.into()),
                        canister_version: change_from_canister.canister_version,
                    },
                )
            }
        }
    }
}

impl TryFrom<pb_canister_state_bits::canister_change::ChangeOrigin> for CanisterChangeOrigin {
    type Error = ProxyDecodeError;

    fn try_from(
        value: pb_canister_state_bits::canister_change::ChangeOrigin,
    ) -> Result<Self, Self::Error> {
        match value {
            pb_canister_state_bits::canister_change::ChangeOrigin::CanisterChangeFromUser(
                change_from_user,
            ) => Ok(CanisterChangeOrigin::from_user(try_from_option_field(
                change_from_user.user_id,
                "user_id",
            )?)),
            pb_canister_state_bits::canister_change::ChangeOrigin::CanisterChangeFromCanister(
                change_from_canister,
            ) => Ok(CanisterChangeOrigin::from_canister(
                try_from_option_field(change_from_canister.canister_id, "canister_id")?,
                change_from_canister.canister_version,
            )),
        }
    }
}

impl From<&CanisterChangeDetails> for pb_canister_state_bits::canister_change::ChangeDetails {
    fn from(item: &CanisterChangeDetails) -> Self {
        match item {
            CanisterChangeDetails::CanisterCreation(canister_creation) => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterCreation(
                    pb_canister_state_bits::CanisterCreation {
                        controllers: canister_creation
                            .controllers
                            .iter()
                            .map(|c| (*c).into())
                            .collect::<Vec<ic_protobuf::types::v1::PrincipalId>>(),
                    },
                )
            }
            CanisterChangeDetails::CanisterCodeUninstall => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterCodeUninstall(
                    pb_canister_state_bits::CanisterCodeUninstall {},
                )
            }
            CanisterChangeDetails::CanisterCodeDeployment(canister_code_deployment) => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterCodeDeployment(
                    pb_canister_state_bits::CanisterCodeDeployment {
                        module_hash: canister_code_deployment.module_hash.to_vec(),
                        mode: (&canister_code_deployment.mode).into(),
                    },
                )
            }
            CanisterChangeDetails::CanisterControllersChange(canister_controllers_change) => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterControllersChange(
                    pb_canister_state_bits::CanisterControllersChange {
                        controllers: canister_controllers_change
                            .controllers
                            .iter()
                            .map(|c| (*c).into())
                            .collect::<Vec<ic_protobuf::types::v1::PrincipalId>>(),
                    },
                )
            }
        }
    }
}

impl TryFrom<pb_canister_state_bits::canister_change::ChangeDetails> for CanisterChangeDetails {
    type Error = ProxyDecodeError;

    fn try_from(
        item: pb_canister_state_bits::canister_change::ChangeDetails,
    ) -> Result<Self, Self::Error> {
        match item {
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterCreation(
                canister_creation,
            ) => Ok(CanisterChangeDetails::canister_creation(
                canister_creation
                    .controllers
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<PrincipalId>, _>>()?,
            )),
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterCodeUninstall(_) => {
                Ok(CanisterChangeDetails::CanisterCodeUninstall)
            }
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterCodeDeployment(
                canister_code_deployment,
            ) => Ok(CanisterChangeDetails::code_deployment(
                canister_code_deployment.mode.try_into().map_err(
                    |e: CanisterInstallModeError| ProxyDecodeError::ValueOutOfRange {
                        typ: "CanisterInstallMode",
                        err: e.to_string(),
                    },
                )?,
                try_decode_hash(canister_code_deployment.module_hash)?,
            )),
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterControllersChange(
                canister_controllers_change,
            ) => Ok(CanisterChangeDetails::controllers_change(
                canister_controllers_change
                    .controllers
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<PrincipalId>, _>>()?,
            )),
        }
    }
}

impl From<&CanisterChange> for pb_canister_state_bits::CanisterChange {
    fn from(item: &CanisterChange) -> Self {
        Self {
            timestamp_nanos: item.timestamp_nanos,
            canister_version: item.canister_version,
            change_origin: Some((&item.origin).into()),
            change_details: Some((&item.details).into()),
        }
    }
}

impl TryFrom<pb_canister_state_bits::CanisterChange> for CanisterChange {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_canister_state_bits::CanisterChange) -> Result<Self, Self::Error> {
        let origin = try_from_option_field(value.change_origin, "origin")?;
        let details = try_from_option_field(value.change_details, "details")?;
        Ok(Self {
            timestamp_nanos: value.timestamp_nanos,
            canister_version: value.canister_version,
            origin,
            details,
        })
    }
}

/// Struct used for encoding/decoding `(record {canister_id: canister_id, sender_canister_version: opt nat64})`.
#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct UninstallCodeArgs {
    canister_id: PrincipalId,
    sender_canister_version: Option<u64>,
}

impl UninstallCodeArgs {
    pub fn new(canister_id: CanisterId, sender_canister_version: Option<u64>) -> Self {
        Self {
            canister_id: canister_id.into(),
            sender_canister_version,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl Payload<'_> for UninstallCodeArgs {}

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
///     idle_cycles_burned_per_day: nat;
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
    idle_cycles_burned_per_day: candid::Nat,
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
        idle_cycles_burned_per_day: u128,
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
            idle_cycles_burned_per_day: candid::Nat::from(idle_cycles_burned_per_day),
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

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.settings.controllers()
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

    pub fn idle_cycles_burned_per_day(&self) -> u128 {
        self.idle_cycles_burned_per_day.0.to_u128().unwrap()
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
    Install = 1,
    /// Reinstalling a canister that was already installed.
    #[serde(rename = "reinstall")]
    #[strum(serialize = "reinstall")]
    Reinstall = 2,
    /// Upgrade an existing canister.
    #[serde(rename = "upgrade")]
    #[strum(serialize = "upgrade")]
    Upgrade = 3,
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

impl Error for CanisterInstallModeError {}

impl fmt::Display for CanisterInstallModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

impl From<&CanisterInstallMode> for i32 {
    fn from(item: &CanisterInstallMode) -> Self {
        let proto: CanisterInstallModeProto = item.into();
        proto.into()
    }
}

impl TryFrom<i32> for CanisterInstallMode {
    type Error = CanisterInstallModeError;

    fn try_from(item: i32) -> Result<Self, Self::Error> {
        match CanisterInstallModeProto::from_i32(item) {
            Some(CanisterInstallModeProto::Install) => Ok(CanisterInstallMode::Install),
            Some(CanisterInstallModeProto::Reinstall) => Ok(CanisterInstallMode::Reinstall),
            Some(CanisterInstallModeProto::Upgrade) => Ok(CanisterInstallMode::Upgrade),
            Some(CanisterInstallModeProto::Unspecified) | None => {
                Err(CanisterInstallModeError(item.to_string()))
            }
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

impl From<&CanisterInstallMode> for CanisterInstallModeProto {
    fn from(item: &CanisterInstallMode) -> Self {
        match item {
            CanisterInstallMode::Install => CanisterInstallModeProto::Install,
            CanisterInstallMode::Reinstall => CanisterInstallModeProto::Reinstall,
            CanisterInstallMode::Upgrade => CanisterInstallModeProto::Upgrade,
        }
    }
}

#[test]
fn canister_install_mode_round_trip() {
    fn canister_install_mode_round_trip_aux(mode: CanisterInstallMode) {
        let pb_mode: i32 = (&mode).into();
        let dec_mode = CanisterInstallMode::try_from(pb_mode).unwrap();
        assert_eq!(mode, dec_mode);
    }

    canister_install_mode_round_trip_aux(CanisterInstallMode::Install);
    canister_install_mode_round_trip_aux(CanisterInstallMode::Reinstall);
    canister_install_mode_round_trip_aux(CanisterInstallMode::Upgrade);
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
    pub sender_canister_version: Option<u64>,
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
            sender_canister_version: None,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

/// Represents the empty blob.
#[derive(CandidType, Deserialize)]
pub struct EmptyBlob;

impl<'a> Payload<'a> for EmptyBlob {
    fn encode(&self) -> Vec<u8> {
        Encode!().unwrap()
    }

    fn decode(blob: &'a [u8]) -> Result<EmptyBlob, UserError> {
        Decode!(blob)
            .map(|_| EmptyBlob)
            .map_err(candid_error_to_user_error)
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     settings: canister_settings;
/// })`
#[derive(CandidType, Deserialize, Debug)]
pub struct UpdateSettingsArgs {
    pub canister_id: PrincipalId,
    pub settings: CanisterSettingsArgs,
    pub sender_canister_version: Option<u64>,
}

impl UpdateSettingsArgs {
    pub fn new(canister_id: CanisterId, settings: CanisterSettingsArgs) -> Self {
        Self {
            canister_id: canister_id.into(),
            settings,
            sender_canister_version: None,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

#[cfg(feature = "fuzzing_code")]
impl<'a> Arbitrary<'a> for UpdateSettingsArgs {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(UpdateSettingsArgs::new(
            CanisterId::from(u64::arbitrary(u)?),
            CanisterSettingsArgs::new(
                Some(<Vec<PrincipalId>>::arbitrary(u)?),
                Some(u64::arbitrary(u)?),
                Some(u64::arbitrary(u)?),
                Some(u64::arbitrary(u)?),
            ),
        ))
    }
}

impl Payload<'_> for UpdateSettingsArgs {}

/// Struct used for encoding/decoding
/// `(record {
///     controller: opt principal;
///     controllers: opt vec principal;
///     compute_allocation: opt nat;
///     memory_allocation: opt nat;
/// })`
#[derive(Default, Clone, CandidType, Deserialize, Debug)]
pub struct CanisterSettingsArgs {
    /// The field controller is deprecated and should not be used in new code.
    controller: Option<PrincipalId>,
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
}

impl Payload<'_> for CanisterSettingsArgs {}

impl CanisterSettingsArgs {
    pub fn new(
        controllers: Option<Vec<PrincipalId>>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
        freezing_threshold: Option<u64>,
    ) -> Self {
        Self {
            controller: None,
            controllers,
            compute_allocation: compute_allocation.map(candid::Nat::from),
            memory_allocation: memory_allocation.map(candid::Nat::from),
            freezing_threshold: freezing_threshold.map(candid::Nat::from),
        }
    }

    pub fn get_controller(&self) -> Option<PrincipalId> {
        self.controller
    }
}

#[derive(Default)]
pub struct CanisterSettingsArgsBuilder {
    controller: Option<PrincipalId>,
    controllers: Option<Vec<PrincipalId>>,
    compute_allocation: Option<candid::Nat>,
    memory_allocation: Option<candid::Nat>,
    freezing_threshold: Option<candid::Nat>,
}

#[allow(dead_code)]
impl CanisterSettingsArgsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> CanisterSettingsArgs {
        CanisterSettingsArgs {
            controller: self.controller,
            controllers: self.controllers,
            compute_allocation: self.compute_allocation,
            memory_allocation: self.memory_allocation,
            freezing_threshold: self.freezing_threshold,
        }
    }

    pub fn with_controller(self, controller: PrincipalId) -> Self {
        Self {
            controller: Some(controller),
            ..self
        }
    }

    pub fn with_controllers(self, controllers: Vec<PrincipalId>) -> Self {
        Self {
            controllers: Some(controllers),
            ..self
        }
    }

    /// Sets the compute allocation in percent. For more details see
    /// the description of this field in the IC specification.
    pub fn with_compute_allocation(self, compute_allocation: u64) -> Self {
        Self {
            compute_allocation: Some(candid::Nat::from(compute_allocation)),
            ..self
        }
    }

    /// Sets the memory allocation in bytes. For more details see
    /// the description of this field in the IC specification.
    pub fn with_memory_allocation(self, memory_allocation: u64) -> Self {
        Self {
            memory_allocation: Some(candid::Nat::from(memory_allocation)),
            ..self
        }
    }

    /// Sets the freezing threshold in seconds. For more details see
    /// the description of this field in the IC specification.
    pub fn with_freezing_threshold(self, freezing_threshold: u64) -> Self {
        Self {
            freezing_threshold: Some(candid::Nat::from(freezing_threshold)),
            ..self
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     settings : opt canister_settings;
/// })`
#[derive(Default, Clone, CandidType, Deserialize)]
pub struct CreateCanisterArgs {
    pub settings: Option<CanisterSettingsArgs>,
    pub sender_canister_version: Option<u64>,
}

impl CreateCanisterArgs {
    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl<'a> Payload<'a> for CreateCanisterArgs {
    fn decode(blob: &'a [u8]) -> Result<Self, UserError> {
        let result = Decode!(blob, Self);
        match result {
            Err(_) => match EmptyBlob::decode(blob) {
                Err(_) => Err(UserError::new(
                    ErrorCode::InvalidManagementPayload,
                    "Payload deserialization error.".to_string(),
                )),
                Ok(_) => Ok(CreateCanisterArgs::default()),
            },
            Ok(settings) => Ok(settings),
        }
    }
}

/// This API is deprecated and should not be used in new code.
/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     controller: principal;
/// })`
#[derive(CandidType, Deserialize)]
pub struct SetControllerArgs {
    canister_id: PrincipalId,
    new_controller: PrincipalId,
    sender_canister_version: Option<u64>,
}

impl SetControllerArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }

    pub fn get_new_controller(&self) -> PrincipalId {
        self.new_controller
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl Payload<'_> for SetControllerArgs {}

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
        let serde_encoded_transcript_records =
            Decode!(blob, Vec<u8>).map_err(candid_error_to_user_error)?;
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

/// Types of curves that can be used for ECDSA signing.
/// ```text
/// (variant { secp256k1; })
/// ```
#[derive(
    CandidType, Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl TryFrom<pb_registry_crypto::EcdsaCurve> for EcdsaCurve {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_registry_crypto::EcdsaCurve) -> Result<Self, Self::Error> {
        match item {
            pb_registry_crypto::EcdsaCurve::Secp256k1 => Ok(EcdsaCurve::Secp256k1),
            pb_registry_crypto::EcdsaCurve::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "EcdsaCurve",
                err: format!("Unable to convert {:?} to an EcdsaCurve", item),
            }),
        }
    }
}

impl From<EcdsaCurve> for pb_registry_crypto::EcdsaCurve {
    fn from(item: EcdsaCurve) -> Self {
        match item {
            EcdsaCurve::Secp256k1 => pb_registry_crypto::EcdsaCurve::Secp256k1,
        }
    }
}

impl std::fmt::Display for EcdsaCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for EcdsaCurve {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Secp256k1" => Ok(Self::Secp256k1),
            _ => Err(format!("{} is not a recognized ECDSA curve", s)),
        }
    }
}

#[test]
fn ecdsa_curve_round_trip() {
    assert_eq!(
        format!("{}", EcdsaCurve::Secp256k1)
            .parse::<EcdsaCurve>()
            .unwrap(),
        EcdsaCurve::Secp256k1
    );
}

/// Unique identifier for a key that can be used for ECDSA signatures. The name
/// is just a identifier, but it may be used to convey some information about
/// the key (e.g. that the key is meant to be used for testing purposes).
/// ```text
/// (record { curve: ecdsa_curve; name: text})
/// ```
#[derive(
    CandidType, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Hash,
)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

impl TryFrom<pb_registry_crypto::EcdsaKeyId> for EcdsaKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_registry_crypto::EcdsaKeyId) -> Result<Self, Self::Error> {
        Ok(Self {
            curve: EcdsaCurve::try_from(
                pb_registry_crypto::EcdsaCurve::from_i32(item.curve).ok_or(
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "EcdsaKeyId",
                        err: format!("Unable to convert {} to an EcdsaCurve", item.curve),
                    },
                )?,
            )?,
            name: item.name,
        })
    }
}

impl From<&EcdsaKeyId> for pb_registry_crypto::EcdsaKeyId {
    fn from(item: &EcdsaKeyId) -> Self {
        Self {
            curve: pb_registry_crypto::EcdsaCurve::from(item.curve) as i32,
            name: item.name.clone(),
        }
    }
}

impl std::fmt::Display for EcdsaKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.curve, self.name)
    }
}

impl FromStr for EcdsaKeyId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (curve, name) = s
            .split_once(':')
            .ok_or_else(|| format!("ECDSA key id {} does not contain a ':'", s))?;
        Ok(EcdsaKeyId {
            curve: curve.parse::<EcdsaCurve>()?,
            name: name.to_string(),
        })
    }
}

#[test]
fn ecdsa_key_id_round_trip() {
    for name in ["secp256k1", "", "other_key", "other key", "other:key"] {
        let key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: name.to_string(),
        };
        assert_eq!(format!("{}", key).parse::<EcdsaKeyId>().unwrap(), key);
    }
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(Vec<Vec<u8>>);

impl DerivationPath {
    pub fn new(path: Vec<Vec<u8>>) -> Self {
        Self(path)
    }

    pub fn get(&self) -> Vec<Vec<u8>> {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for DerivationPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let decoded: Vec<Vec<u8>> = Deserialize::deserialize(deserializer)?;
        if decoded.len() > MAXIMUM_DERIVATION_PATH_LENGTH {
            Err(serde::de::Error::custom(format!(
                "Derivation path length {} exceeds maximum allowed {}",
                decoded.len(),
                MAXIMUM_DERIVATION_PATH_LENGTH
            )))
        } else {
            Ok(DerivationPath::new(decoded))
        }
    }
}

impl Payload<'_> for DerivationPath {}

#[test]
fn verify_max_derivation_path_length() {
    for i in 0..=MAXIMUM_DERIVATION_PATH_LENGTH {
        let path = DerivationPath::new(vec![vec![0_u8, 32]; i]);
        let encoded = path.encode();
        assert_eq!(DerivationPath::decode(&encoded).unwrap(), path);

        let sign_with_ecdsa = SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: path.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "test".to_string(),
            },
        };

        let encoded = sign_with_ecdsa.encode();
        assert_eq!(
            SignWithECDSAArgs::decode(&encoded).unwrap(),
            sign_with_ecdsa
        );

        let ecdsa_public_key = ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path: path,
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "test".to_string(),
            },
        };

        let encoded = ecdsa_public_key.encode();
        assert_eq!(
            ECDSAPublicKeyArgs::decode(&encoded).unwrap(),
            ecdsa_public_key
        );
    }

    for i in MAXIMUM_DERIVATION_PATH_LENGTH + 1..=MAXIMUM_DERIVATION_PATH_LENGTH + 100 {
        let path = DerivationPath::new(vec![vec![0_u8, 32]; i]);
        let encoded = path.encode();
        let res = DerivationPath::decode(&encoded).unwrap_err();
        assert_eq!(res.code(), ErrorCode::InvalidManagementPayload);
        assert!(res.description().contains(&format!(
            "Deserialize error: Derivation path length {} exceeds maximum allowed {}",
            i, MAXIMUM_DERIVATION_PATH_LENGTH
        )));

        let sign_with_ecdsa = SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: path.clone(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "test".to_string(),
            },
        };

        let encoded = sign_with_ecdsa.encode();
        let res = SignWithECDSAArgs::decode(&encoded).unwrap_err();
        assert_eq!(res.code(), ErrorCode::InvalidManagementPayload);
        assert!(res.description().contains(&format!(
            "Deserialize error: Derivation path length {} exceeds maximum allowed {}",
            i, MAXIMUM_DERIVATION_PATH_LENGTH
        )));

        let ecsda_public_key = ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path: path,
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "test".to_string(),
            },
        };

        let encoded = ecsda_public_key.encode();
        let res = ECDSAPublicKeyArgs::decode(&encoded).unwrap_err();
        assert_eq!(res.code(), ErrorCode::InvalidManagementPayload);
        assert!(res.description().contains(&format!(
            "Deserialize error: Derivation path length {} exceeds maximum allowed {}",
            i, MAXIMUM_DERIVATION_PATH_LENGTH
        )));
    }
}

/// Represents the argument of the sign_with_ecdsa API.
/// ```text
/// (record {
///   message_hash : blob;
///   derivation_path : vec blob;
///   key_id : ecdsa_key_id;
/// })
/// ```
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct SignWithECDSAArgs {
    pub message_hash: [u8; 32],
    pub derivation_path: DerivationPath,
    pub key_id: EcdsaKeyId,
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
///   key_id : ecdsa_key_id;
/// })
/// ```
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct ECDSAPublicKeyArgs {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: DerivationPath,
    pub key_id: EcdsaKeyId,
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
///     key_id: ecdsa_key_id;
///     subnet_id: principal;
///     nodes: vec principal;
///     registry_version: nat;
/// })`
#[derive(CandidType, Deserialize, Debug, Eq, PartialEq)]
pub struct ComputeInitialEcdsaDealingsArgs {
    pub key_id: EcdsaKeyId,
    pub subnet_id: SubnetId,
    nodes: Vec<PrincipalId>,
    registry_version: u64,
}

impl ComputeInitialEcdsaDealingsArgs {
    pub fn new(
        key_id: EcdsaKeyId,
        subnet_id: SubnetId,
        nodes: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            key_id,
            subnet_id,
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

/// Struct used to return the xnet initial dealings.
#[derive(Debug)]
pub struct ComputeInitialEcdsaDealingsResponse {
    pub initial_dkg_dealings: InitialIDkgDealings,
}

impl ComputeInitialEcdsaDealingsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let serde_encoded_transcript_records = self.encode_with_serde_cbor();
        Encode!(&serde_encoded_transcript_records).unwrap()
    }

    fn encode_with_serde_cbor(&self) -> Vec<u8> {
        let transcript_records = (&self.initial_dkg_dealings,);
        serde_cbor::to_vec(&transcript_records).unwrap()
    }

    pub fn decode(blob: &[u8]) -> Result<Self, UserError> {
        let serde_encoded_transcript_records =
            Decode!(blob, Vec<u8>).map_err(candid_error_to_user_error)?;
        match serde_cbor::from_slice::<(InitialIDkgDealings,)>(&serde_encoded_transcript_records) {
            Err(err) => Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("Payload deserialization error: '{}'", err),
            )),
            Ok((initial_dkg_dealings,)) => Ok(Self {
                initial_dkg_dealings,
            }),
        }
    }
}

// Export the bitcoin types.
pub use ic_btc_interface::{
    GetBalanceRequest as BitcoinGetBalanceArgs,
    GetCurrentFeePercentilesRequest as BitcoinGetCurrentFeePercentilesArgs,
    GetUtxosRequest as BitcoinGetUtxosArgs, Network as BitcoinNetwork,
    SendTransactionRequest as BitcoinSendTransactionArgs,
};
pub use ic_btc_types_internal::{
    GetSuccessorsRequest as BitcoinGetSuccessorsArgs,
    GetSuccessorsRequestInitial as BitcoinGetSuccessorsRequestInitial,
    GetSuccessorsResponse as BitcoinGetSuccessorsResponse,
    GetSuccessorsResponseComplete as BitcoinGetSuccessorsResponseComplete,
    SendTransactionRequest as BitcoinSendTransactionInternalArgs,
};

impl Payload<'_> for BitcoinGetBalanceArgs {}
impl Payload<'_> for BitcoinGetUtxosArgs {}
impl Payload<'_> for BitcoinSendTransactionArgs {}
impl Payload<'_> for BitcoinGetCurrentFeePercentilesArgs {}
impl Payload<'_> for BitcoinGetSuccessorsArgs {}
impl Payload<'_> for BitcoinGetSuccessorsResponse {}
impl Payload<'_> for BitcoinSendTransactionInternalArgs {}
