//! Data types used for encoding/decoding the Candid payloads of ic:00.
mod bounded_vec;
mod data_size;
mod http;
mod provisional;

#[cfg(feature = "fuzzing_code")]
use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
pub use bounded_vec::*;
use candid::{CandidType, Decode, DecoderConfig, Deserialize, Encode};
pub use data_size::*;
pub use http::{
    BoundedHttpHeaders, CanisterHttpRequestArgs, CanisterHttpResponsePayload, HttpHeader,
    HttpMethod, TransformArgs, TransformContext, TransformFunc,
};
use ic_base_types::{
    CanisterId, NodeId, NumBytes, PrincipalId, RegistryVersion, SnapshotId, SubnetId,
};
use ic_error_types::{ErrorCode, UserError};
use ic_protobuf::proxy::{try_decode_hash, try_from_option_field};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::subnet::v1::{InitialIDkgDealings, InitialNiDkgTranscriptRecord};
use ic_protobuf::state::canister_state_bits::v1::{self as pb_canister_state_bits};
use ic_protobuf::types::v1::CanisterInstallModeV2 as CanisterInstallModeV2Proto;
use ic_protobuf::types::v1::{
    CanisterInstallMode as CanisterInstallModeProto,
    CanisterUpgradeOptions as CanisterUpgradeOptionsProto,
    WasmMemoryPersistence as WasmMemoryPersistenceProto,
};
use ic_protobuf::{proxy::ProxyDecodeError, registry::crypto::v1 as pb_registry_crypto};
use num_traits::cast::ToPrimitive;
pub use provisional::{ProvisionalCreateCanisterWithCyclesArgs, ProvisionalTopUpCanisterArgs};
use serde::Serialize;
use serde_bytes::ByteBuf;
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

/// Limit the amount of work for skipping unneeded data on the wire when parsing Candid.
/// The value of 10_000 follows the Candid recommendation.
const DEFAULT_SKIPPING_QUOTA: usize = 10_000;

fn decoder_config() -> DecoderConfig {
    let mut config = DecoderConfig::new();
    config.set_skipping_quota(DEFAULT_SKIPPING_QUOTA);
    config.set_full_error_message(false);
    config
}

/// Methods exported by ic:00.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, EnumIter, EnumString)]
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
    InstallChunkedCode,
    RawRand,
    SetupInitialDKG,
    SignWithECDSA,
    StartCanister,
    StopCanister,
    UninstallCode,
    UpdateSettings,
    ComputeInitialIDkgDealings,

    // Schnorr interface.
    SchnorrPublicKey,
    SignWithSchnorr,

    // Bitcoin Interface.
    BitcoinGetBalance,
    BitcoinGetUtxos,
    BitcoinGetBlockHeaders,
    BitcoinSendTransaction,
    BitcoinGetCurrentFeePercentiles,
    // Private APIs used exclusively by the bitcoin canisters.
    BitcoinSendTransactionInternal, // API for sending transactions to the network.
    BitcoinGetSuccessors,           // API for fetching blocks from the network.

    NodeMetricsHistory,

    FetchCanisterLogs,

    // These methods are only available on test IC instances where there is a
    // need to fabricate cycles without burning ICP first.
    ProvisionalCreateCanisterWithCycles,
    ProvisionalTopUpCanister,

    // Support for chunked uploading of Wasm modules.
    UploadChunk,
    StoredChunks,
    ClearChunkStore,

    // Support for canister snapshots.
    TakeCanisterSnapshot,
    LoadCanisterSnapshot,
    ListCanisterSnapshots,
    DeleteCanisterSnapshot,
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
        Decode!([decoder_config()]; blob, Self).map_err(candid_error_to_user_error)
    }
}

/// Struct used for encoding/decoding `(record {canister_id})`.
#[derive(Debug, CandidType, Deserialize, Serialize)]
pub struct CanisterIdRecord {
    canister_id: PrincipalId,
}

impl CanisterIdRecord {
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterCodeDeploymentRecord {
    mode: CanisterInstallMode,
    module_hash: [u8; WASM_HASH_LENGTH],
}

impl CanisterCodeDeploymentRecord {
    pub fn mode(&self) -> CanisterInstallMode {
        self.mode
    }
    pub fn module_hash(&self) -> [u8; WASM_HASH_LENGTH] {
        self.module_hash
    }
}

/// `CandidType` for `CanisterControllersChangeRecord`
/// ```text
/// record {
///   controllers : vec principal;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterControllersChangeRecord {
    controllers: Vec<PrincipalId>,
}

impl CanisterControllersChangeRecord {
    pub fn controllers(&self) -> &[PrincipalId] {
        &self.controllers
    }
}

/// `CandidType` for `CanisterLoadSnapshotRecord`
/// ```text
/// record {
///    canister_version : nat64;
///    snapshot_id : blob;
///    taken_at_timestamp : nat64;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterLoadSnapshotRecord {
    canister_version: u64,
    #[serde(with = "serde_bytes")]
    snapshot_id: Vec<u8>,
    taken_at_timestamp: u64,
}

impl CanisterLoadSnapshotRecord {
    pub fn new(canister_version: u64, snapshot_id: SnapshotId, taken_at_timestamp: u64) -> Self {
        Self {
            canister_version,
            snapshot_id: snapshot_id.to_vec(),
            taken_at_timestamp,
        }
    }

    pub fn canister_version(&self) -> u64 {
        self.canister_version
    }

    pub fn taken_at_timestamp(&self) -> u64 {
        self.taken_at_timestamp
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        // Safe to unwrap:
        // `CanisterLoadSnapshotRecord` contains only valid snapshot IDs.
        SnapshotId::try_from(&self.snapshot_id).unwrap()
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
///   load_snapshot : record {
///     canister_version: nat64;
///     snapshot_id: blob;
///     taken_at_timestamp: nat64;
///   };
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum CanisterChangeDetails {
    #[serde(rename = "creation")]
    CanisterCreation(CanisterCreationRecord),
    #[serde(rename = "code_uninstall")]
    CanisterCodeUninstall,
    #[serde(rename = "code_deployment")]
    CanisterCodeDeployment(CanisterCodeDeploymentRecord),
    #[serde(rename = "controllers_change")]
    CanisterControllersChange(CanisterControllersChangeRecord),
    #[serde(rename = "load_snapshot")]
    CanisterLoadSnapshot(CanisterLoadSnapshotRecord),
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

    pub fn load_snapshot(
        canister_version: u64,
        snapshot_id: Vec<u8>,
        taken_at_timestamp: u64,
    ) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterLoadSnapshot(CanisterLoadSnapshotRecord {
            canister_version,
            snapshot_id,
            taken_at_timestamp,
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
                std::mem::size_of_val(canister_creation.controllers())
            }
            CanisterChangeDetails::CanisterControllersChange(canister_controllers_change) => {
                std::mem::size_of_val(canister_controllers_change.controllers())
            }
            CanisterChangeDetails::CanisterCodeDeployment(_)
            | CanisterChangeDetails::CanisterCodeUninstall
            | CanisterChangeDetails::CanisterLoadSnapshot(_) => 0,
        };
        NumBytes::from((size_of::<CanisterChange>() + controllers_memory_size) as u64)
    }

    pub fn canister_version(&self) -> u64 {
        self.canister_version
    }

    pub fn details(&self) -> &CanisterChangeDetails {
        &self.details
    }
}

/// `CandidType` for `CanisterInfoRequest`
/// ```text
/// record {
///   canister_id : principal;
///   num_requested_changes : opt nat64;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
        CanisterId::unchecked_from_principal(self.canister_id)
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
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
            CanisterChangeDetails::CanisterLoadSnapshot(canister_load_snapshot) => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterLoadSnapshot(
                    pb_canister_state_bits::CanisterLoadSnapshot {
                        canister_version: canister_load_snapshot.canister_version,
                        snapshot_id: canister_load_snapshot.snapshot_id.clone(),
                        taken_at_timestamp: canister_load_snapshot.taken_at_timestamp,
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
            ) => {
                let mode = CanisterInstallMode::try_from(
                    CanisterInstallModeProto::try_from(canister_code_deployment.mode).map_err(
                        |_| ProxyDecodeError::ValueOutOfRange {
                            typ: "CanisterInstallMode",
                            err: format!(
                                "Unexpected value for canister install mode {}",
                                canister_code_deployment.mode
                            ),
                        },
                    )?,
                )
                .map_err(|e: CanisterInstallModeError| {
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "CanisterInstallMode",
                        err: e.to_string(),
                    }
                })?;

                let module_hash = try_decode_hash(canister_code_deployment.module_hash)?;

                Ok(CanisterChangeDetails::code_deployment(mode, module_hash))
            }
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterControllersChange(
                canister_controllers_change,
            ) => Ok(CanisterChangeDetails::controllers_change(
                canister_controllers_change
                    .controllers
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<PrincipalId>, _>>()?,
            )),
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterLoadSnapshot(
                canister_load_snapshot,
            ) => Ok(CanisterChangeDetails::load_snapshot(
                canister_load_snapshot.canister_version,
                canister_load_snapshot.snapshot_id,
                canister_load_snapshot.taken_at_timestamp,
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

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     sender_canister_version : opt nat64;
/// })`
#[derive(Debug, CandidType, Deserialize, Serialize)]
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
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl Payload<'_> for UninstallCodeArgs {}

/// Maximum number of allowed log viewers (specified in the interface spec).
const MAX_ALLOWED_LOG_VIEWERS_COUNT: usize = 10;

pub type BoundedAllowedViewers =
    BoundedVec<MAX_ALLOWED_LOG_VIEWERS_COUNT, UNBOUNDED, UNBOUNDED, PrincipalId>;

/// Log visibility for a canister.
/// ```text
/// variant {
///    controllers;
///    public;
///    allowed_viewers: vec principal;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, EnumIter)]
pub enum LogVisibilityV2 {
    #[default]
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "allowed_viewers")]
    AllowedViewers(BoundedAllowedViewers),
}

impl Payload<'_> for LogVisibilityV2 {}

impl From<&LogVisibilityV2> for pb_canister_state_bits::LogVisibilityV2 {
    fn from(item: &LogVisibilityV2) -> Self {
        use pb_canister_state_bits as pb;
        match item {
            LogVisibilityV2::Controllers => pb::LogVisibilityV2 {
                log_visibility_v2: Some(pb::log_visibility_v2::LogVisibilityV2::Controllers(1)),
            },
            LogVisibilityV2::Public => pb::LogVisibilityV2 {
                log_visibility_v2: Some(pb::log_visibility_v2::LogVisibilityV2::Public(2)),
            },
            LogVisibilityV2::AllowedViewers(principals) => pb::LogVisibilityV2 {
                log_visibility_v2: Some(pb::log_visibility_v2::LogVisibilityV2::AllowedViewers(
                    pb::LogVisibilityAllowedViewers {
                        principals: principals
                            .get()
                            .iter()
                            .map(|c| (*c).into())
                            .collect::<Vec<ic_protobuf::types::v1::PrincipalId>>()
                            .clone(),
                    },
                )),
            },
        }
    }
}

impl TryFrom<pb_canister_state_bits::LogVisibilityV2> for LogVisibilityV2 {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_canister_state_bits::LogVisibilityV2) -> Result<Self, Self::Error> {
        use pb_canister_state_bits as pb;
        let Some(log_visibility_v2) = item.log_visibility_v2 else {
            return Err(ProxyDecodeError::MissingField(
                "LogVisibilityV2::log_visibility_v2",
            ));
        };
        match log_visibility_v2 {
            pb::log_visibility_v2::LogVisibilityV2::Controllers(_) => Ok(Self::Controllers),
            pb::log_visibility_v2::LogVisibilityV2::Public(_) => Ok(Self::Public),
            pb::log_visibility_v2::LogVisibilityV2::AllowedViewers(data) => {
                let principals = data
                    .principals
                    .iter()
                    .map(|p| {
                        PrincipalId::try_from(p.raw.clone()).map_err(|e| {
                            ProxyDecodeError::ValueOutOfRange {
                                typ: "PrincipalId",
                                err: e.to_string(),
                            }
                        })
                    })
                    .collect::<Result<Vec<PrincipalId>, _>>()?;
                Ok(Self::AllowedViewers(BoundedAllowedViewers::new(principals)))
            }
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     controller : principal;
///     compute_allocation: nat;
///     memory_allocation: nat;
///     freezing_threshold: nat;
///     reserved_cycles_limit: nat;
///     log_visibility: log_visibility;
///     wasm_memory_limit: nat;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct DefiniteCanisterSettingsArgs {
    controller: PrincipalId,
    controllers: Vec<PrincipalId>,
    compute_allocation: candid::Nat,
    memory_allocation: candid::Nat,
    freezing_threshold: candid::Nat,
    reserved_cycles_limit: candid::Nat,
    log_visibility: LogVisibilityV2,
    wasm_memory_limit: candid::Nat,
}

impl DefiniteCanisterSettingsArgs {
    pub fn new(
        controller: PrincipalId,
        controllers: Vec<PrincipalId>,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
        reserved_cycles_limit: Option<u128>,
        log_visibility: LogVisibilityV2,
        wasm_memory_limit: Option<u64>,
    ) -> Self {
        let memory_allocation = candid::Nat::from(memory_allocation.unwrap_or(0));
        let reserved_cycles_limit = candid::Nat::from(reserved_cycles_limit.unwrap_or(0));
        let wasm_memory_limit = candid::Nat::from(wasm_memory_limit.unwrap_or(0));
        Self {
            controller,
            controllers,
            compute_allocation: candid::Nat::from(compute_allocation),
            memory_allocation,
            freezing_threshold: candid::Nat::from(freezing_threshold),
            reserved_cycles_limit,
            log_visibility,
            wasm_memory_limit,
        }
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.controllers.clone()
    }

    pub fn reserved_cycles_limit(&self) -> candid::Nat {
        self.reserved_cycles_limit.clone()
    }

    pub fn log_visibility(&self) -> &LogVisibilityV2 {
        &self.log_visibility
    }

    pub fn wasm_memory_limit(&self) -> candid::Nat {
        self.wasm_memory_limit.clone()
    }
}

impl Payload<'_> for DefiniteCanisterSettingsArgs {}

/// The deprecated version of CanisterStatusResult that is being
/// used by NNS canisters.
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
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

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct QueryStats {
    num_calls_total: candid::Nat,
    num_instructions_total: candid::Nat,
    request_payload_bytes_total: candid::Nat,
    response_payload_bytes_total: candid::Nat,
}

/// Struct used for encoding/decoding
/// `(record {
///     status : variant { running; stopping; stopped };
///     settings: definite_canister_settings;
///     module_hash: opt blob;
///     controller: principal;
///     memory_size: nat;
///     cycles: nat;
///     freezing_threshold: nat,
///     idle_cycles_burned_per_day: nat;
///     reserved_cycles: nat;
///     query_stats: record {
///         num_calls: nat;
///         num_instructions: nat;
///         ingress_payload_size: nat;
///         egress_payload_size: nat;
///     }
/// })`
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
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
    reserved_cycles: candid::Nat,
    query_stats: QueryStats,
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
        reserved_cycles_limit: Option<u128>,
        log_visibility: LogVisibilityV2,
        idle_cycles_burned_per_day: u128,
        reserved_cycles: u128,
        query_num_calls: u128,
        query_num_instructions: u128,
        query_ingress_payload_size: u128,
        query_egress_payload_size: u128,
        wasm_memory_limit: Option<u64>,
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
                reserved_cycles_limit,
                log_visibility,
                wasm_memory_limit,
            ),
            freezing_threshold: candid::Nat::from(freezing_threshold),
            idle_cycles_burned_per_day: candid::Nat::from(idle_cycles_burned_per_day),
            reserved_cycles: candid::Nat::from(reserved_cycles),
            query_stats: QueryStats {
                num_calls_total: candid::Nat::from(query_num_calls),
                num_instructions_total: candid::Nat::from(query_num_instructions),
                request_payload_bytes_total: candid::Nat::from(query_ingress_payload_size),
                response_payload_bytes_total: candid::Nat::from(query_egress_payload_size),
            },
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

    pub fn compute_allocation(&self) -> u64 {
        self.settings.compute_allocation.0.to_u64().unwrap()
    }

    pub fn memory_allocation(&self) -> u64 {
        self.settings.memory_allocation.0.to_u64().unwrap()
    }

    pub fn idle_cycles_burned_per_day(&self) -> u128 {
        self.idle_cycles_burned_per_day.0.to_u128().unwrap()
    }

    pub fn reserved_cycles(&self) -> u128 {
        self.reserved_cycles.0.to_u128().unwrap()
    }

    pub fn settings(&self) -> DefiniteCanisterSettingsArgs {
        self.settings.clone()
    }
}

/// Indicates whether the canister is running, stopping, or stopped.
///
/// Unlike `CanisterStatus`, it contains no additional metadata.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
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
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Default,
    CandidType,
    Deserialize,
    EnumIter,
    EnumString,
    Serialize,
)]
pub enum CanisterInstallMode {
    /// A fresh install of a new canister.
    #[serde(rename = "install")]
    #[strum(serialize = "install")]
    #[default]
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

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
/// Wasm main memory retention on upgrades.
/// Currently used to specify the persistence of Wasm main memory.
pub enum WasmMemoryPersistence {
    /// Retain the main memory across upgrades.
    /// Used for enhanced orthogonal persistence, as implemented in Motoko
    Keep,
    /// Reinitialize the main memory on upgrade.
    /// Default behavior without enhanced orthogonal persistence.
    Replace,
}

impl WasmMemoryPersistence {
    pub fn iter() -> Iter<'static, WasmMemoryPersistence> {
        static MODES: [WasmMemoryPersistence; 2] =
            [WasmMemoryPersistence::Keep, WasmMemoryPersistence::Replace];
        MODES.iter()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Deserialize, Serialize)]
/// Struct used for encoding/decoding:
/// `record {
///    skip_pre_upgrade: opt bool;
///    wasm_memory_persistence : opt variant {
///      keep;
///      replace;
///    };
/// }`
/// Extendibility for the future: Adding new optional fields ensures both backwards- and
/// forwards-compatibility in Candid.
pub struct CanisterUpgradeOptions {
    /// Determine whether the pre-upgrade hook should be skipped during upgrade.
    pub skip_pre_upgrade: Option<bool>,
    /// Support for enhanced orthogonal persistence: Retain the main memory on upgrade.
    pub wasm_memory_persistence: Option<WasmMemoryPersistence>,
}

/// The mode with which a canister is installed.
///
/// This second version of the mode allows someone to specify upgrade options.
#[derive(
    Copy, Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Deserialize, EnumString, Serialize,
)]
pub enum CanisterInstallModeV2 {
    /// A fresh install of a new canister.
    #[serde(rename = "install")]
    #[strum(serialize = "install")]
    #[default]
    Install,
    /// Reinstalling a canister that was already installed.
    #[serde(rename = "reinstall")]
    #[strum(serialize = "reinstall")]
    Reinstall,
    /// Upgrade an existing canister.
    #[serde(rename = "upgrade")]
    #[strum(serialize = "upgrade")]
    Upgrade(Option<CanisterUpgradeOptions>),
}

impl CanisterInstallModeV2 {
    pub fn iter() -> Iter<'static, CanisterInstallModeV2> {
        static MODES: [CanisterInstallModeV2; 12] = [
            CanisterInstallModeV2::Install,
            CanisterInstallModeV2::Reinstall,
            CanisterInstallModeV2::Upgrade(None),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: None,
                wasm_memory_persistence: None,
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: None,
                wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: None,
                wasm_memory_persistence: Some(WasmMemoryPersistence::Replace),
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: Some(false),
                wasm_memory_persistence: None,
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: Some(false),
                wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: Some(false),
                wasm_memory_persistence: Some(WasmMemoryPersistence::Replace),
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: Some(true),
                wasm_memory_persistence: None,
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: Some(true),
                wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
            })),
            CanisterInstallModeV2::Upgrade(Some(CanisterUpgradeOptions {
                skip_pre_upgrade: Some(true),
                wasm_memory_persistence: Some(WasmMemoryPersistence::Replace),
            })),
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

impl TryFrom<CanisterInstallModeProto> for CanisterInstallMode {
    type Error = CanisterInstallModeError;

    fn try_from(item: CanisterInstallModeProto) -> Result<Self, Self::Error> {
        match item {
            CanisterInstallModeProto::Install => Ok(CanisterInstallMode::Install),
            CanisterInstallModeProto::Reinstall => Ok(CanisterInstallMode::Reinstall),
            CanisterInstallModeProto::Upgrade => Ok(CanisterInstallMode::Upgrade),
            CanisterInstallModeProto::Unspecified => {
                Err(CanisterInstallModeError((item as i32).to_string()))
            }
        }
    }
}

impl TryFrom<CanisterInstallModeV2Proto> for CanisterInstallModeV2 {
    type Error = CanisterInstallModeError;

    fn try_from(item: CanisterInstallModeV2Proto) -> Result<Self, Self::Error> {
        match item.canister_install_mode_v2.unwrap() {
            ic_protobuf::types::v1::canister_install_mode_v2::CanisterInstallModeV2::Mode(item) => {
                match CanisterInstallModeProto::try_from(item).ok() {
                    Some(CanisterInstallModeProto::Install) => Ok(CanisterInstallModeV2::Install),
                    Some(CanisterInstallModeProto::Reinstall) => {
                        Ok(CanisterInstallModeV2::Reinstall)
                    }
                    Some(CanisterInstallModeProto::Upgrade) => {
                        Ok(CanisterInstallModeV2::Upgrade(None))
                    }
                    Some(CanisterInstallModeProto::Unspecified) | None => {
                        Err(CanisterInstallModeError(item.to_string()))
                    }
                }
            }

            ic_protobuf::types::v1::canister_install_mode_v2::CanisterInstallModeV2::Mode2(
                upgrade_mode,
            ) => Ok(CanisterInstallModeV2::Upgrade(Some(
                CanisterUpgradeOptions {
                    skip_pre_upgrade: upgrade_mode.skip_pre_upgrade,
                    wasm_memory_persistence: match upgrade_mode.wasm_memory_persistence {
                        None => None,
                        Some(mode) => Some(match WasmMemoryPersistenceProto::try_from(mode).ok() {
                            Some(persistence) => WasmMemoryPersistence::try_from(persistence),
                            None => Err(CanisterInstallModeError(
                                format!("Invalid `WasmMemoryPersistence` value: {mode}")
                                    .to_string(),
                            )),
                        }?),
                    },
                },
            ))),
        }
    }
}

impl From<CanisterInstallMode> for String {
    fn from(mode: CanisterInstallMode) -> Self {
        let result = match mode {
            CanisterInstallMode::Install => "install",
            CanisterInstallMode::Reinstall => "reinstall",
            CanisterInstallMode::Upgrade => "upgrade",
        };
        result.to_string()
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

impl From<&CanisterInstallModeV2> for CanisterInstallModeV2Proto {
    fn from(item: &CanisterInstallModeV2) -> Self {
        CanisterInstallModeV2Proto {
            canister_install_mode_v2: Some(match item {
                CanisterInstallModeV2::Install => {
                    ic_protobuf::types::v1::canister_install_mode_v2::CanisterInstallModeV2::Mode(
                        CanisterInstallModeProto::Install.into(),
                    )
                }
                CanisterInstallModeV2::Reinstall => {
                    ic_protobuf::types::v1::canister_install_mode_v2::CanisterInstallModeV2::Mode(
                        CanisterInstallModeProto::Reinstall.into(),
                    )
                }
                CanisterInstallModeV2::Upgrade(None) => {
                    ic_protobuf::types::v1::canister_install_mode_v2::CanisterInstallModeV2::Mode(
                        CanisterInstallModeProto::Upgrade.into(),
                    )
                }
                CanisterInstallModeV2::Upgrade(Some(upgrade_options)) => {
                    ic_protobuf::types::v1::canister_install_mode_v2::CanisterInstallModeV2::Mode2(
                        CanisterUpgradeOptionsProto {
                            skip_pre_upgrade: upgrade_options.skip_pre_upgrade,
                            wasm_memory_persistence: upgrade_options.wasm_memory_persistence.map(
                                |mode| {
                                    let proto: WasmMemoryPersistenceProto = (&mode).into();
                                    proto.into()
                                },
                            ),
                        },
                    )
                }
            }),
        }
    }
}

impl From<CanisterInstallModeV2> for CanisterInstallMode {
    /// This function is used only in the Canister History to avoid breaking changes.
    /// The function is lossy, hence it should be avoided when possible.
    fn from(item: CanisterInstallModeV2) -> Self {
        match item {
            CanisterInstallModeV2::Install => CanisterInstallMode::Install,
            CanisterInstallModeV2::Reinstall => CanisterInstallMode::Reinstall,
            CanisterInstallModeV2::Upgrade(_) => CanisterInstallMode::Upgrade,
        }
    }
}

impl From<&WasmMemoryPersistence> for WasmMemoryPersistenceProto {
    fn from(item: &WasmMemoryPersistence) -> Self {
        match item {
            WasmMemoryPersistence::Keep => WasmMemoryPersistenceProto::Keep,
            WasmMemoryPersistence::Replace => WasmMemoryPersistenceProto::Replace,
        }
    }
}

impl TryFrom<WasmMemoryPersistenceProto> for WasmMemoryPersistence {
    type Error = CanisterInstallModeError;

    fn try_from(item: WasmMemoryPersistenceProto) -> Result<Self, Self::Error> {
        match item {
            WasmMemoryPersistenceProto::Keep => Ok(WasmMemoryPersistence::Keep),
            WasmMemoryPersistenceProto::Replace => Ok(WasmMemoryPersistence::Replace),
            WasmMemoryPersistenceProto::Unspecified => Err(CanisterInstallModeError(
                format!("Invalid `WasmMemoryPersistence` value: {item:?}").to_string(),
            )),
        }
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
///     sender_canister_version : opt nat64;
/// })`
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InstallCodeArgs {
    pub mode: CanisterInstallMode,
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
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
    ) -> Self {
        Self {
            mode,
            canister_id: canister_id.into(),
            wasm_module,
            arg,
            compute_allocation: compute_allocation.map(candid::Nat::from),
            memory_allocation: memory_allocation.map(candid::Nat::from),
            sender_canister_version: None,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InstallCodeArgsV2 {
    pub mode: CanisterInstallModeV2,
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub sender_canister_version: Option<u64>,
}

impl std::fmt::Display for InstallCodeArgsV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "InstallCodeArgsV2 {{")?;
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
        writeln!(f, "}}")
    }
}

impl Payload<'_> for InstallCodeArgsV2 {}

impl InstallCodeArgsV2 {
    pub fn new(
        mode: CanisterInstallModeV2,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
    ) -> Self {
        Self {
            mode,
            canister_id: canister_id.into(),
            wasm_module,
            arg,
            compute_allocation: compute_allocation.map(candid::Nat::from),
            memory_allocation: memory_allocation.map(candid::Nat::from),
            sender_canister_version: None,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
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
        Decode!([decoder_config()]; blob)
            .map(|_| EmptyBlob)
            .map_err(candid_error_to_user_error)
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     settings: canister_settings;
///     sender_canister_version : opt nat64;
/// })`
#[derive(Debug, CandidType, Deserialize)]
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
        CanisterId::unchecked_from_principal(self.canister_id)
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
            CanisterSettingsArgsBuilder::new()
                .with_controllers(<Vec<PrincipalId>>::arbitrary(u)?)
                .with_compute_allocation(u64::arbitrary(u)?)
                .with_memory_allocation(u64::arbitrary(u)?)
                .with_freezing_threshold(u64::arbitrary(u)?)
                .build(),
        ))
    }
}

impl Payload<'_> for UpdateSettingsArgs {}

/// Maximum number of controllers allowed in a request (specified in the interface spec).
const MAX_ALLOWED_CONTROLLERS_COUNT: usize = 10;

pub type BoundedControllers =
    BoundedVec<MAX_ALLOWED_CONTROLLERS_COUNT, UNBOUNDED, UNBOUNDED, PrincipalId>;

impl Payload<'_> for BoundedControllers {}

impl DataSize for PrincipalId {
    fn data_size(&self) -> usize {
        self.as_slice().data_size()
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     controllers: opt vec principal;
///     compute_allocation: opt nat;
///     memory_allocation: opt nat;
///     freezing_threshold: opt nat;
///     reserved_cycles_limit: opt nat;
///     log_visibility : opt log_visibility;
///     wasm_memory_limit: opt nat;
///     wasm_memory_threshold: opt nat;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct CanisterSettingsArgs {
    pub controllers: Option<BoundedControllers>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibilityV2>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub wasm_memory_threshold: Option<candid::Nat>,
}

impl Payload<'_> for CanisterSettingsArgs {}

impl CanisterSettingsArgs {
    /// Note: do not use `new(...)` with passing all the arguments, use corresponding builder instead.
    #[deprecated(note = "please use `CanisterSettingsArgsBuilder` instead")]
    pub fn new() -> Self {
        Self {
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
            log_visibility: None,
            wasm_memory_limit: None,
            wasm_memory_threshold: None,
        }
    }
}

#[derive(Default)]
pub struct CanisterSettingsArgsBuilder {
    controllers: Option<Vec<PrincipalId>>,
    compute_allocation: Option<candid::Nat>,
    memory_allocation: Option<candid::Nat>,
    freezing_threshold: Option<candid::Nat>,
    reserved_cycles_limit: Option<candid::Nat>,
    log_visibility: Option<LogVisibilityV2>,
    wasm_memory_limit: Option<candid::Nat>,
    wasm_memory_threshold: Option<candid::Nat>,
}

#[allow(dead_code)]
impl CanisterSettingsArgsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> CanisterSettingsArgs {
        CanisterSettingsArgs {
            controllers: self.controllers.map(BoundedControllers::new),
            compute_allocation: self.compute_allocation,
            memory_allocation: self.memory_allocation,
            freezing_threshold: self.freezing_threshold,
            reserved_cycles_limit: self.reserved_cycles_limit,
            log_visibility: self.log_visibility,
            wasm_memory_limit: self.wasm_memory_limit,
            wasm_memory_threshold: self.wasm_memory_threshold,
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

    /// Optionally sets the compute allocation in percent.
    pub fn with_maybe_compute_allocation(self, compute_allocation: Option<u64>) -> Self {
        match compute_allocation {
            Some(compute_allocation) => self.with_compute_allocation(compute_allocation),
            None => self,
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

    /// Optionally sets the memory allocation in percent.
    pub fn with_maybe_memory_allocation(self, memory_allocation: Option<u64>) -> Self {
        match memory_allocation {
            Some(memory_allocation) => self.with_memory_allocation(memory_allocation),
            None => self,
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

    /// Sets the reserved cycles limit in cycles.
    pub fn with_reserved_cycles_limit(self, reserved_cycles_limit: u128) -> Self {
        Self {
            reserved_cycles_limit: Some(candid::Nat::from(reserved_cycles_limit)),
            ..self
        }
    }

    /// Sets the log visibility.
    pub fn with_log_visibility(self, log_visibility: LogVisibilityV2) -> Self {
        Self {
            log_visibility: Some(log_visibility),
            ..self
        }
    }

    /// Sets the Wasm memory limit.
    pub fn with_wasm_memory_limit(self, wasm_memory_limit: u64) -> Self {
        Self {
            wasm_memory_limit: Some(candid::Nat::from(wasm_memory_limit)),
            ..self
        }
    }

    /// Sets the Wasm memory threshold in bytes.
    pub fn with_wasm_memory_threshold(self, wasm_memory_threshold: u64) -> Self {
        Self {
            wasm_memory_threshold: Some(candid::Nat::from(wasm_memory_threshold)),
            ..self
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     settings : opt canister_settings;
///     sender_canister_version : opt nat64;
/// })`
#[derive(Clone, PartialEq, Debug, Default, CandidType, Deserialize)]
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
        match Decode!([decoder_config()]; blob, Self) {
            Err(err) => {
                // First check if deserialization failed due to exceeding the maximum allowed limit.
                if format!("{err:?}").contains("The number of elements exceeds maximum allowed") {
                    Err(UserError::new(
                        ErrorCode::InvalidManagementPayload,
                        format!("Payload deserialization error: {err:?}"),
                    ))
                } else {
                    // Decoding an empty blob is added for backward compatibility.
                    match EmptyBlob::decode(blob) {
                        Err(_) => Err(UserError::new(
                            ErrorCode::InvalidManagementPayload,
                            "Payload deserialization error.".to_string(),
                        )),
                        Ok(_) => Ok(CreateCanisterArgs::default()),
                    }
                }
            }
            Ok(settings) => Ok(settings),
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     node_ids : vec principal;
///     registry_version: nat64;
/// })`
#[derive(Debug, CandidType, Deserialize)]
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
                    ErrorCode::InvalidManagementPayload,
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
            Decode!([decoder_config()]; blob, Vec<u8>).map_err(candid_error_to_user_error)?;
        match serde_cbor::from_slice::<(
            InitialNiDkgTranscriptRecord,
            InitialNiDkgTranscriptRecord,
            SubnetId,
            PublicKey,
        )>(&serde_encoded_transcript_records)
        {
            Err(err) => Err(UserError::new(
                ErrorCode::InvalidManagementPayload,
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
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    EnumIter,
    Serialize,
)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl From<&EcdsaCurve> for pb_registry_crypto::EcdsaCurve {
    fn from(item: &EcdsaCurve) -> Self {
        match item {
            EcdsaCurve::Secp256k1 => pb_registry_crypto::EcdsaCurve::Secp256k1,
        }
    }
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

impl std::fmt::Display for EcdsaCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for EcdsaCurve {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "secp256k1" => Ok(Self::Secp256k1),
            _ => Err(format!("{} is not a recognized ECDSA curve", s)),
        }
    }
}

/// Unique identifier for a key that can be used for ECDSA signatures. The name
/// is just a identifier, but it may be used to convey some information about
/// the key (e.g. that the key is meant to be used for testing purposes).
/// ```text
/// (record { curve: ecdsa_curve; name: text})
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

impl From<&EcdsaKeyId> for pb_registry_crypto::EcdsaKeyId {
    fn from(item: &EcdsaKeyId) -> Self {
        Self {
            curve: pb_registry_crypto::EcdsaCurve::from(&item.curve) as i32,
            name: item.name.clone(),
        }
    }
}

impl TryFrom<pb_registry_crypto::EcdsaKeyId> for EcdsaKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_registry_crypto::EcdsaKeyId) -> Result<Self, Self::Error> {
        Ok(Self {
            curve: EcdsaCurve::try_from(
                pb_registry_crypto::EcdsaCurve::try_from(item.curve).map_err(|_| {
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "EcdsaKeyId",
                        err: format!("Unable to convert {} to an EcdsaCurve", item.curve),
                    }
                })?,
            )?,
            name: item.name,
        })
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

/// Types of algorithms that can be used for Schnorr signing.
/// ```text
/// (variant { bip340secp256k1; ed25519 })
/// ```
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    EnumIter,
    Serialize,
)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256k1,
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl From<&SchnorrAlgorithm> for pb_registry_crypto::SchnorrAlgorithm {
    fn from(item: &SchnorrAlgorithm) -> Self {
        match item {
            SchnorrAlgorithm::Bip340Secp256k1 => {
                pb_registry_crypto::SchnorrAlgorithm::Bip340secp256k1
            }
            SchnorrAlgorithm::Ed25519 => pb_registry_crypto::SchnorrAlgorithm::Ed25519,
        }
    }
}

impl TryFrom<pb_registry_crypto::SchnorrAlgorithm> for SchnorrAlgorithm {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_registry_crypto::SchnorrAlgorithm) -> Result<Self, Self::Error> {
        match item {
            pb_registry_crypto::SchnorrAlgorithm::Bip340secp256k1 => {
                Ok(SchnorrAlgorithm::Bip340Secp256k1)
            }
            pb_registry_crypto::SchnorrAlgorithm::Ed25519 => Ok(SchnorrAlgorithm::Ed25519),
            pb_registry_crypto::SchnorrAlgorithm::Unspecified => {
                Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "SchnorrAlgorithm",
                    err: format!("Unable to convert {:?} to a SchnorrAlgorithm", item),
                })
            }
        }
    }
}

impl std::fmt::Display for SchnorrAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for SchnorrAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bip340secp256k1" => Ok(Self::Bip340Secp256k1),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(format!("{} is not a recognized Schnorr algorithm", s)),
        }
    }
}

/// Unique identifier for a key that can be used for Schnorr signatures. The name
/// is just a identifier, but it may be used to convey some information about
/// the key (e.g. that the key is meant to be used for testing purposes).
/// ```text
/// (record { algorithm: schnorr_algorithm; name: text})
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

impl From<&SchnorrKeyId> for pb_registry_crypto::SchnorrKeyId {
    fn from(item: &SchnorrKeyId) -> Self {
        Self {
            algorithm: pb_registry_crypto::SchnorrAlgorithm::from(&item.algorithm) as i32,
            name: item.name.clone(),
        }
    }
}

impl TryFrom<pb_registry_crypto::SchnorrKeyId> for SchnorrKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_registry_crypto::SchnorrKeyId) -> Result<Self, Self::Error> {
        let pb_registry_crypto::SchnorrKeyId { algorithm, name } = item;
        let algorithm = SchnorrAlgorithm::try_from(
            pb_registry_crypto::SchnorrAlgorithm::try_from(algorithm).map_err(|_| {
                ProxyDecodeError::ValueOutOfRange {
                    typ: "SchnorrKeyId",
                    err: format!("Unable to convert {} to a SchnorrAlgorithm", algorithm),
                }
            })?,
        )?;
        Ok(Self { algorithm, name })
    }
}

impl std::fmt::Display for SchnorrKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.name)
    }
}

impl FromStr for SchnorrKeyId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (algorithm, name) = s
            .split_once(':')
            .ok_or_else(|| format!("Schnorr key id {} does not contain a ':'", s))?;
        Ok(SchnorrKeyId {
            algorithm: algorithm.parse::<SchnorrAlgorithm>()?,
            name: name.to_string(),
        })
    }
}

/// Unique identifier for a key that can be used for one of the signature schemes
/// supported on the IC.
/// ```text
/// (variant { EcdsaKeyId; SchnorrKeyId })
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub enum MasterPublicKeyId {
    Ecdsa(EcdsaKeyId),
    Schnorr(SchnorrKeyId),
}

impl From<&MasterPublicKeyId> for pb_registry_crypto::MasterPublicKeyId {
    fn from(item: &MasterPublicKeyId) -> Self {
        use pb_registry_crypto::master_public_key_id::KeyId;
        let key_id_pb = match item {
            MasterPublicKeyId::Schnorr(schnorr_key_id) => KeyId::Schnorr(schnorr_key_id.into()),
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => KeyId::Ecdsa(ecdsa_key_id.into()),
        };
        Self {
            key_id: Some(key_id_pb),
        }
    }
}

impl TryFrom<pb_registry_crypto::MasterPublicKeyId> for MasterPublicKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_registry_crypto::MasterPublicKeyId) -> Result<Self, Self::Error> {
        use pb_registry_crypto::master_public_key_id::KeyId;
        let Some(key_id_pb) = item.key_id else {
            return Err(ProxyDecodeError::MissingField("MasterPublicKeyId::key_id"));
        };
        let master_public_key_id = match key_id_pb {
            KeyId::Schnorr(schnorr_key_id) => {
                MasterPublicKeyId::Schnorr(schnorr_key_id.try_into()?)
            }
            KeyId::Ecdsa(ecdsa_key_id) => MasterPublicKeyId::Ecdsa(ecdsa_key_id.try_into()?),
        };
        Ok(master_public_key_id)
    }
}

impl std::fmt::Display for MasterPublicKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ecdsa(esdsa_key_id) => {
                write!(f, "ecdsa:")?;
                esdsa_key_id.fmt(f)
            }
            Self::Schnorr(schnorr_key_id) => {
                write!(f, "schnorr:")?;
                schnorr_key_id.fmt(f)
            }
        }
    }
}

impl FromStr for MasterPublicKeyId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, key_id) = s
            .split_once(':')
            .ok_or_else(|| format!("Master public key id {} does not contain a ':'", s))?;
        match scheme.to_lowercase().as_str() {
            "ecdsa" => Ok(Self::Ecdsa(EcdsaKeyId::from_str(key_id)?)),
            "schnorr" => Ok(Self::Schnorr(SchnorrKeyId::from_str(key_id)?)),
            _ => Err(format!(
                "Scheme {} in master public key id {} is not supported.",
                scheme, s
            )),
        }
    }
}

pub type DerivationPath = BoundedVec<MAXIMUM_DERIVATION_PATH_LENGTH, UNBOUNDED, UNBOUNDED, ByteBuf>;

impl DerivationPath {
    /// Converts the `DerivationPath`` from `BoundedVec<ByteBuf>` into a `Vec<Vec<u8>>`.
    pub fn into_inner(self) -> Vec<Vec<u8>> {
        self.get().iter().map(|x| x.to_vec()).collect()
    }
}

impl Payload<'_> for DerivationPath {}

impl DataSize for ByteBuf {
    fn data_size(&self) -> usize {
        self.as_slice().data_size()
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
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SignWithECDSAArgs {
    pub message_hash: [u8; 32],
    pub derivation_path: DerivationPath,
    pub key_id: EcdsaKeyId,
}

impl Payload<'_> for SignWithECDSAArgs {}

/// Struct used to return an ECDSA signature.
#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithECDSAReply {
    #[serde(with = "serde_bytes")]
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
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
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
#[derive(Debug, CandidType, Deserialize)]
pub struct ECDSAPublicKeyResponse {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>,
}

impl Payload<'_> for ECDSAPublicKeyResponse {}

/// Maximum number of nodes allowed in a ComputeInitialDealings request.
const MAX_ALLOWED_NODES_COUNT: usize = 100;

pub type BoundedNodes = BoundedVec<MAX_ALLOWED_NODES_COUNT, UNBOUNDED, UNBOUNDED, PrincipalId>;

/// Argument of the compute_initial_idkg_dealings API.
/// `(record {
///     key_id: master_public_key_id;
///     subnet_id: principal;
///     nodes: vec principal;
///     registry_version: nat64;
/// })`
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ComputeInitialIDkgDealingsArgs {
    pub key_id: MasterPublicKeyId,
    pub subnet_id: SubnetId,
    nodes: BoundedNodes,
    registry_version: u64,
}

impl Payload<'_> for ComputeInitialIDkgDealingsArgs {}

impl ComputeInitialIDkgDealingsArgs {
    pub fn new(
        key_id: MasterPublicKeyId,
        subnet_id: SubnetId,
        nodes: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            key_id,
            subnet_id,
            nodes: BoundedNodes::new(nodes.iter().map(|id| id.get()).collect()),
            registry_version: registry_version.get(),
        }
    }

    pub fn get_set_of_nodes(&self) -> Result<BTreeSet<NodeId>, UserError> {
        let mut set = BTreeSet::<NodeId>::new();
        for node_id in self.nodes.get().iter() {
            if !set.insert(NodeId::new(*node_id)) {
                return Err(UserError::new(
                    ErrorCode::InvalidManagementPayload,
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

/// Represents the argument of the sign_with_schnorr API.
/// ```text
/// (record {
///   message : blob;
///   derivation_path : vec blob;
///   key_id : schnorr_key_id;
/// })
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SignWithSchnorrArgs {
    #[serde(with = "serde_bytes")]
    pub message: Vec<u8>,
    pub derivation_path: DerivationPath,
    pub key_id: SchnorrKeyId,
}

impl Payload<'_> for SignWithSchnorrArgs {}

/// Struct used to return an Schnorr signature.
#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithSchnorrReply {
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl Payload<'_> for SignWithSchnorrReply {}

/// Represents the argument of the schnorr_public_key API.
/// ```text
/// (record {
///   canister_id : opt canister_id;
///   derivation_path : vec blob;
///   key_id : schnorr_key_id;
/// })
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SchnorrPublicKeyArgs {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: DerivationPath,
    pub key_id: SchnorrKeyId,
}

impl Payload<'_> for SchnorrPublicKeyArgs {}

/// Represents the response of the schnorr_public_key API.
/// ```text
/// (record {
///   public_key : blob;
///   chain_code : blob;
/// })
/// ```
#[derive(Debug, CandidType, Deserialize)]
pub struct SchnorrPublicKeyResponse {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>,
}

impl Payload<'_> for SchnorrPublicKeyResponse {}

/// Struct used to return the xnet initial dealings.
#[derive(Debug)]
pub struct ComputeInitialIDkgDealingsResponse {
    pub initial_dkg_dealings: InitialIDkgDealings,
}

impl ComputeInitialIDkgDealingsResponse {
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
            Decode!([decoder_config()]; blob, Vec<u8>).map_err(candid_error_to_user_error)?;
        match serde_cbor::from_slice::<(InitialIDkgDealings,)>(&serde_encoded_transcript_records) {
            Err(err) => Err(UserError::new(
                ErrorCode::InvalidManagementPayload,
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
    GetBlockHeadersRequest as BitcoinGetBlockHeadersArgs,
    GetCurrentFeePercentilesRequest as BitcoinGetCurrentFeePercentilesArgs,
    GetUtxosRequest as BitcoinGetUtxosArgs, Network as BitcoinNetwork,
    SendTransactionRequest as BitcoinSendTransactionArgs,
};
pub use ic_btc_replica_types::{
    GetSuccessorsRequest as BitcoinGetSuccessorsArgs,
    GetSuccessorsRequestInitial as BitcoinGetSuccessorsRequestInitial,
    GetSuccessorsResponse as BitcoinGetSuccessorsResponse,
    GetSuccessorsResponseComplete as BitcoinGetSuccessorsResponseComplete,
    SendTransactionRequest as BitcoinSendTransactionInternalArgs,
};

impl Payload<'_> for BitcoinGetBalanceArgs {}
impl Payload<'_> for BitcoinGetUtxosArgs {}
impl Payload<'_> for BitcoinGetBlockHeadersArgs {}
impl Payload<'_> for BitcoinSendTransactionArgs {}
impl Payload<'_> for BitcoinGetCurrentFeePercentilesArgs {}
impl Payload<'_> for BitcoinGetSuccessorsArgs {}
impl Payload<'_> for BitcoinGetSuccessorsResponse {}
impl Payload<'_> for BitcoinSendTransactionInternalArgs {}

/// Query methods exported by the management canister.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, EnumIter, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum QueryMethod {
    FetchCanisterLogs,
}

/// `CandidType` for `NodeMetricsHistoryArgs`
/// ```text
/// record {
///     subnet_id: principal;
///     start_at_timestamp_nanos: nat64;
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct NodeMetricsHistoryArgs {
    pub subnet_id: PrincipalId,
    pub start_at_timestamp_nanos: u64,
}

impl Payload<'_> for NodeMetricsHistoryArgs {}

/// `CandidType` for `NodeMetrics`
/// ```text
/// record {
///     node_id : principal;
///     num_blocks_proposed_total : nat64;
///     num_block_failures_total : nat64;
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct NodeMetrics {
    pub node_id: PrincipalId,
    pub num_blocks_proposed_total: u64,
    pub num_block_failures_total: u64,
}

impl Payload<'_> for NodeMetrics {}

/// `CandidType` for `NodeMetricsHistoryResponse`
/// ```text
/// record {
///     timestamp_nanos : nat64;
///     node_metrics : vec node_metrics;
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct NodeMetricsHistoryResponse {
    pub timestamp_nanos: u64,
    pub node_metrics: Vec<NodeMetrics>,
}

impl Payload<'_> for NodeMetricsHistoryResponse {}

/// `CandidType` for `FetchCanisterLogsRequest`
/// ```text
/// record {
///     canister_id: principal;
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct FetchCanisterLogsRequest {
    pub canister_id: PrincipalId,
}

impl Payload<'_> for FetchCanisterLogsRequest {}

impl FetchCanisterLogsRequest {
    pub fn new(canister_id: CanisterId) -> Self {
        Self {
            canister_id: canister_id.into(),
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

/// `CandidType` for `CanisterLogRecord`
/// ```text
/// record {
///     idx: nat64;
///     timestamp_nanos: nat64;
///     content: blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct CanisterLogRecord {
    pub idx: u64,
    pub timestamp_nanos: u64,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

impl Payload<'_> for CanisterLogRecord {}

impl DataSize for CanisterLogRecord {
    fn data_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.content.as_slice().data_size()
    }
}

#[test]
fn test_canister_log_record_data_size() {
    let record = CanisterLogRecord {
        idx: 100,
        timestamp_nanos: 200,
        content: vec![1, 2, 3],
    };
    assert_eq!(record.data_size(), 8 + 8 + 24 + 3);
}

impl From<&CanisterLogRecord> for pb_canister_state_bits::CanisterLogRecord {
    fn from(item: &CanisterLogRecord) -> Self {
        Self {
            idx: item.idx,
            timestamp_nanos: item.timestamp_nanos,
            content: item.content.clone(),
        }
    }
}

impl From<pb_canister_state_bits::CanisterLogRecord> for CanisterLogRecord {
    fn from(item: pb_canister_state_bits::CanisterLogRecord) -> Self {
        Self {
            idx: item.idx,
            timestamp_nanos: item.timestamp_nanos,
            content: item.content,
        }
    }
}

/// `CandidType` for `FetchCanisterLogsResponse`
/// ```text
/// record {
///     canister_log_records: vec canister_log_record;
/// }
/// ```
#[derive(Clone, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct FetchCanisterLogsResponse {
    pub canister_log_records: Vec<CanisterLogRecord>,
}

impl Payload<'_> for FetchCanisterLogsResponse {}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
///     chunk: blob;
/// })`
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct UploadChunkArgs {
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub chunk: Vec<u8>,
}

impl Payload<'_> for UploadChunkArgs {}

impl UploadChunkArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

/// Candid type representing the hash of a wasm chunk.
/// `(record {
///      hash: blob;
/// })`
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize)]
pub struct ChunkHash {
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl Payload<'_> for ChunkHash {}

/// Struct to be returned when uploading a Wasm chunk.
/// `(record {
///      hash: blob;
/// })`
pub type UploadChunkReply = ChunkHash;

/// Struct used for encoding/decoding
/// `(record {
///     mode : variant {
///         install;
///         reinstall;
///         upgrade: opt record {
///             skip_pre_upgrade: opt bool
///         }
///     };
///     target_canister_id: principal;
///     store_canister_id: opt principal;
///     chunk_hashes_list: vec chunk_hash;
///     wasm_module_hash: blob;
///     arg: blob;
///     sender_canister_version : opt nat64;
/// })`
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InstallChunkedCodeArgs {
    pub mode: CanisterInstallModeV2,
    pub target_canister: PrincipalId,
    pub store_canister: Option<PrincipalId>,
    pub chunk_hashes_list: Vec<ChunkHash>,
    #[serde(with = "serde_bytes")]
    pub wasm_module_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub sender_canister_version: Option<u64>,
}

impl std::fmt::Display for InstallChunkedCodeArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "InstallChunkedCodeArgs {{")?;
        writeln!(f, "  mode: {:?}", &self.mode)?;
        writeln!(f, "  target_canister: {:?}", &self.target_canister)?;
        writeln!(f, "  store_canister: {:?}", &self.store_canister)?;
        writeln!(f, "  arg: <{:?} bytes>", self.arg.len())?;
        writeln!(f, "}}")
    }
}

impl Payload<'_> for InstallChunkedCodeArgs {
    fn decode(blob: &'_ [u8]) -> Result<Self, UserError> {
        let args = match Decode!([decoder_config()]; blob, Self).map_err(candid_error_to_user_error)
        {
            Ok(record) => record,
            Err(_) => InstallChunkedCodeArgsLegacy::decode(blob)?.into(),
        };
        Ok(args)
    }
}

impl InstallChunkedCodeArgs {
    pub fn new(
        mode: CanisterInstallModeV2,
        target_canister: CanisterId,
        store_canister: Option<CanisterId>,
        chunk_hashes_list: Vec<Vec<u8>>,
        wasm_module_hash: Vec<u8>,
        arg: Vec<u8>,
    ) -> Self {
        Self {
            mode,
            target_canister: target_canister.into(),
            store_canister: store_canister.map(|p| p.into()),
            chunk_hashes_list: chunk_hashes_list
                .into_iter()
                .map(|hash| ChunkHash { hash })
                .collect(),
            wasm_module_hash,
            arg,
            sender_canister_version: None,
        }
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }

    pub fn target_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.target_canister)
    }

    pub fn store_canister_id(&self) -> Option<CanisterId> {
        self.store_canister
            .map(CanisterId::unchecked_from_principal)
    }
}

/// Struct used for encoding/decoding of legacy version of `InstallChunkedCodeArgs`,
/// it is used to preserve backward compatibility.
/// `(record {
///     mode : variant {
///         install;
///         reinstall;
///         upgrade: opt record {
///             skip_pre_upgrade: opt bool
///         }
///     };
///     target_canister_id: principal;
///     store_canister_id: opt principal;
///     chunk_hashes_list: vec blob;
///     wasm_module_hash: blob;
///     arg: blob;
///     sender_canister_version : opt nat64;
/// })`
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InstallChunkedCodeArgsLegacy {
    pub mode: CanisterInstallModeV2,
    pub target_canister: PrincipalId,
    pub store_canister: Option<PrincipalId>,
    pub chunk_hashes_list: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub wasm_module_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub sender_canister_version: Option<u64>,
}

impl From<InstallChunkedCodeArgsLegacy> for InstallChunkedCodeArgs {
    fn from(value: InstallChunkedCodeArgsLegacy) -> Self {
        Self {
            mode: value.mode,
            target_canister: value.target_canister,
            store_canister: value.store_canister,
            chunk_hashes_list: value
                .chunk_hashes_list
                .into_iter()
                .map(|hash| ChunkHash { hash })
                .collect(),
            wasm_module_hash: value.wasm_module_hash,
            arg: value.arg,
            sender_canister_version: value.sender_canister_version,
        }
    }
}

impl Payload<'_> for InstallChunkedCodeArgsLegacy {}

impl InstallChunkedCodeArgsLegacy {
    pub fn new(
        mode: CanisterInstallModeV2,
        target_canister: CanisterId,
        store_canister: Option<CanisterId>,
        chunk_hashes_list: Vec<Vec<u8>>,
        wasm_module_hash: Vec<u8>,
        arg: Vec<u8>,
    ) -> Self {
        Self {
            mode,
            target_canister: target_canister.into(),
            store_canister: store_canister.map(|p| p.into()),
            chunk_hashes_list,
            wasm_module_hash,
            arg,
            sender_canister_version: None,
        }
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
/// })`
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct ClearChunkStoreArgs {
    pub canister_id: PrincipalId,
}

impl Payload<'_> for ClearChunkStoreArgs {}

impl ClearChunkStoreArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
/// })`
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct StoredChunksArgs {
    pub canister_id: PrincipalId,
}

impl Payload<'_> for StoredChunksArgs {}

impl StoredChunksArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

/// Struct to be returned when listing chunks in the Wasm store
/// `(vec record { hash: blob })`
#[derive(PartialEq, Debug, CandidType, Deserialize)]
pub struct StoredChunksReply(pub Vec<ChunkHash>);

impl Payload<'_> for StoredChunksReply {}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
///     replace_snapshot: opt blob;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotArgs {
    pub canister_id: PrincipalId,
    pub replace_snapshot: Option<serde_bytes::ByteBuf>,
}

impl TakeCanisterSnapshotArgs {
    pub fn new(canister_id: CanisterId, replace_snapshot: Option<SnapshotId>) -> Self {
        Self {
            canister_id: canister_id.get(),
            replace_snapshot: replace_snapshot
                .map(|snapshot_id| ByteBuf::from(snapshot_id.to_vec())),
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn replace_snapshot(&self) -> Option<SnapshotId> {
        self.replace_snapshot
            .as_ref()
            .map(|bytes| SnapshotId::try_from(&bytes.clone().into_vec()).unwrap())
    }
}

impl<'a> Payload<'a> for TakeCanisterSnapshotArgs {
    fn decode(blob: &'a [u8]) -> Result<Self, UserError> {
        let args = Decode!([decoder_config()]; blob, Self).map_err(candid_error_to_user_error)?;

        match &args.replace_snapshot {
            Some(replace_snapshot) => {
                // Verify that snapshot ID has the correct format.
                if let Err(err) = SnapshotId::try_from(&replace_snapshot.clone().into_vec()) {
                    return Err(UserError::new(
                        ErrorCode::InvalidManagementPayload,
                        format!("Payload deserialization error: {err:?}"),
                    ));
                }
            }
            None => {}
        }
        Ok(args)
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
///     snapshot_id: blob;
///     sender_canister_version: opt nat64;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotArgs {
    canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    snapshot_id: Vec<u8>,
    sender_canister_version: Option<u64>,
}

impl LoadCanisterSnapshotArgs {
    pub fn new(
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        sender_canister_version: Option<u64>,
    ) -> Self {
        Self {
            canister_id: canister_id.get(),
            snapshot_id: snapshot_id.to_vec(),
            sender_canister_version,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        SnapshotId::try_from(&self.snapshot_id).unwrap()
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl<'a> Payload<'a> for LoadCanisterSnapshotArgs {
    fn decode(blob: &'a [u8]) -> Result<Self, UserError> {
        let args = Decode!([decoder_config()]; blob, Self).map_err(candid_error_to_user_error)?;
        // Verify that snapshot ID has the correct format.
        if let Err(err) = SnapshotId::try_from(&args.snapshot_id) {
            return Err(UserError::new(
                ErrorCode::InvalidManagementPayload,
                format!("Payload deserialization error: {err:?}"),
            ));
        }
        Ok(args)
    }
}

/// Struct to be returned when taking a canister snapshot.
/// `(record {
///      id: blob;
///      taken_at_timestamp: nat64;
///      total_size: nat64;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct CanisterSnapshotResponse {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub taken_at_timestamp: u64,
    pub total_size: u64,
}

impl Payload<'_> for CanisterSnapshotResponse {}

impl CanisterSnapshotResponse {
    pub fn new(snapshot_id: &SnapshotId, taken_at_timestamp: u64, total_size: NumBytes) -> Self {
        Self {
            id: snapshot_id.to_vec(),
            taken_at_timestamp,
            total_size: total_size.get(),
        }
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        SnapshotId::try_from(&self.id).unwrap()
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn taken_at_timestamp(&self) -> u64 {
        self.taken_at_timestamp
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
///     snapshot_id: blob;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct DeleteCanisterSnapshotArgs {
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub snapshot_id: Vec<u8>,
}

impl DeleteCanisterSnapshotArgs {
    pub fn new(canister_id: CanisterId, snapshot_id: SnapshotId) -> Self {
        Self {
            canister_id: canister_id.get(),
            snapshot_id: snapshot_id.to_vec(),
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_snapshot_id(&self) -> SnapshotId {
        SnapshotId::try_from(&self.snapshot_id).unwrap()
    }
}

impl<'a> Payload<'a> for DeleteCanisterSnapshotArgs {
    fn decode(blob: &'a [u8]) -> Result<Self, UserError> {
        let args = Decode!([decoder_config()]; blob, Self).map_err(candid_error_to_user_error)?;

        // Verify that snapshot ID has the correct format.
        if let Err(err) = SnapshotId::try_from(&args.snapshot_id) {
            return Err(UserError::new(
                ErrorCode::InvalidManagementPayload,
                format!("Payload deserialization error: {err:?}"),
            ));
        }
        Ok(args)
    }
}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id: principal;
/// })`
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct ListCanisterSnapshotArgs {
    canister_id: PrincipalId,
}

impl ListCanisterSnapshotArgs {
    pub fn new(canister_id: CanisterId) -> Self {
        Self {
            canister_id: canister_id.get(),
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

impl Payload<'_> for ListCanisterSnapshotArgs {}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn canister_install_mode_round_trip() {
        fn canister_install_mode_round_trip_aux(mode: CanisterInstallMode) {
            let pb_mode = CanisterInstallModeProto::from(&mode);
            let dec_mode = CanisterInstallMode::try_from(pb_mode).unwrap();
            assert_eq!(mode, dec_mode);
        }

        canister_install_mode_round_trip_aux(CanisterInstallMode::Install);
        canister_install_mode_round_trip_aux(CanisterInstallMode::Reinstall);
        canister_install_mode_round_trip_aux(CanisterInstallMode::Upgrade);
    }

    #[test]
    fn compatibility_for_canister_install_mode() {
        // If this fails, you are making a potentially incompatible change to `CanisterInstallMode`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            CanisterInstallMode::iter()
                .map(|x| x as i32)
                .collect::<Vec<i32>>(),
            [1, 2, 3]
        );
    }

    #[test]
    fn wasm_persistence_round_trip() {
        for persistence in WasmMemoryPersistence::iter() {
            let encoded: WasmMemoryPersistenceProto = persistence.into();
            let decoded = WasmMemoryPersistence::try_from(encoded).unwrap();
            assert_eq!(*persistence, decoded);
        }

        WasmMemoryPersistence::try_from(WasmMemoryPersistenceProto::Unspecified).unwrap_err();
    }

    #[test]
    fn canister_install_mode_v2_round_trip() {
        for mode in CanisterInstallModeV2::iter() {
            let encoded: CanisterInstallModeV2Proto = mode.into();
            let decoded = CanisterInstallModeV2::try_from(encoded).unwrap();
            assert_eq!(*mode, decoded);
        }
    }

    #[test]
    fn verify_max_bounded_controllers_length() {
        const TEST_START: usize = 5;
        const THRESHOLD: usize = 10;
        const TEST_END: usize = 15;
        for i in TEST_START..=TEST_END {
            // Arrange.
            let controllers = BoundedControllers::new(vec![PrincipalId::new_anonymous(); i]);

            // Act.
            let result = BoundedControllers::decode(&controllers.encode());

            // Assert.
            if i <= THRESHOLD {
                // Verify decoding without errors for allowed sizes.
                assert_eq!(result.unwrap(), controllers);
            } else {
                // Verify decoding with errors for disallowed sizes.
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
                assert!(
                    error.description().contains(&format!(
                        "Deserialize error: The number of elements exceeds maximum allowed {}",
                        MAX_ALLOWED_CONTROLLERS_COUNT
                    )),
                    "Actual: {}",
                    error.description()
                );
            }
        }
    }

    #[test]
    fn test_create_canister_args_decode_empty_blob() {
        // This test is added for backward compatibility to allow decoding an empty blob.
        let encoded = EmptyBlob {}.encode();
        let result = CreateCanisterArgs::decode(&encoded);
        assert_eq!(result, Ok(CreateCanisterArgs::default()));
    }

    #[test]
    fn test_create_canister_args_decode_controllers_count() {
        const TEST_START: usize = 5;
        const THRESHOLD: usize = 10;
        const TEST_END: usize = 15;
        for i in TEST_START..=TEST_END {
            // Arrange.
            let args = CreateCanisterArgs {
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![PrincipalId::new_anonymous(); i])
                        .build(),
                ),
                sender_canister_version: None,
            };

            // Act.
            let result = CreateCanisterArgs::decode(&args.encode());

            // Assert.
            if i <= THRESHOLD {
                // Assert decoding without errors for allowed sizes.
                assert_eq!(result.unwrap(), args);
            } else {
                // Assert decoding with errors for disallowed sizes.
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
                assert!(
                    error
                        .description()
                        .contains("The number of elements exceeds maximum allowed "),
                    "Actual: {}",
                    error.description()
                );
            }
        }
    }

    #[test]
    fn ecdsa_curve_round_trip() {
        for curve in EcdsaCurve::iter() {
            assert_eq!(format!("{}", curve).parse::<EcdsaCurve>().unwrap(), curve);
        }
    }

    #[test]
    fn ecdsa_key_id_round_trip() {
        for curve in EcdsaCurve::iter() {
            for name in ["secp256k1", "", "other_key", "other key", "other:key"] {
                let key = EcdsaKeyId {
                    curve,
                    name: name.to_string(),
                };
                assert_eq!(format!("{}", key).parse::<EcdsaKeyId>().unwrap(), key);
            }
        }
    }

    #[test]
    fn schnorr_algorithm_round_trip() {
        for algorithm in SchnorrAlgorithm::iter() {
            assert_eq!(
                format!("{}", algorithm)
                    .parse::<SchnorrAlgorithm>()
                    .unwrap(),
                algorithm
            );
        }
    }

    #[test]
    fn schnorr_key_id_round_trip() {
        for algorithm in SchnorrAlgorithm::iter() {
            for name in ["Ed25519", "", "other_key", "other key", "other:key"] {
                let key = SchnorrKeyId {
                    algorithm,
                    name: name.to_string(),
                };
                assert_eq!(format!("{}", key).parse::<SchnorrKeyId>().unwrap(), key);
            }
        }
    }

    #[test]
    fn master_public_key_id_round_trip() {
        for algorithm in SchnorrAlgorithm::iter() {
            for name in ["Ed25519", "", "other_key", "other key", "other:key"] {
                let key = MasterPublicKeyId::Schnorr(SchnorrKeyId {
                    algorithm,
                    name: name.to_string(),
                });
                assert_eq!(
                    format!("{}", key).parse::<MasterPublicKeyId>().unwrap(),
                    key
                );
            }
        }

        for curve in EcdsaCurve::iter() {
            for name in ["secp256k1", "", "other_key", "other key", "other:key"] {
                let key = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve,
                    name: name.to_string(),
                });
                assert_eq!(
                    format!("{}", key).parse::<MasterPublicKeyId>().unwrap(),
                    key
                );
            }
        }
    }

    #[test]
    fn verify_max_derivation_path_length() {
        for i in 0..=MAXIMUM_DERIVATION_PATH_LENGTH {
            let path = DerivationPath::new(vec![ByteBuf::from(vec![0_u8, 32]); i]);
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
            let path = DerivationPath::new(vec![ByteBuf::from(vec![0_u8, 32]); i]);
            let encoded = path.encode();
            let result = DerivationPath::decode(&encoded).unwrap_err();
            assert_eq!(result.code(), ErrorCode::InvalidManagementPayload);
            assert!(
                result.description().contains(&format!(
                    "Deserialize error: The number of elements exceeds maximum allowed {}",
                    MAXIMUM_DERIVATION_PATH_LENGTH
                )),
                "Actual: {}",
                result.description()
            );

            let sign_with_ecdsa = SignWithECDSAArgs {
                message_hash: [1; 32],
                derivation_path: path.clone(),
                key_id: EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "test".to_string(),
                },
            };

            let encoded = sign_with_ecdsa.encode();
            let result = SignWithECDSAArgs::decode(&encoded).unwrap_err();
            assert_eq!(result.code(), ErrorCode::InvalidManagementPayload);
            assert!(
                result.description().contains(&format!(
                    "Deserialize error: The number of elements exceeds maximum allowed {}",
                    MAXIMUM_DERIVATION_PATH_LENGTH
                )),
                "Actual: {}",
                result.description()
            );

            let ecsda_public_key = ECDSAPublicKeyArgs {
                canister_id: None,
                derivation_path: path,
                key_id: EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "test".to_string(),
                },
            };

            let encoded = ecsda_public_key.encode();
            let result = ECDSAPublicKeyArgs::decode(&encoded).unwrap_err();
            assert_eq!(result.code(), ErrorCode::InvalidManagementPayload);
            assert!(
                result.description().contains(&format!(
                    "Deserialize error: The number of elements exceeds maximum allowed {}",
                    MAXIMUM_DERIVATION_PATH_LENGTH
                )),
                "Actual: {}",
                result.description()
            );
        }
    }
}
