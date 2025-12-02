//! Data types used for encoding/decoding the Candid payloads of ic:00.
mod bounded_vec;
mod data_size;
mod http;
mod provisional;

#[cfg(feature = "fuzzing_code")]
use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
pub use bounded_vec::*;
use candid::{CandidType, Decode, DecoderConfig, Deserialize, Encode, Reserved};
pub use data_size::*;
pub use http::{
    ALLOWED_HTTP_OUTCALLS_PRICING_VERSIONS, BoundedHttpHeaders, CanisterHttpRequestArgs,
    CanisterHttpResponsePayload, DEFAULT_HTTP_OUTCALLS_PRICING_VERSION, HttpHeader, HttpMethod,
    PRICING_VERSION_LEGACY, PRICING_VERSION_PAY_AS_YOU_GO, TransformArgs, TransformContext,
    TransformFunc,
};
use ic_base_types::{
    CanisterId, EnvironmentVariables, NodeId, NumBytes, PrincipalId, RegistryVersion, SnapshotId,
    SubnetId,
};
use ic_error_types::{ErrorCode, UserError};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::proxy::{try_decode_hash, try_from_option_field};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::subnet::v1::{InitialIDkgDealings, InitialNiDkgTranscriptRecord};
use ic_protobuf::state::canister_state_bits::v1 as pb_canister_state_bits;
use ic_protobuf::types::v1 as pb_types;
use ic_protobuf::types::v1::CanisterInstallModeV2 as CanisterInstallModeV2Proto;
use ic_protobuf::types::v1::{
    CanisterInstallMode as CanisterInstallModeProto,
    CanisterUpgradeOptions as CanisterUpgradeOptionsProto,
    WasmMemoryPersistence as WasmMemoryPersistenceProto,
};
use std::hash::{Hash, Hasher};

use num_traits::cast::ToPrimitive;
pub use provisional::{ProvisionalCreateCanisterWithCyclesArgs, ProvisionalTopUpCanisterArgs};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::mem::size_of;
use std::{collections::BTreeSet, convert::TryFrom, error::Error, fmt, slice::Iter, str::FromStr};
use strum_macros::{Display, EnumCount, EnumIter, EnumString};

/// The id of the management canister.
pub const IC_00: CanisterId = CanisterId::ic_00();
pub const MAX_CONTROLLERS: usize = 10;
pub const HASH_LENGTH: usize = 32;
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
    CanisterMetadata,
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
    ReshareChainKey,

    // Schnorr interface.
    SchnorrPublicKey,
    SignWithSchnorr,

    // VetKd interface.
    #[strum(serialize = "vetkd_public_key")]
    VetKdPublicKey,
    #[strum(serialize = "vetkd_derive_key")]
    VetKdDeriveKey,

    // Bitcoin Interface.
    BitcoinGetBalance,
    BitcoinGetUtxos,
    BitcoinGetBlockHeaders,
    BitcoinSendTransaction,
    BitcoinGetCurrentFeePercentiles,
    // Private APIs used exclusively by the bitcoin canisters.
    BitcoinSendTransactionInternal, // API for sending transactions to the network.
    BitcoinGetSuccessors,           // API for fetching blocks from the network.

    // Subnet information
    NodeMetricsHistory,
    SubnetInfo,

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

    // Support for import and export of canister snapshots
    ReadCanisterSnapshotMetadata,
    ReadCanisterSnapshotData,
    UploadCanisterSnapshotMetadata,
    UploadCanisterSnapshotData,

    // Support for canister migration
    RenameCanister,
}

fn candid_error_to_user_error(err: candid::Error) -> UserError {
    UserError::new(
        ErrorCode::InvalidManagementPayload,
        format!("Error decoding candid: {err:#}"),
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

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
/// }
/// ```
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
///   environment_variables_hash : opt blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterCreationRecord {
    controllers: Vec<PrincipalId>,
    environment_variables_hash: Option<[u8; HASH_LENGTH]>,
}

impl CanisterCreationRecord {
    pub fn controllers(&self) -> &[PrincipalId] {
        &self.controllers
    }

    pub fn environment_variables_hash(&self) -> Option<[u8; HASH_LENGTH]> {
        self.environment_variables_hash
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
    module_hash: [u8; HASH_LENGTH],
}

impl CanisterCodeDeploymentRecord {
    pub fn mode(&self) -> CanisterInstallMode {
        self.mode
    }
    pub fn module_hash(&self) -> [u8; HASH_LENGTH] {
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
///    source : variant {
///         taken_from_canister : reserved;
///         metadata_upload : reserved;
///    };
///    from_canister_id : opt principal;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterLoadSnapshotRecord {
    canister_version: u64,
    snapshot_id: SnapshotId,
    taken_at_timestamp: u64,
    source: SnapshotSource,
    from_canister_id: Option<CanisterId>,
}

impl CanisterLoadSnapshotRecord {
    pub fn new(
        canister_version: u64,
        snapshot_id: SnapshotId,
        taken_at_timestamp: u64,
        source: SnapshotSource,
        from_canister_id: Option<CanisterId>,
    ) -> Self {
        Self {
            canister_version,
            snapshot_id,
            taken_at_timestamp,
            source,
            from_canister_id,
        }
    }

    pub fn canister_version(&self) -> u64 {
        self.canister_version
    }

    pub fn taken_at_timestamp(&self) -> u64 {
        self.taken_at_timestamp
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    pub fn source(&self) -> SnapshotSource {
        self.source
    }

    pub fn from_canister_id(&self) -> Option<CanisterId> {
        self.from_canister_id
    }
}

/// `CandidType` for `CanisterSettingsChangeRecord`
/// ``` text
/// record {
///   controllers : opt vec principal;
///   environment_variables_hash : opt blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterSettingsChangeRecord {
    controllers: Option<Vec<PrincipalId>>,
    environment_variables_hash: Option<[u8; HASH_LENGTH]>,
}

impl CanisterSettingsChangeRecord {
    pub fn controllers(&self) -> Option<&[PrincipalId]> {
        self.controllers.as_deref()
    }

    pub fn environment_variables_hash(&self) -> Option<[u8; HASH_LENGTH]> {
        self.environment_variables_hash
    }
}

/// `CandidType` for `CanisterRenameRecord`
/// ```text
/// record {
///    canister_id : principal;
///    total_num_changes : nat64;
///    rename_to : record {
///        canister_id : principal;
///        version : nat64;
///        total_num_changes : nat64;
///    };
///    requested_by : principal;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterRenameRecord {
    canister_id: PrincipalId,
    total_num_changes: u64,
    rename_to: RenameToRecord,
    requested_by: PrincipalId,
}

impl CanisterRenameRecord {
    pub fn canister_id(&self) -> PrincipalId {
        self.canister_id
    }

    pub fn total_num_changes(&self) -> u64 {
        self.total_num_changes
    }

    pub fn rename_to(&self) -> &RenameToRecord {
        &self.rename_to
    }

    pub fn requested_by(&self) -> PrincipalId {
        self.requested_by
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RenameToRecord {
    canister_id: PrincipalId,
    version: u64,
    total_num_changes: u64,
}

impl RenameToRecord {
    pub fn canister_id(&self) -> PrincipalId {
        self.canister_id
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn total_num_changes(&self) -> u64 {
        self.total_num_changes
    }
}

/// `CandidType` for `CanisterChangeDetails`
/// ```text
/// variant {
///   creation : record {
///     controllers : vec principal;
///     environment_variables_hash : opt blob;
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
///     canister_version : nat64;
///     snapshot_id : blob;
///     taken_at_timestamp : nat64;
///     source : variant {
///       taken_from_canister : reserved;
///       metadata_upload : reserved;
///     };
///     from_canister_id : opt principal;
///   };
///   settings_change : record {
///     controllers : opt vec principal;
///     environment_variables_hash : opt blob;
///   };
///   rename_canister : record {
///     canister_id : principal;
///     total_num_changes : nat64;
///     rename_to : record {
///       canister_id : principal;
///       version : nat64;
///       total_num_changes : nat64;
///     };
///     requested_by : principal;
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
    #[serde(rename = "settings_change")]
    CanisterSettingsChange(CanisterSettingsChangeRecord),
    #[serde(rename = "rename_canister")]
    CanisterRename(CanisterRenameRecord),
}

impl CanisterChangeDetails {
    pub fn canister_creation(
        controllers: Vec<PrincipalId>,
        environment_variables_hash: Option<[u8; HASH_LENGTH]>,
    ) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterCreation(CanisterCreationRecord {
            controllers,
            environment_variables_hash,
        })
    }

    pub fn code_deployment(
        mode: CanisterInstallMode,
        module_hash: [u8; HASH_LENGTH],
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
        snapshot_id: SnapshotId,
        taken_at_timestamp: u64,
        source: SnapshotSource,
        from_canister_id: Option<CanisterId>,
    ) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterLoadSnapshot(CanisterLoadSnapshotRecord {
            canister_version,
            snapshot_id,
            taken_at_timestamp,
            source,
            from_canister_id,
        })
    }

    pub fn settings_change(
        controllers: Option<Vec<PrincipalId>>,
        environment_variables_hash: Option<[u8; HASH_LENGTH]>,
    ) -> CanisterChangeDetails {
        CanisterChangeDetails::CanisterSettingsChange(CanisterSettingsChangeRecord {
            controllers,
            environment_variables_hash,
        })
    }

    pub fn rename_canister(
        canister_id: PrincipalId,
        total_num_changes: u64,
        to_canister_id: PrincipalId,
        to_version: u64,
        to_total_num_changes: u64,
        requested_by: PrincipalId,
    ) -> CanisterChangeDetails {
        let rename_to = RenameToRecord {
            canister_id: to_canister_id,
            version: to_version,
            total_num_changes: to_total_num_changes,
        };
        let record = CanisterRenameRecord {
            canister_id,
            total_num_changes,
            rename_to,
            requested_by,
        };
        CanisterChangeDetails::CanisterRename(record)
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
    /// The vector of controllers in `CanisterCreation`, `CanisterControllersChange`
    /// and `CanisterSettingsChange` is counted separately because
    /// the controllers are stored on heap and thus not accounted
    /// for in `size_of::<CanisterChange>()`.
    pub fn count_bytes(&self) -> NumBytes {
        let num_controllers = match &self.details {
            CanisterChangeDetails::CanisterCreation(canister_creation) => {
                canister_creation.controllers().len()
            }
            CanisterChangeDetails::CanisterControllersChange(canister_controllers_change) => {
                canister_controllers_change.controllers().len()
            }
            CanisterChangeDetails::CanisterSettingsChange(canister_settings_change) => {
                canister_settings_change
                    .controllers()
                    .map(|controllers| controllers.len())
                    .unwrap_or_default()
            }
            CanisterChangeDetails::CanisterCodeDeployment(_)
            | CanisterChangeDetails::CanisterCodeUninstall
            | CanisterChangeDetails::CanisterLoadSnapshot(_)
            | CanisterChangeDetails::CanisterRename(_) => 0,
        };
        NumBytes::from(
            (size_of::<CanisterChange>() + num_controllers * size_of::<PrincipalId>()) as u64,
        )
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

/// `CandidType` for `CanisterMetadataRequest`
/// ```text
/// record {
///   canister_id : principal;
///   name : text;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterMetadataRequest {
    canister_id: PrincipalId,
    name: String,
}

impl CanisterMetadataRequest {
    pub fn new(canister_id: CanisterId, name: String) -> CanisterMetadataRequest {
        CanisterMetadataRequest {
            canister_id: canister_id.into(),
            name,
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Payload<'_> for CanisterMetadataRequest {}

/// `CandidType` for `CanisterMetadataResponse`
/// ```text
/// record {
///   value : blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterMetadataResponse {
    #[serde(with = "serde_bytes")]
    value: Vec<u8>,
}

impl CanisterMetadataResponse {
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Payload<'_> for CanisterMetadataResponse {}

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
                        environment_variables_hash: canister_creation
                            .environment_variables_hash
                            .map(|hash| hash.to_vec()),
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
                        snapshot_id: canister_load_snapshot.snapshot_id.to_vec(),
                        taken_at_timestamp: canister_load_snapshot.taken_at_timestamp,
                        source: pb_canister_state_bits::SnapshotSource::from(
                            canister_load_snapshot.source,
                        )
                        .into(),
                        from_canister_id: canister_load_snapshot
                            .from_canister_id
                            .map(|x| x.get().into()),
                    },
                )
            }
            CanisterChangeDetails::CanisterSettingsChange(canister_settings_change) => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterSettingsChange(
                    pb_canister_state_bits::CanisterSettingsChange {
                        controllers: canister_settings_change.controllers.as_ref().map(
                            |controllers| pb_canister_state_bits::CanisterControllers {
                                controllers: controllers
                                    .iter()
                                    .map(|c| (*c).into())
                                    .collect::<Vec<ic_protobuf::types::v1::PrincipalId>>(),
                            },
                        ),
                        environment_variables_hash: canister_settings_change
                            .environment_variables_hash
                            .map(|hash| hash.to_vec()),
                    },
                )
            }
            CanisterChangeDetails::CanisterRename(canister_rename) => {
                pb_canister_state_bits::canister_change::ChangeDetails::CanisterRename(
                    pb_canister_state_bits::CanisterRename {
                        canister_id: Some(canister_rename.canister_id.into()),
                        total_num_changes: canister_rename.total_num_changes,
                        rename_to: Some(pb_canister_state_bits::RenameTo {
                            canister_id: Some(canister_rename.rename_to.canister_id.into()),
                            version: canister_rename.rename_to.version,
                            total_num_changes: canister_rename.rename_to.total_num_changes,
                        }),
                        requested_by: Some(canister_rename.requested_by.into()),
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
            ) => {
                let environment_variables_hash = match canister_creation.environment_variables_hash
                {
                    Some(bytes) => Some(try_decode_hash(bytes)?),
                    None => None,
                };
                Ok(CanisterChangeDetails::canister_creation(
                    canister_creation
                        .controllers
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<PrincipalId>, _>>()?,
                    environment_variables_hash,
                ))
            }
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
            ) => {
                let snapshot_id = SnapshotId::try_from(canister_load_snapshot.snapshot_id)
                    .map_err(|e| {
                        ProxyDecodeError::Other(format!("Failed to decode snapshot_id: {e:?}"))
                    })?;

                let source = SnapshotSource::try_from(
                    pb_canister_state_bits::SnapshotSource::try_from(canister_load_snapshot.source)
                        .map_err(|e| {
                            ProxyDecodeError::Other(format!(
                                "Failed to decode snapshot source: {e:?}"
                            ))
                        })?,
                )?;

                let from_canister_id = match canister_load_snapshot.from_canister_id {
                    Some(id) => Some(CanisterId::unchecked_from_principal(id.try_into()?)),
                    None => None,
                };

                Ok(CanisterChangeDetails::load_snapshot(
                    canister_load_snapshot.canister_version,
                    snapshot_id,
                    canister_load_snapshot.taken_at_timestamp,
                    source,
                    from_canister_id,
                ))
            }
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterSettingsChange(
                canister_settings_change,
            ) => {
                let controllers = match canister_settings_change.controllers {
                    None => None,
                    Some(canister_controllers) => Some(
                        canister_controllers
                            .controllers
                            .into_iter()
                            .map(TryInto::try_into)
                            .collect::<Result<Vec<PrincipalId>, _>>()?,
                    ),
                };
                let environment_variables_hash =
                    match canister_settings_change.environment_variables_hash {
                        Some(bytes) => Some(try_decode_hash(bytes)?),
                        None => None,
                    };
                Ok(CanisterChangeDetails::settings_change(
                    controllers,
                    environment_variables_hash,
                ))
            }
            pb_canister_state_bits::canister_change::ChangeDetails::CanisterRename(
                canister_rename,
            ) => {
                let rename_to = canister_rename
                    .rename_to
                    .ok_or(ProxyDecodeError::MissingField("CanisterRename::rename_to"))?;
                // The only principal who could request canister renaming before
                // that principal started to be recorded in canister history
                // is the following principal allowlisted in the NNS proposal 139083:
                // https://dashboard.internetcomputer.org/proposal/139083
                let default_requested_by = PrincipalId::from_str(
                    "axa43-ya3vf-zi3lb-xbffp-vdsi5-alaja-wujmj-qg26n-pugel-72qro-iae",
                )
                .unwrap();
                let requested_by = if let Some(requested_by) = canister_rename.requested_by {
                    requested_by.try_into()?
                } else {
                    default_requested_by
                };
                Ok(CanisterChangeDetails::rename_canister(
                    canister_rename
                        .canister_id
                        .as_ref()
                        .ok_or(ProxyDecodeError::MissingField(
                            "CanisterRename::canister_id",
                        ))?
                        .to_owned()
                        .try_into()?,
                    canister_rename.total_num_changes,
                    rename_to
                        .canister_id
                        .as_ref()
                        .ok_or(ProxyDecodeError::MissingField("RenameTo::canister_id"))?
                        .to_owned()
                        .try_into()?,
                    rename_to.version,
                    rename_to.total_num_changes,
                    requested_by,
                ))
            }
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
/// ```text
/// record {
///   canister_id : principal;
///   sender_canister_version : opt nat64;
/// }
/// ```
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
///    allowed_viewers : vec principal;
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
        match item {
            LogVisibilityV2::Controllers => pb_canister_state_bits::LogVisibilityV2 {
                log_visibility_v2: Some(
                    pb_canister_state_bits::log_visibility_v2::LogVisibilityV2::Controllers(1),
                ),
            },
            LogVisibilityV2::Public => pb_canister_state_bits::LogVisibilityV2 {
                log_visibility_v2: Some(
                    pb_canister_state_bits::log_visibility_v2::LogVisibilityV2::Public(2),
                ),
            },
            LogVisibilityV2::AllowedViewers(principals) => {
                pb_canister_state_bits::LogVisibilityV2 {
                    log_visibility_v2: Some(
                        pb_canister_state_bits::log_visibility_v2::LogVisibilityV2::AllowedViewers(
                            pb_canister_state_bits::LogVisibilityAllowedViewers {
                                principals: principals
                                    .get()
                                    .iter()
                                    .map(|c| (*c).into())
                                    .collect::<Vec<ic_protobuf::types::v1::PrincipalId>>()
                                    .clone(),
                            },
                        ),
                    ),
                }
            }
        }
    }
}

impl TryFrom<pb_canister_state_bits::LogVisibilityV2> for LogVisibilityV2 {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_canister_state_bits::LogVisibilityV2) -> Result<Self, Self::Error> {
        let Some(log_visibility_v2) = item.log_visibility_v2 else {
            return Err(ProxyDecodeError::MissingField(
                "LogVisibilityV2::log_visibility_v2",
            ));
        };
        match log_visibility_v2 {
            pb_canister_state_bits::log_visibility_v2::LogVisibilityV2::Controllers(_) => {
                Ok(Self::Controllers)
            }
            pb_canister_state_bits::log_visibility_v2::LogVisibilityV2::Public(_) => {
                Ok(Self::Public)
            }
            pb_canister_state_bits::log_visibility_v2::LogVisibilityV2::AllowedViewers(data) => {
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
/// ```text
/// record {
///   controller : principal;
///   controllers : vec principal;
///   compute_allocation : nat;
///   memory_allocation : nat;
///   freezing_threshold : nat;
///   reserved_cycles_limit : nat;
///   log_visibility : log_visibility;
///   log_memory_limit : nat;
///   wasm_memory_limit : nat;
///   wasm_memory_threshold : nat;
///   environment_variables : vec environment_variable;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct DefiniteCanisterSettingsArgs {
    controller: PrincipalId,
    controllers: Vec<PrincipalId>,
    compute_allocation: candid::Nat,
    memory_allocation: candid::Nat,
    freezing_threshold: candid::Nat,
    reserved_cycles_limit: candid::Nat,
    log_visibility: LogVisibilityV2,
    log_memory_limit: candid::Nat,
    wasm_memory_limit: candid::Nat,
    wasm_memory_threshold: candid::Nat,
    environment_variables: Vec<EnvironmentVariable>,
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
        log_memory_limit: u64,
        wasm_memory_limit: Option<u64>,
        wasm_memory_threshold: u64,
        environment_variables: EnvironmentVariables,
    ) -> Self {
        let memory_allocation = candid::Nat::from(memory_allocation.unwrap_or(0));
        let reserved_cycles_limit = candid::Nat::from(reserved_cycles_limit.unwrap_or(0));
        let wasm_memory_limit = candid::Nat::from(wasm_memory_limit.unwrap_or(0));
        let environment_variables = environment_variables
            .iter()
            .map(|(name, value)| EnvironmentVariable {
                name: name.clone(),
                value: value.clone(),
            })
            .collect::<Vec<EnvironmentVariable>>();
        Self {
            controller,
            controllers,
            compute_allocation: candid::Nat::from(compute_allocation),
            memory_allocation,
            freezing_threshold: candid::Nat::from(freezing_threshold),
            reserved_cycles_limit,
            log_visibility,
            log_memory_limit: candid::Nat::from(log_memory_limit),
            wasm_memory_limit,
            wasm_memory_threshold: candid::Nat::from(wasm_memory_threshold),
            environment_variables,
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

    pub fn log_memory_limit(&self) -> candid::Nat {
        self.log_memory_limit.clone()
    }

    pub fn wasm_memory_limit(&self) -> candid::Nat {
        self.wasm_memory_limit.clone()
    }

    pub fn wasm_memory_threshold(&self) -> candid::Nat {
        self.wasm_memory_threshold.clone()
    }

    pub fn compute_allocation(&self) -> candid::Nat {
        self.compute_allocation.clone()
    }

    pub fn memory_allocation(&self) -> candid::Nat {
        self.memory_allocation.clone()
    }

    pub fn freezing_threshold(&self) -> candid::Nat {
        self.freezing_threshold.clone()
    }

    pub fn environment_variables(&self) -> &[EnvironmentVariable] {
        &self.environment_variables
    }
}

impl Payload<'_> for DefiniteCanisterSettingsArgs {}

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct QueryStats {
    num_calls_total: candid::Nat,
    num_instructions_total: candid::Nat,
    request_payload_bytes_total: candid::Nat,
    response_payload_bytes_total: candid::Nat,
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   status : variant { running; stopping; stopped };
///   ready_for_migration : bool;
///   version : nat64;
///   settings : definite_canister_settings;
///   module_hash : opt blob;
///   controller : principal;
///   memory_size : nat;
///   memory_metrics : record {
///     wasm_memory_size : nat;
///     stable_memory_size : nat;
///     global_memory_size : nat;
///     wasm_binary_size : nat;
///     custom_sections_size : nat;
///     canister_history_size : nat;
///     wasm_chunk_store_size : nat;
///     snapshots_size : nat;
///   };
///   cycles : nat;
///   balance : vec record { blob; nat };
///   freezing_threshold : nat;
///   idle_cycles_burned_per_day : nat;
///   reserved_cycles : nat;
///   query_stats : record {
///     num_calls : nat;
///     num_instructions : nat;
///     ingress_payload_size : nat;
///     egress_payload_size : nat;
///   };
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterStatusResultV2 {
    status: CanisterStatusType,
    ready_for_migration: bool,
    version: u64,
    module_hash: Option<Vec<u8>>,
    controller: candid::Principal,
    settings: DefiniteCanisterSettingsArgs,
    memory_size: candid::Nat,
    memory_metrics: MemoryMetrics,
    cycles: candid::Nat,
    // this is for compat with Spec 0.12/0.13
    balance: Vec<(Vec<u8>, candid::Nat)>,
    freezing_threshold: candid::Nat,
    idle_cycles_burned_per_day: candid::Nat,
    reserved_cycles: candid::Nat,
    query_stats: QueryStats,
}

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct MemoryMetrics {
    wasm_memory_size: candid::Nat,
    stable_memory_size: candid::Nat,
    global_memory_size: candid::Nat,
    wasm_binary_size: candid::Nat,
    custom_sections_size: candid::Nat,
    canister_history_size: candid::Nat,
    wasm_chunk_store_size: candid::Nat,
    snapshots_size: candid::Nat,
}

impl CanisterStatusResultV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: CanisterStatusType,
        ready_for_migration: bool,
        version: u64,
        module_hash: Option<Vec<u8>>,
        controller: PrincipalId,
        controllers: Vec<PrincipalId>,
        memory_size: NumBytes,
        wasm_memory_size: NumBytes,
        stable_memory_size: NumBytes,
        global_memory_size: NumBytes,
        wasm_binary_size: NumBytes,
        custom_sections_size: NumBytes,
        canister_history_size: NumBytes,
        wasm_chunk_store_size: NumBytes,
        snapshots_size: NumBytes,
        cycles: u128,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
        reserved_cycles_limit: Option<u128>,
        log_visibility: LogVisibilityV2,
        log_memory_limit: u64,
        idle_cycles_burned_per_day: u128,
        reserved_cycles: u128,
        query_num_calls: u128,
        query_num_instructions: u128,
        query_ingress_payload_size: u128,
        query_egress_payload_size: u128,
        wasm_memory_limit: Option<u64>,
        wasm_memory_threshold: u64,
        environment_variables: EnvironmentVariables,
    ) -> Self {
        Self {
            status,
            ready_for_migration,
            version,
            module_hash,
            controller: candid::Principal::from_text(controller.to_string()).unwrap(),
            memory_size: candid::Nat::from(memory_size.get()),
            memory_metrics: MemoryMetrics {
                wasm_memory_size: candid::Nat::from(wasm_memory_size.get()),
                stable_memory_size: candid::Nat::from(stable_memory_size.get()),
                global_memory_size: candid::Nat::from(global_memory_size.get()),
                wasm_binary_size: candid::Nat::from(wasm_binary_size.get()),
                custom_sections_size: candid::Nat::from(custom_sections_size.get()),
                canister_history_size: candid::Nat::from(canister_history_size.get()),
                wasm_chunk_store_size: candid::Nat::from(wasm_chunk_store_size.get()),
                snapshots_size: candid::Nat::from(snapshots_size.get()),
            },
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
                log_memory_limit,
                wasm_memory_limit,
                wasm_memory_threshold,
                environment_variables,
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

    pub fn ready_for_migration(&self) -> bool {
        self.ready_for_migration
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Helper to facilitate comparing canister settings that differ only in the canister version.
    pub fn ignore_version(self) -> Self {
        Self { version: 0, ..self }
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

    pub fn wasm_memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_metrics.wasm_memory_size.0.to_u64().unwrap())
    }

    pub fn stable_memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_metrics.stable_memory_size.0.to_u64().unwrap())
    }

    pub fn global_memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_metrics.global_memory_size.0.to_u64().unwrap())
    }

    pub fn wasm_binary_size(&self) -> NumBytes {
        NumBytes::from(self.memory_metrics.wasm_binary_size.0.to_u64().unwrap())
    }

    pub fn custom_sections_size(&self) -> NumBytes {
        NumBytes::from(self.memory_metrics.custom_sections_size.0.to_u64().unwrap())
    }

    pub fn canister_history_size(&self) -> NumBytes {
        NumBytes::from(
            self.memory_metrics
                .canister_history_size
                .0
                .to_u64()
                .unwrap(),
        )
    }

    pub fn wasm_chunk_store_size(&self) -> NumBytes {
        NumBytes::from(
            self.memory_metrics
                .wasm_chunk_store_size
                .0
                .to_u64()
                .unwrap(),
        )
    }

    pub fn snapshots_size(&self) -> NumBytes {
        NumBytes::from(self.memory_metrics.snapshots_size.0.to_u64().unwrap())
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

    pub fn environment_variables(&self) -> &[EnvironmentVariable] {
        &self.settings.environment_variables
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
    #[serde(rename = "keep")]
    Keep,
    /// Reinitialize the main memory on upgrade.
    /// Default behavior without enhanced orthogonal persistence.
    #[serde(rename = "replace")]
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
/// Struct used for encoding/decoding
/// ```text
/// record {
///   skip_pre_upgrade : opt bool;
///   wasm_memory_persistence : opt variant {
///     keep;
///     replace;
///   };
/// }
/// ```
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
            CanisterInstallModeV2::Install => Self::Install,
            CanisterInstallModeV2::Reinstall => Self::Reinstall,
            CanisterInstallModeV2::Upgrade(_) => Self::Upgrade,
        }
    }
}

impl From<CanisterInstallMode> for CanisterInstallModeV2 {
    fn from(item: CanisterInstallMode) -> Self {
        match item {
            CanisterInstallMode::Install => Self::Install,
            CanisterInstallMode::Reinstall => Self::Reinstall,
            CanisterInstallMode::Upgrade => Self::Upgrade(None),
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
/// ```text
/// record {
///   mode : variant { install; reinstall; upgrade };
///   canister_id : principal;
///   wasm_module : blob;
///   arg : blob;
///   sender_canister_version : opt nat64;
/// }
/// ```
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InstallCodeArgs {
    pub mode: CanisterInstallMode,
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub sender_canister_version: Option<u64>,
}

impl std::fmt::Display for InstallCodeArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "InstallCodeArgs {{")?;
        writeln!(f, "  mode: {:?}", &self.mode)?;
        writeln!(f, "  canister_id: {:?}", &self.canister_id)?;
        writeln!(f, "  wasm_module: <{:?} bytes>", self.wasm_module.len())?;
        writeln!(f, "  arg: <{:?} bytes>", self.arg.len())?;
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
    ) -> Self {
        Self {
            mode,
            canister_id: canister_id.into(),
            wasm_module,
            arg,
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

/// Struct used for encoding/decoding
/// ```text
/// record {
///   mode : variant {
///     install;
///     reinstall;
///     upgrade : opt record {
///       skip_pre_upgrade : opt bool;
///       wasm_memory_persistence : opt variant {
///         keep;
///         replace;
///       };
///     };
///   };
///   canister_id : principal;
///   wasm_module : blob;
///   arg : blob;
///   sender_canister_version : opt nat64;
/// }
/// ```
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InstallCodeArgsV2 {
    pub mode: CanisterInstallModeV2,
    pub canister_id: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
    pub sender_canister_version: Option<u64>,
}

impl std::fmt::Display for InstallCodeArgsV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "InstallCodeArgsV2 {{")?;
        writeln!(f, "  mode: {:?}", &self.mode)?;
        writeln!(f, "  canister_id: {:?}", &self.canister_id)?;
        writeln!(f, "  wasm_module: <{:?} bytes>", self.wasm_module.len())?;
        writeln!(f, "  arg: <{:?} bytes>", self.arg.len())?;
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
    ) -> Self {
        Self {
            mode,
            canister_id: canister_id.into(),
            wasm_module,
            arg,
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
/// ```text
/// record {
///   canister_id : principal;
///   settings : canister_settings;
///   sender_canister_version : opt nat64;
/// }
/// ```
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
/// ```text
/// record {
///   name : text;
///   value : text;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct EnvironmentVariable {
    pub name: String,
    pub value: String,
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   controllers : opt vec principal;
///   compute_allocation : opt nat;
///   memory_allocation : opt nat;
///   freezing_threshold : opt nat;
///   reserved_cycles_limit : opt nat;
///   log_visibility : opt log_visibility;
///   log_memory_limit : opt nat;
///   wasm_memory_limit : opt nat;
///   wasm_memory_threshold : opt nat;
///   environment_variables : opt vec environment_variable;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct CanisterSettingsArgs {
    pub controllers: Option<BoundedControllers>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibilityV2>,
    pub log_memory_limit: Option<candid::Nat>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub wasm_memory_threshold: Option<candid::Nat>,
    pub environment_variables: Option<Vec<EnvironmentVariable>>,
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
            log_memory_limit: None,
            wasm_memory_limit: None,
            wasm_memory_threshold: None,
            environment_variables: None,
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
    log_memory_limit: Option<candid::Nat>,
    wasm_memory_limit: Option<candid::Nat>,
    wasm_memory_threshold: Option<candid::Nat>,
    environment_variables: Option<Vec<EnvironmentVariable>>,
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
            log_memory_limit: self.log_memory_limit,
            wasm_memory_limit: self.wasm_memory_limit,
            wasm_memory_threshold: self.wasm_memory_threshold,
            environment_variables: self.environment_variables,
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

    /// Sets the freezing threshold in seconds. For more details see
    /// the description of this field in the IC specification.
    /// Values larger than `u64::MAX` are invalid and thus this function
    /// should only be used in tests.
    #[doc(hidden)]
    pub fn with_freezing_threshold_u128(self, freezing_threshold: u128) -> Self {
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

    /// Sets the log capacity in bytes.
    pub fn with_log_memory_limit(self, log_memory_limit: u64) -> Self {
        Self {
            log_memory_limit: Some(candid::Nat::from(log_memory_limit)),
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

    pub fn with_environment_variables(
        self,
        environment_variables: Vec<EnvironmentVariable>,
    ) -> Self {
        Self {
            environment_variables: Some(environment_variables),
            ..self
        }
    }
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   settings : opt canister_settings;
///   sender_canister_version : opt nat64;
/// }
/// ```
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
/// ```text
/// record {
///   node_ids : vec principal;
///   registry_version : nat64;
/// }
/// ```
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
                    format!("Expected a set of NodeIds. The NodeId {node_id} is repeated"),
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
                format!("Payload deserialization error: '{err}'"),
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
/// variant { secp256k1; }
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

impl TryFrom<u32> for EcdsaCurve {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EcdsaCurve::Secp256k1),
            _ => Err(format!(
                "{value} is not a recognized EcdsaCurve variant identifier."
            )),
        }
    }
}

impl From<&EcdsaCurve> for pb_types::EcdsaCurve {
    fn from(item: &EcdsaCurve) -> Self {
        match item {
            EcdsaCurve::Secp256k1 => pb_types::EcdsaCurve::Secp256k1,
        }
    }
}

impl TryFrom<pb_types::EcdsaCurve> for EcdsaCurve {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_types::EcdsaCurve) -> Result<Self, Self::Error> {
        match item {
            pb_types::EcdsaCurve::Secp256k1 => Ok(EcdsaCurve::Secp256k1),
            pb_types::EcdsaCurve::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "EcdsaCurve",
                err: format!("Unable to convert {item:?} to an EcdsaCurve"),
            }),
        }
    }
}

impl std::fmt::Display for EcdsaCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for EcdsaCurve {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "secp256k1" => Ok(Self::Secp256k1),
            _ => Err(format!("{s} is not a recognized ECDSA curve")),
        }
    }
}

/// Unique identifier for a key that can be used for ECDSA signatures. The name
/// is just a identifier, but it may be used to convey some information about
/// the key (e.g. that the key is meant to be used for testing purposes).
/// ```text
/// record { curve : ecdsa_curve; name : text}
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

impl From<&EcdsaKeyId> for pb_types::EcdsaKeyId {
    fn from(item: &EcdsaKeyId) -> Self {
        Self {
            curve: pb_types::EcdsaCurve::from(&item.curve) as i32,
            name: item.name.clone(),
        }
    }
}

impl TryFrom<pb_types::EcdsaKeyId> for EcdsaKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_types::EcdsaKeyId) -> Result<Self, Self::Error> {
        Ok(Self {
            curve: EcdsaCurve::try_from(pb_types::EcdsaCurve::try_from(item.curve).map_err(
                |_| ProxyDecodeError::ValueOutOfRange {
                    typ: "EcdsaKeyId",
                    err: format!("Unable to convert {} to an EcdsaCurve", item.curve),
                },
            )?)?,
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
            .ok_or_else(|| format!("ECDSA key id {s} does not contain a ':'"))?;
        Ok(EcdsaKeyId {
            curve: curve.parse::<EcdsaCurve>()?,
            name: name.to_string(),
        })
    }
}

/// Types of algorithms that can be used for Schnorr signing.
/// ```text
/// variant { bip340secp256k1; ed25519 }
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

impl TryFrom<u32> for SchnorrAlgorithm {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SchnorrAlgorithm::Bip340Secp256k1),
            1 => Ok(SchnorrAlgorithm::Ed25519),
            _ => Err(format!(
                "{value} is not a recognized SchnorrAlgorithm variant identifier."
            )),
        }
    }
}

impl From<&SchnorrAlgorithm> for pb_types::SchnorrAlgorithm {
    fn from(item: &SchnorrAlgorithm) -> Self {
        match item {
            SchnorrAlgorithm::Bip340Secp256k1 => pb_types::SchnorrAlgorithm::Bip340secp256k1,
            SchnorrAlgorithm::Ed25519 => pb_types::SchnorrAlgorithm::Ed25519,
        }
    }
}

impl TryFrom<pb_types::SchnorrAlgorithm> for SchnorrAlgorithm {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_types::SchnorrAlgorithm) -> Result<Self, Self::Error> {
        match item {
            pb_types::SchnorrAlgorithm::Bip340secp256k1 => Ok(SchnorrAlgorithm::Bip340Secp256k1),
            pb_types::SchnorrAlgorithm::Ed25519 => Ok(SchnorrAlgorithm::Ed25519),
            pb_types::SchnorrAlgorithm::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "SchnorrAlgorithm",
                err: format!("Unable to convert {item:?} to a SchnorrAlgorithm"),
            }),
        }
    }
}

impl std::fmt::Display for SchnorrAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for SchnorrAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bip340secp256k1" => Ok(Self::Bip340Secp256k1),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(format!("{s} is not a recognized Schnorr algorithm")),
        }
    }
}

/// Unique identifier for a key that can be used for Schnorr signatures. The name
/// is just a identifier, but it may be used to convey some information about
/// the key (e.g. that the key is meant to be used for testing purposes).
/// ```text
/// record { algorithm : schnorr_algorithm; name : text}
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

impl From<&SchnorrKeyId> for pb_types::SchnorrKeyId {
    fn from(item: &SchnorrKeyId) -> Self {
        Self {
            algorithm: pb_types::SchnorrAlgorithm::from(&item.algorithm) as i32,
            name: item.name.clone(),
        }
    }
}

impl TryFrom<pb_types::SchnorrKeyId> for SchnorrKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_types::SchnorrKeyId) -> Result<Self, Self::Error> {
        let pb_types::SchnorrKeyId { algorithm, name } = item;
        let algorithm =
            SchnorrAlgorithm::try_from(pb_types::SchnorrAlgorithm::try_from(algorithm).map_err(
                |_| ProxyDecodeError::ValueOutOfRange {
                    typ: "SchnorrKeyId",
                    err: format!("Unable to convert {algorithm} to a SchnorrAlgorithm"),
                },
            )?)?;
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
            .ok_or_else(|| format!("Schnorr key id {s} does not contain a ':'"))?;
        Ok(SchnorrKeyId {
            algorithm: algorithm.parse::<SchnorrAlgorithm>()?,
            name: name.to_string(),
        })
    }
}

/// Types of curves that can be used for threshold key derivation (vetKD).
/// ```text
/// variant { bls12_381_g2; }
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
pub enum VetKdCurve {
    #[serde(rename = "bls12_381_g2")]
    #[allow(non_camel_case_types)]
    Bls12_381_G2,
}

impl TryFrom<u32> for VetKdCurve {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(VetKdCurve::Bls12_381_G2),
            _ => Err(format!(
                "{value} is not a recognized VetKdCurve variant identifier."
            )),
        }
    }
}

impl From<&VetKdCurve> for pb_types::VetKdCurve {
    fn from(item: &VetKdCurve) -> Self {
        match item {
            VetKdCurve::Bls12_381_G2 => pb_types::VetKdCurve::Bls12381G2,
        }
    }
}

impl TryFrom<pb_types::VetKdCurve> for VetKdCurve {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_types::VetKdCurve) -> Result<Self, Self::Error> {
        match item {
            pb_types::VetKdCurve::Bls12381G2 => Ok(VetKdCurve::Bls12_381_G2),
            pb_types::VetKdCurve::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "VetKdCurve",
                err: format!("Unable to convert {item:?} to a VetKdCurve"),
            }),
        }
    }
}

impl std::fmt::Display for VetKdCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for VetKdCurve {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bls12_381_g2" => Ok(Self::Bls12_381_G2),
            _ => Err(format!("{s} is not a recognized vetKD curve")),
        }
    }
}

/// Unique identifier for a key that can be used for threshold key derivation
/// (vetKD). The name is just an identifier, but it may be used to convey
/// some information about the key (e.g. that the key is meant to be used for
/// testing purposes).
/// ```text
/// record { curve : vetkd_curve; name : text}
/// ```
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
pub struct VetKdKeyId {
    pub curve: VetKdCurve,
    pub name: String,
}

impl From<&VetKdKeyId> for pb_types::VetKdKeyId {
    fn from(item: &VetKdKeyId) -> Self {
        Self {
            curve: pb_types::VetKdCurve::from(&item.curve) as i32,
            name: item.name.clone(),
        }
    }
}

impl TryFrom<pb_types::VetKdKeyId> for VetKdKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_types::VetKdKeyId) -> Result<Self, Self::Error> {
        Ok(Self {
            curve: VetKdCurve::try_from(pb_types::VetKdCurve::try_from(item.curve).map_err(
                |_| ProxyDecodeError::ValueOutOfRange {
                    typ: "VetKdKeyId",
                    err: format!("Unable to convert {} to a VetKdCurve", item.curve),
                },
            )?)?,
            name: item.name,
        })
    }
}

impl std::fmt::Display for VetKdKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.curve, self.name)
    }
}

impl FromStr for VetKdKeyId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (curve, name) = s
            .split_once(':')
            .ok_or_else(|| format!("vetKD key id {s} does not contain a ':'"))?;
        Ok(VetKdKeyId {
            curve: curve.parse::<VetKdCurve>()?,
            name: name.to_string(),
        })
    }
}

/// Unique identifier for a key that can be used for one of the signature schemes
/// supported on the IC.
/// ```text
/// variant { Ecdsa : ecdsa_key_id; Schnorr : schnorr_key_id; VetKd : vetkd_key_id }
/// ```
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    EnumCount,
    Serialize,
)]
pub enum MasterPublicKeyId {
    Ecdsa(EcdsaKeyId),
    Schnorr(SchnorrKeyId),
    VetKd(VetKdKeyId),
}

impl From<&MasterPublicKeyId> for pb_types::MasterPublicKeyId {
    fn from(item: &MasterPublicKeyId) -> Self {
        use pb_types::master_public_key_id::KeyId;
        let key_id_pb = match item {
            MasterPublicKeyId::Schnorr(schnorr_key_id) => KeyId::Schnorr(schnorr_key_id.into()),
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => KeyId::Ecdsa(ecdsa_key_id.into()),
            MasterPublicKeyId::VetKd(vetkd_key_id) => KeyId::Vetkd(vetkd_key_id.into()),
        };
        Self {
            key_id: Some(key_id_pb),
        }
    }
}

impl TryFrom<pb_types::MasterPublicKeyId> for MasterPublicKeyId {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_types::MasterPublicKeyId) -> Result<Self, Self::Error> {
        use pb_types::master_public_key_id::KeyId;
        let Some(key_id_pb) = item.key_id else {
            return Err(ProxyDecodeError::MissingField("MasterPublicKeyId::key_id"));
        };
        let master_public_key_id = match key_id_pb {
            KeyId::Schnorr(schnorr_key_id) => {
                MasterPublicKeyId::Schnorr(schnorr_key_id.try_into()?)
            }
            KeyId::Ecdsa(ecdsa_key_id) => MasterPublicKeyId::Ecdsa(ecdsa_key_id.try_into()?),
            KeyId::Vetkd(vetkd_key_id) => MasterPublicKeyId::VetKd(vetkd_key_id.try_into()?),
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
            Self::VetKd(vetkd_key_id) => {
                write!(f, "vetkd:")?;
                vetkd_key_id.fmt(f)
            }
        }
    }
}

impl MasterPublicKeyId {
    /// Check whether this type of [`MasterPublicKeyId`] requires to run on the IDKG protocol
    pub fn is_idkg_key(&self) -> bool {
        match self {
            Self::Ecdsa(_) | Self::Schnorr(_) => true,
            Self::VetKd(_) => false,
        }
    }

    /// Check whether this type of [`MasterPublicKeyId`] is a VetKd key
    pub fn is_vetkd_key(&self) -> bool {
        matches!(self, Self::VetKd(_))
    }

    /// Check whether this type of [`MasterPublicKeyId`] requires pre-signatures
    pub fn requires_pre_signatures(&self) -> bool {
        match self {
            Self::Ecdsa(_) | Self::Schnorr(_) => true,
            Self::VetKd(_) => false,
        }
    }
}

impl FromStr for MasterPublicKeyId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, key_id) = s
            .split_once(':')
            .ok_or_else(|| format!("Master public key id {s} does not contain a ':'"))?;
        match scheme.to_lowercase().as_str() {
            "ecdsa" => Ok(Self::Ecdsa(EcdsaKeyId::from_str(key_id)?)),
            "schnorr" => Ok(Self::Schnorr(SchnorrKeyId::from_str(key_id)?)),
            "vetkd" => Ok(Self::VetKd(VetKdKeyId::from_str(key_id)?)),
            _ => Err(format!(
                "Scheme {scheme} in master public key id {s} is not supported."
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
/// record {
///   message_hash : blob;
///   derivation_path : vec blob;
///   key_id : ecdsa_key_id;
/// }
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
/// record {
///   canister_id : opt canister_id;
///   derivation_path : vec blob;
///   key_id : ecdsa_key_id;
/// }
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
/// record {
///   public_key : blob;
///   chain_code : blob;
/// }
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

/// Argument of the reshare_chain_key API.
/// ```text
/// record {
///     key_id : master_public_key_id;
///     subnet_id : principal;
///     nodes : vec principal;
///     registry_version : nat64;
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ReshareChainKeyArgs {
    pub key_id: MasterPublicKeyId,
    pub subnet_id: SubnetId,
    nodes: BoundedNodes,
    registry_version: u64,
}

impl Payload<'_> for ReshareChainKeyArgs {}

impl ReshareChainKeyArgs {
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
                    format!("Expected a set of NodeIds. The NodeId {node_id} is repeated"),
                ));
            }
        }
        Ok(set)
    }

    pub fn get_registry_version(&self) -> RegistryVersion {
        RegistryVersion::new(self.registry_version)
    }
}

/// Struct used to return the chain key resharing.
#[derive(Debug, Deserialize, Serialize)]
pub enum ReshareChainKeyResponse {
    IDkg(InitialIDkgDealings),
    NiDkg(InitialNiDkgTranscriptRecord),
}

impl ReshareChainKeyResponse {
    pub fn encode(&self) -> Vec<u8> {
        let serde_encoded_bytes = self.encode_with_serde_cbor();
        Encode!(&serde_encoded_bytes).unwrap()
    }

    fn encode_with_serde_cbor(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }

    pub fn decode(blob: &[u8]) -> Result<Self, UserError> {
        let serde_encoded_bytes =
            Decode!([decoder_config()]; blob, Vec<u8>).map_err(candid_error_to_user_error)?;
        serde_cbor::from_slice::<Self>(&serde_encoded_bytes).map_err(|err| {
            UserError::new(
                ErrorCode::InvalidManagementPayload,
                format!("Payload deserialization error: '{err}'"),
            )
        })
    }
}

/// Represents the BIP341 aux argument of the sign_with_schnorr API.
/// ```text
/// record {
///   merkle_root_hash : blob;
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SignWithBip341Aux {
    pub merkle_root_hash: ByteBuf,
}

/// Represents the aux argument of the sign_with_schnorr API.
/// ```text
/// variant {
///    bip341 : record {
///      merkle_root_hash : blob;
///   }
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum SignWithSchnorrAux {
    #[serde(rename = "bip341")]
    Bip341(SignWithBip341Aux),
}

/// Represents the argument of the sign_with_schnorr API.
/// ```text
/// record {
///   message : blob;
///   derivation_path : vec blob;
///   key_id : schnorr_key_id;
///   aux : opt schnorr_aux;
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SignWithSchnorrArgs {
    #[serde(with = "serde_bytes")]
    pub message: Vec<u8>,
    pub derivation_path: DerivationPath,
    pub key_id: SchnorrKeyId,
    pub aux: Option<SignWithSchnorrAux>,
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
/// record {
///   canister_id : opt canister_id;
///   derivation_path : vec blob;
///   key_id : schnorr_key_id;
/// }
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
/// record {
///   public_key : blob;
///   chain_code : blob;
/// }
/// ```
#[derive(Debug, CandidType, Deserialize)]
pub struct SchnorrPublicKeyResponse {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>,
}

impl Payload<'_> for SchnorrPublicKeyResponse {}

/// Represents the argument of the vetkd_derive_key API.
/// ```text
/// record {
///   input : blob;
///   context : blob;
///   transport_public_key : blob;
///   key_id : record { curve : vetkd_curve; name : text };
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct VetKdDeriveKeyArgs {
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub input: Vec<u8>,
    pub key_id: VetKdKeyId,
    #[serde(with = "serde_bytes")]
    pub transport_public_key: [u8; 48],
}

impl Payload<'_> for VetKdDeriveKeyArgs {}

/// Struct used to return vet KD result.
/// ```text
/// record {
///   encrypted_key : blob;
/// }
/// ```
#[derive(Debug, CandidType, Deserialize)]
pub struct VetKdDeriveKeyResult {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}

impl Payload<'_> for VetKdDeriveKeyResult {}

/// Represents the argument of the vetkd_public_key API.
/// ```text
/// record {
///   canister_id : opt canister_id;
///   context : blob;
///   key_id : record { curve : vetkd_curve; name : text };
/// }
/// ```
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct VetKdPublicKeyArgs {
    pub canister_id: Option<CanisterId>,
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
    pub key_id: VetKdKeyId,
}

impl Payload<'_> for VetKdPublicKeyArgs {}

/// Represents the response of the vetkd_public_key API.
/// ```text
/// record {
///   public_key : blob;
/// }
/// ```
#[derive(Debug, CandidType, Deserialize)]
pub struct VetKdPublicKeyResult {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

impl Payload<'_> for VetKdPublicKeyResult {}

// Export the bitcoin types.
pub use ic_btc_interface::{
    GetBalanceRequest as BitcoinGetBalanceArgs,
    GetBlockHeadersRequest as BitcoinGetBlockHeadersArgs,
    GetCurrentFeePercentilesRequest as BitcoinGetCurrentFeePercentilesArgs,
    GetUtxosRequest as BitcoinGetUtxosArgs, SendTransactionRequest as BitcoinSendTransactionArgs,
};
pub use ic_btc_replica_types::{
    GetSuccessorsRequest as BitcoinGetSuccessorsArgs,
    GetSuccessorsRequestInitial as BitcoinGetSuccessorsRequestInitial,
    GetSuccessorsResponse as BitcoinGetSuccessorsResponse,
    GetSuccessorsResponseComplete as BitcoinGetSuccessorsResponseComplete,
    GetSuccessorsResponsePartial as BitcoinGetSuccessorsResponsePartial, Network as BitcoinNetwork,
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
    CanisterStatus,
}

/// `CandidType` for `SubnetInfoArgs`
/// ```text
/// record {
///   subnet_id : principal;
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct SubnetInfoArgs {
    pub subnet_id: PrincipalId,
}

impl Payload<'_> for SubnetInfoArgs {}

/// `CandidType` for `SubnetInfoResponse`
/// ```text
/// record {
///     replica_version : text;
///     registry_version : nat64;
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct SubnetInfoResponse {
    pub replica_version: String,
    pub registry_version: u64,
}

impl Payload<'_> for SubnetInfoResponse {}

/// `CandidType` for `NodeMetricsHistoryArgs`
/// ```text
/// record {
///     subnet_id : principal;
///     start_at_timestamp_nanos : nat64;
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

/// Exclusive range for fetching canister logs `[start, end)`.
/// It's used both for `idx` and `timestamp_nanos` based filtering.
/// If `end` is below `start`, the range is considered empty.
#[derive(Copy, Clone, Debug, Default, CandidType, Deserialize)]
pub struct FetchCanisterLogsRange {
    pub start: u64, // Inclusive.
    pub end: u64,   // Exclusive, values below `start` are ignored.
}

impl Payload<'_> for FetchCanisterLogsRange {}

impl FetchCanisterLogsRange {
    /// Creates a new range from `start` (inclusive) to `end` (exclusive).
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Returns true if the range is valid (i.e., start < end).
    pub fn is_valid(&self) -> bool {
        self.start < self.end
    }

    /// Returns the length of the range.
    /// If user provides an `end` value below `start`, the length is 0.
    fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns the end of the range (exclusive).
    fn sanitized_end(&self) -> u64 {
        self.start + self.len()
    }

    /// Returns true if the range is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if the range contains the given value.
    pub fn contains(&self, value: u64) -> bool {
        self.start <= value && value < self.sanitized_end()
    }
}

#[derive(Copy, Clone, Debug, CandidType, Deserialize)]
pub enum FetchCanisterLogsFilter {
    #[serde(rename = "by_idx")]
    ByIdx(FetchCanisterLogsRange),

    #[serde(rename = "by_timestamp_nanos")]
    ByTimestampNanos(FetchCanisterLogsRange),
}

impl Payload<'_> for FetchCanisterLogsFilter {}

impl FetchCanisterLogsFilter {
    pub fn is_valid(&self) -> bool {
        match self {
            FetchCanisterLogsFilter::ByIdx(range) => range.is_valid(),
            FetchCanisterLogsFilter::ByTimestampNanos(range) => range.is_valid(),
        }
    }
}

/// `CandidType` for `FetchCanisterLogsRequest`
/// ```text
/// record {
///     canister_id : principal;
///     filter : opt variant {
///       by_idx : record { start : nat64; end : nat64 };
///       by_timestamp_nanos : record { start : nat64; end : nat64 };
///     }
/// }
/// ```
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct FetchCanisterLogsRequest {
    pub canister_id: PrincipalId,
    pub filter: Option<FetchCanisterLogsFilter>,
}

impl Payload<'_> for FetchCanisterLogsRequest {}

impl FetchCanisterLogsRequest {
    pub fn new(canister_id: CanisterId) -> Self {
        Self {
            canister_id: canister_id.into(),
            filter: None,
        }
    }

    pub fn new_with_filter(canister_id: CanisterId, filter: FetchCanisterLogsFilter) -> Self {
        Self {
            canister_id: canister_id.into(),
            filter: Some(filter),
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

/// `CandidType` for `CanisterLogRecord`
/// ```text
/// record {
///     idx : nat64;
///     timestamp_nanos : nat64;
///     content : blob;
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
///     canister_log_records : vec canister_log_record;
/// }
/// ```
#[derive(Clone, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct FetchCanisterLogsResponse {
    pub canister_log_records: Vec<CanisterLogRecord>,
}

impl Payload<'_> for FetchCanisterLogsResponse {}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
///   chunk : blob;
/// }
/// ```
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
/// ```text
/// record {
///   hash : blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Serialize, Deserialize)]
pub struct ChunkHash {
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl Payload<'_> for ChunkHash {}

/// Struct to be returned when uploading a Wasm chunk.
/// ```text
/// record {
///   hash : blob;
/// }
/// ```
pub type UploadChunkReply = ChunkHash;

/// Struct used for encoding/decoding
/// ```text
/// record {
///   mode : variant {
///     install;
///     reinstall;
///     upgrade : opt record {
///       skip_pre_upgrade : opt bool;
///     };
///   };
///   target_canister : principal;
///   store_canister : opt principal;
///   chunk_hashes_list : vec chunk_hash;
///   wasm_module_hash : blob;
///   arg : blob;
///   sender_canister_version : opt nat64;
/// }
/// ```
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
/// ```text
/// record {
///     mode : variant {
///         install;
///         reinstall;
///         upgrade : opt record {
///             skip_pre_upgrade : opt bool
///         }
///     };
///     target_canister_id : principal;
///     store_canister_id : opt principal;
///     chunk_hashes_list : vec blob;
///     wasm_module_hash : blob;
///     arg : blob;
///     sender_canister_version : opt nat64;
/// }
/// ```
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
/// ```text
/// record {
///   canister_id : principal;
/// }
/// ```
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
/// ```text
/// record {
///   canister_id : principal;
/// }
/// ```
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
/// ```text
/// vec record { hash : blob }
/// ```
#[derive(PartialEq, Debug, CandidType, Deserialize)]
pub struct StoredChunksReply(pub Vec<ChunkHash>);

impl Payload<'_> for StoredChunksReply {}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
///   replace_snapshot : opt blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotArgs {
    pub canister_id: PrincipalId,
    pub replace_snapshot: Option<SnapshotId>,
}

impl TakeCanisterSnapshotArgs {
    pub fn new(canister_id: CanisterId, replace_snapshot: Option<SnapshotId>) -> Self {
        Self {
            canister_id: canister_id.get(),
            replace_snapshot,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn replace_snapshot(&self) -> Option<SnapshotId> {
        self.replace_snapshot
    }
}
impl Payload<'_> for TakeCanisterSnapshotArgs {}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
///   snapshot_id : blob;
///   sender_canister_version : opt nat64;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotArgs {
    canister_id: PrincipalId,
    snapshot_id: SnapshotId,
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
            snapshot_id,
            sender_canister_version,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl Payload<'_> for LoadCanisterSnapshotArgs {}

/// Struct to be returned when taking a canister snapshot.
/// ```text
/// record {
///      id : blob;
///      taken_at_timestamp : nat64;
///      total_size : nat64;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterSnapshotResponse {
    pub id: SnapshotId,
    pub taken_at_timestamp: u64,
    pub total_size: u64,
}

impl Payload<'_> for CanisterSnapshotResponse {}

impl CanisterSnapshotResponse {
    pub fn new(snapshot_id: &SnapshotId, taken_at_timestamp: u64, total_size: NumBytes) -> Self {
        Self {
            id: *snapshot_id,
            taken_at_timestamp,
            total_size: total_size.get(),
        }
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        self.id
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn taken_at_timestamp(&self) -> u64 {
        self.taken_at_timestamp
    }
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
///   snapshot_id : blob;
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct DeleteCanisterSnapshotArgs {
    pub canister_id: PrincipalId,
    pub snapshot_id: SnapshotId,
}

impl DeleteCanisterSnapshotArgs {
    pub fn new(canister_id: CanisterId, snapshot_id: SnapshotId) -> Self {
        Self {
            canister_id: canister_id.get(),
            snapshot_id,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }
}

impl Payload<'_> for DeleteCanisterSnapshotArgs {}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
/// }
/// ```
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

/// An enum representing the possible values of a global variable.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, EnumIter, CandidType)]
pub enum Global {
    #[serde(rename = "i32")]
    I32(i32),
    #[serde(rename = "i64")]
    I64(i64),
    #[serde(rename = "f32")]
    F32(f32),
    #[serde(rename = "f64")]
    F64(f64),
    #[serde(rename = "v128")]
    V128(u128),
}

impl Global {
    pub fn type_name(&self) -> &'static str {
        match self {
            Global::I32(_) => "i32",
            Global::I64(_) => "i64",
            Global::F32(_) => "f32",
            Global::F64(_) => "f64",
            Global::V128(_) => "v128",
        }
    }
}

impl Hash for Global {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = match self {
            Global::I32(val) => val.to_le_bytes().to_vec(),
            Global::I64(val) => val.to_le_bytes().to_vec(),
            Global::F32(val) => val.to_le_bytes().to_vec(),
            Global::F64(val) => val.to_le_bytes().to_vec(),
            Global::V128(val) => val.to_le_bytes().to_vec(),
        };
        bytes.hash(state)
    }
}

impl PartialEq<Global> for Global {
    fn eq(&self, other: &Global) -> bool {
        match (self, other) {
            (Global::I32(val), Global::I32(other_val)) => val == other_val,
            (Global::I64(val), Global::I64(other_val)) => val == other_val,
            (Global::F32(val), Global::F32(other_val)) => val == other_val,
            (Global::F64(val), Global::F64(other_val)) => val == other_val,
            (Global::V128(val), Global::V128(other_val)) => val == other_val,
            _ => false,
        }
    }
}

impl Eq for Global {}

impl From<&Global> for pb_canister_state_bits::Global {
    fn from(item: &Global) -> Self {
        match item {
            Global::I32(value) => Self {
                global: Some(pb_canister_state_bits::global::Global::I32(*value)),
            },
            Global::I64(value) => Self {
                global: Some(pb_canister_state_bits::global::Global::I64(*value)),
            },
            Global::F32(value) => Self {
                global: Some(pb_canister_state_bits::global::Global::F32(*value)),
            },
            Global::F64(value) => Self {
                global: Some(pb_canister_state_bits::global::Global::F64(*value)),
            },
            Global::V128(value) => Self {
                global: Some(pb_canister_state_bits::global::Global::V128(
                    value.to_le_bytes().to_vec(),
                )),
            },
        }
    }
}

impl TryFrom<pb_canister_state_bits::Global> for Global {
    type Error = ProxyDecodeError;
    fn try_from(value: pb_canister_state_bits::Global) -> Result<Self, Self::Error> {
        match try_from_option_field(value.global, "Global::global")? {
            pb_canister_state_bits::global::Global::I32(value) => Ok(Self::I32(value)),
            pb_canister_state_bits::global::Global::I64(value) => Ok(Self::I64(value)),
            pb_canister_state_bits::global::Global::F32(value) => Ok(Self::F32(value)),
            pb_canister_state_bits::global::Global::F64(value) => Ok(Self::F64(value)),
            pb_canister_state_bits::global::Global::V128(value) => Ok(Self::V128(
                u128::from_le_bytes(value.as_slice().try_into().unwrap()),
            )),
        }
    }
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
///   snapshot_id : blob;
/// }
/// ```

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ReadCanisterSnapshotMetadataArgs {
    pub canister_id: PrincipalId,
    pub snapshot_id: SnapshotId,
}

impl ReadCanisterSnapshotMetadataArgs {
    pub fn new(canister_id: CanisterId, snapshot_id: SnapshotId) -> Self {
        Self {
            canister_id: canister_id.get(),
            snapshot_id,
        }
    }
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }
}

impl Payload<'_> for ReadCanisterSnapshotMetadataArgs {}

#[derive(Clone, Copy, Eq, PartialEq, Debug, CandidType, Serialize, Deserialize, EnumIter)]
pub enum SnapshotSource {
    #[serde(rename = "taken_from_canister")]
    TakenFromCanister(Reserved),
    #[serde(rename = "metadata_upload")]
    MetadataUpload(Reserved),
}

impl SnapshotSource {
    /// Alternative to the literal variant `SnapshotSource::TakenFromCanister(candid::Reserved)`
    /// for consumers that don't want to depend on Candid directly.
    pub fn taken_from_canister() -> Self {
        Self::TakenFromCanister(Reserved)
    }

    /// Alternative to the literal variant `SnapshotSource::MetadataUpload(candid::Reserved)`
    /// for consumers that don't want to depend on Candid directly.
    pub fn metadata_upload() -> Self {
        Self::MetadataUpload(Reserved)
    }
}

impl Default for SnapshotSource {
    fn default() -> Self {
        Self::TakenFromCanister(Reserved)
    }
}

impl From<SnapshotSource> for pb_canister_state_bits::SnapshotSource {
    fn from(value: SnapshotSource) -> Self {
        match value {
            SnapshotSource::TakenFromCanister(Reserved) => {
                pb_canister_state_bits::SnapshotSource::TakenFromCanister
            }
            SnapshotSource::MetadataUpload(Reserved) => {
                pb_canister_state_bits::SnapshotSource::UploadedManually
            }
        }
    }
}

impl TryFrom<pb_canister_state_bits::SnapshotSource> for SnapshotSource {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_canister_state_bits::SnapshotSource) -> Result<Self, Self::Error> {
        match value {
            pb_canister_state_bits::SnapshotSource::Unspecified => {
                Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "SnapshotSource",
                    err: format!("Unexpected value of SnapshotSource: {value:?}"),
                })
            }
            pb_canister_state_bits::SnapshotSource::TakenFromCanister => {
                Ok(SnapshotSource::TakenFromCanister(Reserved))
            }
            pb_canister_state_bits::SnapshotSource::UploadedManually => {
                Ok(SnapshotSource::MetadataUpload(Reserved))
            }
        }
    }
}

/// Struct used for encoding/decoding
/// ```text
/// record {
///     source : variant {
///         taken_from_canister : reserved;
///         metadata_upload : reserved;
///     };
///     taken_at_timestamp : nat64;
///     wasm_module_size : nat64;
///     globals : vec variant {
///         i32 : int32;
///         i64 : int64;
///         f32 : float32;
///         f64 : float64;
///         v128 : nat;
///     };
///     wasm_memory_size : nat64;
///     stable_memory_size : nat64;
///     wasm_chunk_store : vec record {
///         hash : blob;
///     };
///     canister_version : nat64;
///     certified_data : blob;
///     global_timer : variant {
///         inactive;
///         active : nat64;
///     };
///     on_low_wasm_memory_hook_status : variant {
///         condition_not_satisfied;
///         ready;
///         executed;
///     };
/// }
/// ```

#[derive(Clone, PartialEq, Debug, CandidType, Serialize, Deserialize)]
pub struct ReadCanisterSnapshotMetadataResponse {
    pub source: SnapshotSource,
    pub taken_at_timestamp: u64,
    pub wasm_module_size: u64,
    pub globals: Vec<Global>,
    pub wasm_memory_size: u64,
    pub stable_memory_size: u64,
    pub wasm_chunk_store: Vec<ChunkHash>,
    pub canister_version: u64,
    #[serde(with = "serde_bytes")]
    pub certified_data: Vec<u8>,
    pub global_timer: Option<GlobalTimer>,
    pub on_low_wasm_memory_hook_status: Option<OnLowWasmMemoryHookStatus>,
}

impl Payload<'_> for ReadCanisterSnapshotMetadataResponse {}

/// An inner type of [`ReadCanisterSnapshotMetadataResponse`].
///
/// Corresponds to the internal `CanisterTimer`, but is candid de/encodable.
#[derive(Copy, Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum GlobalTimer {
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "active")]
    Active(u64),
}

/// A wrapper around the different statuses of `OnLowWasmMemory` hook execution.
#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Default, Deserialize, CandidType, Serialize, EnumIter,
)]
pub enum OnLowWasmMemoryHookStatus {
    #[default]
    #[serde(rename = "condition_not_satisfied")]
    ConditionNotSatisfied,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "executed")]
    Executed,
}

impl OnLowWasmMemoryHookStatus {
    pub fn update(&mut self, is_hook_condition_satisfied: bool) {
        *self = if is_hook_condition_satisfied {
            match *self {
                Self::ConditionNotSatisfied | Self::Ready => Self::Ready,
                Self::Executed => Self::Executed,
            }
        } else {
            Self::ConditionNotSatisfied
        };
    }

    pub fn is_ready(&self) -> bool {
        *self == Self::Ready
    }

    /// Used to compare the hook status from snapshot metadata with a recently checked hook_condition
    /// (via `CanisterState::is_low_wasm_memory_hook_condition_satisfied`).
    pub fn is_consistent_with(&self, hook_condition: bool) -> bool {
        match (hook_condition, self) {
            (true, OnLowWasmMemoryHookStatus::ConditionNotSatisfied)
            | (false, OnLowWasmMemoryHookStatus::Ready)
            | (false, OnLowWasmMemoryHookStatus::Executed) => false,
            // all other combinations are valid
            _ => true,
        }
    }
}

impl From<&OnLowWasmMemoryHookStatus> for pb_canister_state_bits::OnLowWasmMemoryHookStatus {
    fn from(item: &OnLowWasmMemoryHookStatus) -> Self {
        use OnLowWasmMemoryHookStatus::*;

        match *item {
            ConditionNotSatisfied => Self::ConditionNotSatisfied,
            Ready => Self::Ready,
            Executed => Self::Executed,
        }
    }
}

impl TryFrom<pb_canister_state_bits::OnLowWasmMemoryHookStatus> for OnLowWasmMemoryHookStatus {
    type Error = ProxyDecodeError;

    fn try_from(
        value: pb_canister_state_bits::OnLowWasmMemoryHookStatus,
    ) -> Result<Self, Self::Error> {
        match value {
            pb_canister_state_bits::OnLowWasmMemoryHookStatus::Unspecified => {
                Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "OnLowWasmMemoryHookStatus",
                    err: format!(
                        "Unexpected value of status of on low wasm memory hook: {value:?}"
                    ),
                })
            }
            pb_canister_state_bits::OnLowWasmMemoryHookStatus::ConditionNotSatisfied => {
                Ok(OnLowWasmMemoryHookStatus::ConditionNotSatisfied)
            }
            pb_canister_state_bits::OnLowWasmMemoryHookStatus::Ready => {
                Ok(OnLowWasmMemoryHookStatus::Ready)
            }
            pb_canister_state_bits::OnLowWasmMemoryHookStatus::Executed => {
                Ok(OnLowWasmMemoryHookStatus::Executed)
            }
        }
    }
}

/// Struct for encoding/decoding
/// ```text
/// record {
///  canister_id : principal;
///  snapshot_id : blob;
///  kind : variant {
///         wasm_module : record {
///         offset : nat64;
///         size : nat64;
///     };
///     wasm_memory : record {
///         offset : nat64;
///         size : nat64;
///     };
///     stable_memory : record {
///         offset : nat64;
///         size : nat64;
///     };
///     wasm_chunk : record {
///         hash : blob;
///     };
///  };
/// }
/// ```

#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]
pub struct ReadCanisterSnapshotDataArgs {
    pub canister_id: PrincipalId,
    pub snapshot_id: SnapshotId,
    pub kind: CanisterSnapshotDataKind,
}

impl Payload<'_> for ReadCanisterSnapshotDataArgs {}

impl ReadCanisterSnapshotDataArgs {
    pub fn new(
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        kind: CanisterSnapshotDataKind,
    ) -> Self {
        Self {
            canister_id: canister_id.get(),
            snapshot_id,
            kind,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }
}

#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]
pub enum CanisterSnapshotDataKind {
    #[serde(rename = "wasm_module")]
    WasmModule { offset: u64, size: u64 },
    #[serde(rename = "wasm_memory")]
    WasmMemory { offset: u64, size: u64 },
    #[serde(rename = "stable_memory")]
    StableMemory { offset: u64, size: u64 },
    #[serde(rename = "wasm_chunk")]
    WasmChunk {
        #[serde(with = "serde_bytes")]
        hash: Vec<u8>,
    },
}

#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]

/// Struct to encode/decode
/// ```text
/// record { chunk : blob }
/// ```
pub struct ReadCanisterSnapshotDataResponse {
    #[serde(with = "serde_bytes")]
    pub chunk: Vec<u8>,
}

impl Payload<'_> for ReadCanisterSnapshotDataResponse {}

impl ReadCanisterSnapshotDataResponse {
    pub fn new(chunk: Vec<u8>) -> Self {
        Self { chunk }
    }
}

/// Struct to encode/decode
/// ```text
/// record {
///     canister_id : principal;
///     replace_snapshot : opt blob;
///     wasm_module_size : nat64;
///     globals : vec variant {
///         i32 : int32;
///         i64 : int64;
///         f32 : float32;
///         f64 : float64;
///         v128 : nat;
///     };
///     wasm_memory_size : nat64;
///     stable_memory_size : nat64;
///     certified_data : blob;
///     global_timer : opt variant {
///         inactive;
///         active : nat64;
///     };
///     on_low_wasm_memory_hook_status : opt variant {
///         condition_not_satisfied;
///         ready;
///         executed;
///     };
/// }
/// ```

#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]
pub struct UploadCanisterSnapshotMetadataArgs {
    pub canister_id: PrincipalId,
    pub replace_snapshot: Option<SnapshotId>,
    pub wasm_module_size: u64,
    pub globals: Vec<Global>,
    pub wasm_memory_size: u64,
    pub stable_memory_size: u64,
    #[serde(with = "serde_bytes")]
    pub certified_data: Vec<u8>,
    pub global_timer: Option<GlobalTimer>,
    pub on_low_wasm_memory_hook_status: Option<OnLowWasmMemoryHookStatus>,
}

impl Payload<'_> for UploadCanisterSnapshotMetadataArgs {}

impl UploadCanisterSnapshotMetadataArgs {
    pub fn new(
        canister_id: CanisterId,
        replace_snapshot: Option<SnapshotId>,
        wasm_module_size: u64,
        globals: Vec<Global>,
        wasm_memory_size: u64,
        stable_memory_size: u64,
        certified_data: Vec<u8>,
        global_timer: Option<GlobalTimer>,
        on_low_wasm_memory_hook_status: Option<OnLowWasmMemoryHookStatus>,
    ) -> Self {
        Self {
            canister_id: canister_id.get(),
            replace_snapshot,
            wasm_module_size,
            globals,
            wasm_memory_size,
            stable_memory_size,
            certified_data,
            global_timer,
            on_low_wasm_memory_hook_status,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn replace_snapshot(&self) -> Option<SnapshotId> {
        self.replace_snapshot
    }

    /// Returns the size of this snapshot, excluding the size of the wasm chunk store.
    pub fn snapshot_size_bytes(&self) -> NumBytes {
        let num_bytes = self.wasm_module_size
            + self.wasm_memory_size
            + self.stable_memory_size
            + self.certified_data.len() as u64
            + self.globals.len() as u64 * size_of::<Global>() as u64;

        NumBytes::new(num_bytes)
    }
}

/// Struct to encode/decode
/// ```text
/// record {
///   snapshot_id : blob;
/// }
/// ```
#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]
pub struct UploadCanisterSnapshotMetadataResponse {
    pub snapshot_id: SnapshotId,
}

impl Payload<'_> for UploadCanisterSnapshotMetadataResponse {}

impl UploadCanisterSnapshotMetadataResponse {
    pub fn get_snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }
}

/// Struct to encode/decode
/// ```text
/// record {
///     canister_id : principal;
///     snapshot_id : blob;
///     kind : variant {
///         wasm_module : record {
///             offset : nat64;
///         };
///         wasm_memory : record {
///             offset : nat64;
///         };
///         stable_memory : record {
///             offset : nat64;
///         };
///         wasm_chunk;
///     };
///     chunk : blob;
/// }
/// ```

#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]
pub struct UploadCanisterSnapshotDataArgs {
    pub canister_id: PrincipalId,
    pub snapshot_id: SnapshotId,
    pub kind: CanisterSnapshotDataOffset,
    #[serde(with = "serde_bytes")]
    pub chunk: Vec<u8>,
}

impl Payload<'_> for UploadCanisterSnapshotDataArgs {}

impl UploadCanisterSnapshotDataArgs {
    pub fn new(
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        kind: CanisterSnapshotDataOffset,
        chunk: Vec<u8>,
    ) -> Self {
        Self {
            canister_id: canister_id.get(),
            snapshot_id,
            kind,
            chunk,
        }
    }

    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn get_snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }
}

#[derive(Clone, Debug, Deserialize, CandidType, Serialize)]
pub enum CanisterSnapshotDataOffset {
    #[serde(rename = "wasm_module")]
    WasmModule { offset: u64 },
    #[serde(rename = "wasm_memory")]
    WasmMemory { offset: u64 },
    #[serde(rename = "stable_memory")]
    StableMemory { offset: u64 },
    #[serde(rename = "wasm_chunk")]
    WasmChunk,
}

/// Struct to encode/decode
/// ```text
/// record {
///   canister_id : principal;
///   rename_to : record {
///     canister_id : principal;
///     version : nat64;
///     total_num_changes : nat64;
///   };
///   requested_by : principal;
///   sender_canister_version : nat64;
/// }
/// ```

#[derive(Clone, Debug, Deserialize, CandidType, Serialize, PartialEq)]
pub struct RenameCanisterArgs {
    pub canister_id: PrincipalId,
    pub rename_to: RenameToArgs,
    pub requested_by: PrincipalId,
    pub sender_canister_version: u64,
}

impl Payload<'_> for RenameCanisterArgs {}

impl RenameCanisterArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }

    pub fn requested_by(&self) -> PrincipalId {
        self.requested_by
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        Some(self.sender_canister_version)
    }
}

#[derive(Clone, Debug, Deserialize, CandidType, Serialize, PartialEq)]
pub struct RenameToArgs {
    pub canister_id: PrincipalId,
    pub version: u64,
    pub total_num_changes: u64,
}

impl RenameToArgs {
    pub fn get_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    use ic_protobuf::state::canister_state_bits::v1 as pb_canister_state_bits;

    #[test]
    fn snapshot_source_exhaustive() {
        for initial in SnapshotSource::iter() {
            let encoded = pb_canister_state_bits::SnapshotSource::from(initial);
            let round_trip = SnapshotSource::try_from(encoded).unwrap();
            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn on_low_wasm_memory_hook_status_exhaustive() {
        for initial in OnLowWasmMemoryHookStatus::iter() {
            let encoded = pb_canister_state_bits::OnLowWasmMemoryHookStatus::from(&initial);
            let round_trip = OnLowWasmMemoryHookStatus::try_from(encoded).unwrap();
            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn ecdsa_from_u32_exhaustive() {
        // If this test fails, make sure this trait impl covers all variants:
        // `impl TryFrom<u32> for EcdsaCurve`
        for curve in EcdsaCurve::iter() {
            match curve {
                EcdsaCurve::Secp256k1 => assert_eq!(EcdsaCurve::try_from(0).unwrap(), curve),
            }
        }
    }

    #[test]
    fn schnorr_from_u32_exhaustive() {
        // If this test fails, make sure this trait impl covers all variants:
        // `impl TryFrom<u32> for SchnorrAlgorithm`
        for algorithm in SchnorrAlgorithm::iter() {
            match algorithm {
                SchnorrAlgorithm::Bip340Secp256k1 => {
                    assert_eq!(SchnorrAlgorithm::try_from(0).unwrap(), algorithm)
                }
                SchnorrAlgorithm::Ed25519 => {
                    assert_eq!(SchnorrAlgorithm::try_from(1).unwrap(), algorithm)
                }
            }
        }
    }

    #[test]
    fn vetkd_from_u32_exhaustive() {
        // If this test fails, make sure this trait impl covers all variants:
        // `impl TryFrom<u32> for VetKdCurve`
        for curve in VetKdCurve::iter() {
            match curve {
                VetKdCurve::Bls12_381_G2 => assert_eq!(VetKdCurve::try_from(0).unwrap(), curve),
            }
        }
    }

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
    fn compatibility_for_snapshot_source() {
        // If this fails, you are making a potentially incompatible change to `SnapshotSource`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        let actual_variants: Vec<i32> = SnapshotSource::iter()
            .map(|x| pb_canister_state_bits::SnapshotSource::from(x) as i32)
            .collect();
        let expected_variants = vec![1, 2];
        assert_eq!(actual_variants, expected_variants);
    }

    #[test]
    fn compatibility_for_on_low_wasm_memory_hook_status() {
        // If this fails, you are making a potentially incompatible change to `OnLowWasmMemoryHookStatus`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        let actual_variants: Vec<i32> = OnLowWasmMemoryHookStatus::iter()
            .map(|x| x as i32)
            .collect();
        let expected_variants = vec![0, 1, 2];
        assert_eq!(actual_variants, expected_variants);
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
                        "Deserialize error: The number of elements exceeds maximum allowed {MAX_ALLOWED_CONTROLLERS_COUNT}"
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
            assert_eq!(format!("{curve}").parse::<EcdsaCurve>().unwrap(), curve);
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
                assert_eq!(format!("{key}").parse::<EcdsaKeyId>().unwrap(), key);
            }
        }
    }

    #[test]
    fn schnorr_algorithm_round_trip() {
        for algorithm in SchnorrAlgorithm::iter() {
            assert_eq!(
                format!("{algorithm}").parse::<SchnorrAlgorithm>().unwrap(),
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
                assert_eq!(format!("{key}").parse::<SchnorrKeyId>().unwrap(), key);
            }
        }
    }

    #[test]
    fn vetkd_curve_round_trip() {
        for curve in VetKdCurve::iter() {
            assert_eq!(format!("{curve}").parse::<VetKdCurve>().unwrap(), curve);
        }
    }

    #[test]
    fn vetkd_key_id_round_trip() {
        for curve in VetKdCurve::iter() {
            for name in ["bls12_381_g2", "", "other_key", "other key", "other:key"] {
                let key = VetKdKeyId {
                    curve,
                    name: name.to_string(),
                };
                assert_eq!(format!("{key}").parse::<VetKdKeyId>().unwrap(), key);
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
                assert_eq!(format!("{key}").parse::<MasterPublicKeyId>().unwrap(), key);
            }
        }

        for curve in EcdsaCurve::iter() {
            for name in ["secp256k1", "", "other_key", "other key", "other:key"] {
                let key = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve,
                    name: name.to_string(),
                });
                assert_eq!(format!("{key}").parse::<MasterPublicKeyId>().unwrap(), key);
            }
        }

        for curve in VetKdCurve::iter() {
            for name in ["bls12_381_g2", "", "other_key", "other key", "other:key"] {
                let key = MasterPublicKeyId::VetKd(VetKdKeyId {
                    curve,
                    name: name.to_string(),
                });
                assert_eq!(format!("{key}").parse::<MasterPublicKeyId>().unwrap(), key);
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
                    "Deserialize error: The number of elements exceeds maximum allowed {MAXIMUM_DERIVATION_PATH_LENGTH}"
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
                    "Deserialize error: The number of elements exceeds maximum allowed {MAXIMUM_DERIVATION_PATH_LENGTH}"
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
                    "Deserialize error: The number of elements exceeds maximum allowed {MAXIMUM_DERIVATION_PATH_LENGTH}"
                )),
                "Actual: {}",
                result.description()
            );
        }
    }

    #[test]
    fn canister_change_count_bytes() {
        let change_bytes = |controllers| {
            let timestamp_nanos = 0;
            let canister_version = 0;
            let origin = CanisterChangeOrigin::from_canister(PrincipalId::default(), Some(0));
            let details = CanisterChangeDetails::canister_creation(controllers, None);
            let change = CanisterChange::new(timestamp_nanos, canister_version, origin, details);
            change.count_bytes()
        };

        assert_eq!(size_of::<PrincipalId>(), 30);
        let controllers = vec![PrincipalId::default(); 2];
        let num_controllers = controllers.len() as u64;
        assert_eq!(
            change_bytes(controllers),
            change_bytes(vec![]) + NumBytes::new(num_controllers * 30)
        );
    }
}
