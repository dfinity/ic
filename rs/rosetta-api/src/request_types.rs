use crate::models::amount::{signed_amount, tokens_to_amount};
use crate::models::operation::OperationType;
use crate::models::seconds::Seconds;
use crate::models::OperationIdentifier;
use crate::{
    convert::to_model_account_identifier,
    errors::ApiError,
    models::{self, Operation},
    transaction_id::TransactionIdentifier,
};
pub use ic_ledger_canister_blocks_synchronizer::blocks::RosettaBlocksMode;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, BlockIndex, Operation as LedgerOperation, Tokens};
use rosetta_core::convert::principal_id_from_public_key;
use rosetta_core::objects::ObjectMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

// Since our blockchain doesn't have smart contracts all operations are always a
// single value
pub const STATUS_COMPLETED: &str = "COMPLETED";

pub const TRANSACTION: &str = "TRANSACTION";
pub const MINT: &str = "MINT";
pub const BURN: &str = "BURN";
pub const FEE: &str = "FEE";
pub const STAKE: &str = "STAKE";
pub const START_DISSOLVE: &str = "START_DISSOLVE";
pub const STOP_DISSOLVE: &str = "STOP_DISSOLVE";
pub const SET_DISSOLVE_TIMESTAMP: &str = "SET_DISSOLVE_TIMESTAMP";
pub const CHANGE_AUTO_STAKE_MATURITY: &str = "CHANGE_AUTO_STAKE_MATURITY";
pub const DISBURSE: &str = "DISBURSE";
pub const DISSOLVE_TIME_UTC_SECONDS: &str = "dissolve_time_utc_seconds";
pub const ADD_HOT_KEY: &str = "ADD_HOT_KEY";
pub const REMOVE_HOTKEY: &str = "REMOVE_HOTKEY";
pub const SPAWN: &str = "SPAWN";
pub const MERGE_MATURITY: &str = "MERGE_MATURITY";
pub const REGISTER_VOTE: &str = "REGISTER_VOTE";
pub const STAKE_MATURITY: &str = "STAKE_MATURITY";
pub const NEURON_INFO: &str = "NEURON_INFO";
pub const LIST_NEURONS: &str = "LIST_NEURONS";
pub const FOLLOW: &str = "FOLLOW";

/// `RequestType` contains all supported values of `Operation.type`.
/// Extra information, such as `neuron_index` should only be included
/// if it cannot be parsed from the submit payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum RequestType {
    // Aliases for backwards compatibility
    #[serde(rename = "TRANSACTION")]
    #[serde(alias = "Send")]
    Send,
    #[serde(rename = "STAKE")]
    #[serde(alias = "Stake")]
    Stake { neuron_index: u64 },
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    #[serde(alias = "SetDissolveTimestamp")]
    SetDissolveTimestamp { neuron_index: u64 },
    #[serde(rename = "CHANGE_AUTO_STAKE_MATURITY")]
    #[serde(alias = "ChangeAutoStakeMaturity")]
    ChangeAutoStakeMaturity { neuron_index: u64 },
    #[serde(rename = "START_DISSOLVE")]
    #[serde(alias = "StartDissolve")]
    StartDissolve { neuron_index: u64 },
    #[serde(rename = "STOP_DISSOLVE")]
    #[serde(alias = "StopDissolve")]
    StopDissolve { neuron_index: u64 },
    #[serde(rename = "DISBURSE")]
    #[serde(alias = "Disperse")]
    Disburse { neuron_index: u64 },
    #[serde(rename = "ADD_HOT_KEY")]
    #[serde(alias = "AddHotKey")]
    AddHotKey { neuron_index: u64 },
    #[serde(rename = "REMOVE_HOTKEY")]
    #[serde(alias = "RemoveHotKey")]
    RemoveHotKey { neuron_index: u64 },
    #[serde(rename = "SPAWN")]
    #[serde(alias = "Spawn")]
    Spawn { neuron_index: u64 },
    #[serde(rename = "MERGE_MATURITY")]
    #[serde(alias = "MergeMaturity")]
    MergeMaturity { neuron_index: u64 },
    #[serde(rename = "STAKE_MATURITY")]
    #[serde(alias = "StakeMaturity")]
    StakeMaturity { neuron_index: u64 },
    #[serde(rename = "REGISTER_VOTE")]
    #[serde(alias = "RegisterVote")]
    RegisterVote { neuron_index: u64 },
    #[serde(rename = "NEURON_INFO")]
    #[serde(alias = "NeuronInfo")]
    NeuronInfo {
        neuron_index: u64,
        controller: Option<PublicKeyOrPrincipal>,
    },
    #[serde(rename = "LIST_NEURONS")]
    #[serde(alias = "ListNeurons")]
    ListNeurons,
    #[serde(rename = "FOLLOW")]
    #[serde(alias = "Follow")]
    Follow {
        neuron_index: u64,
        controller: Option<PublicKeyOrPrincipal>,
    },
}

impl RequestType {
    pub fn into_str(self) -> &'static str {
        match self {
            RequestType::Send { .. } => TRANSACTION,
            RequestType::Stake { .. } => STAKE,
            RequestType::SetDissolveTimestamp { .. } => SET_DISSOLVE_TIMESTAMP,
            RequestType::ChangeAutoStakeMaturity { .. } => CHANGE_AUTO_STAKE_MATURITY,
            RequestType::StartDissolve { .. } => START_DISSOLVE,
            RequestType::StopDissolve { .. } => STOP_DISSOLVE,
            RequestType::Disburse { .. } => DISBURSE,
            RequestType::AddHotKey { .. } => ADD_HOT_KEY,
            RequestType::RemoveHotKey { .. } => REMOVE_HOTKEY,
            RequestType::Spawn { .. } => SPAWN,
            RequestType::MergeMaturity { .. } => MERGE_MATURITY,
            RequestType::RegisterVote { .. } => REGISTER_VOTE,
            RequestType::StakeMaturity { .. } => STAKE_MATURITY,
            RequestType::NeuronInfo { .. } => NEURON_INFO,
            RequestType::ListNeurons { .. } => LIST_NEURONS,
            RequestType::Follow { .. } => FOLLOW,
        }
    }

    pub const fn is_transfer(&self) -> bool {
        matches!(self, RequestType::Send)
    }

    pub const fn is_neuron_management(&self) -> bool {
        matches!(
            self,
            RequestType::Stake { .. }
                | RequestType::SetDissolveTimestamp { .. }
                | RequestType::ChangeAutoStakeMaturity { .. }
                | RequestType::StartDissolve { .. }
                | RequestType::StopDissolve { .. }
                | RequestType::Disburse { .. }
                | RequestType::AddHotKey { .. }
                | RequestType::RemoveHotKey { .. }
                | RequestType::Spawn { .. }
                | RequestType::MergeMaturity { .. }
                | RequestType::RegisterVote { .. }
                | RequestType::StakeMaturity { .. }
                | RequestType::NeuronInfo { .. }
                | RequestType::ListNeurons { .. }
                | RequestType::Follow { .. }
        )
    }
}

impl TryFrom<RequestResultMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: RequestResultMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert RequestResultMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert RequestResultMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RequestResultMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub block_index: Option<BlockIndex>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub neuron_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub transaction_identifier: Option<TransactionIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub response: Option<models::Error>,
}

impl TryFrom<Option<ObjectMap>> for RequestResultMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `neuron_identifier` from metadata JSON object: {}",
                e
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(tag = "status", content = "response")]
pub enum Status {
    Completed,
    // TODO detect already applied.
    AlreadyApplied,
    Failed(ApiError),
    NotAttempted,
}

impl Status {
    pub fn failed(&self) -> Option<&ApiError> {
        match self {
            Status::Failed(e) => Some(e),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Status::Completed => "COMPLETED",
            Status::AlreadyApplied => "ALREADY_APPLIED",
            Status::Failed(_) => "FAILED",
            Status::NotAttempted => "NOT_ATTEMPTED",
        }
    }

    pub fn from_name(n: &str) -> Option<Self> {
        match n {
            "COMPLETED" => Some(Status::Completed),
            "ALREADY_APPLIED" => Some(Status::AlreadyApplied),
            "NOT_ATTEMPTED" => Some(Status::NotAttempted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GetProposalInfo {
    #[serde(default)]
    pub proposal_id: u64,
}

impl TryFrom<GetProposalInfo> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: GetProposalInfo) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert GetProposalInfo to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert GetProposalInfo to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for GetProposalInfo {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `proposal_id` from metadata JSON object: {}",
                e
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SetDissolveTimestamp {
    pub account: icp_ledger::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    /// The number of seconds since Unix epoch.
    pub timestamp: Seconds,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ChangeAutoStakeMaturity {
    pub account: icp_ledger::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    pub requested_setting_for_auto_stake_maturity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StartDissolve {
    pub account: icp_ledger::AccountIdentifier,
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StopDissolve {
    pub account: icp_ledger::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Stake {
    pub account: icp_ledger::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Disburse {
    pub account: icp_ledger::AccountIdentifier,
    pub amount: Option<Tokens>,
    pub recipient: Option<icp_ledger::AccountIdentifier>,
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct AddHotKey {
    pub account: icp_ledger::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    pub key: PublicKeyOrPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct RemoveHotKey {
    pub account: icp_ledger::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    pub key: PublicKeyOrPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Spawn {
    pub account: icp_ledger::AccountIdentifier,
    pub spawned_neuron_index: u64,
    pub controller: Option<PrincipalId>,
    pub percentage_to_spawn: Option<u32>,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeMaturity {
    pub account: icp_ledger::AccountIdentifier,
    pub percentage_to_merge: u32,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RegisterVote {
    pub account: icp_ledger::AccountIdentifier,
    pub proposal: Option<u64>,
    pub vote: i32,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StakeMaturity {
    pub account: icp_ledger::AccountIdentifier,
    pub percentage_to_stake: Option<u32>,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NeuronInfo {
    pub account: icp_ledger::AccountIdentifier,
    pub controller: Option<PrincipalId>,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ListNeurons {
    pub account: icp_ledger::AccountIdentifier,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Follow {
    pub account: icp_ledger::AccountIdentifier,
    pub topic: i32,
    pub followees: Vec<u64>,
    pub controller: Option<PrincipalId>,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
// Externally tagged by default.
pub enum PublicKeyOrPrincipal {
    PublicKey(models::PublicKey),
    Principal(PrincipalId),
}

impl TryFrom<&PublicKeyOrPrincipal> for PrincipalId {
    type Error = ApiError;
    fn try_from(p: &PublicKeyOrPrincipal) -> Result<PrincipalId, ApiError> {
        match p {
            PublicKeyOrPrincipal::PublicKey(pk) => principal_id_from_public_key(pk)
                .map_err(|err| ApiError::InvalidPublicKey(false, err.into())),
            PublicKeyOrPrincipal::Principal(pid) => Ok(*pid),
        }
    }
}

/// Comparisons are done on the normalized representation PrincipalId.
/// This is needed for testing.
impl PartialEq for PublicKeyOrPrincipal {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PublicKeyOrPrincipal::PublicKey(pk0), PublicKeyOrPrincipal::PublicKey(pk1)) => {
                pk0 == pk1
            }
            _ => PrincipalId::try_from(self) == PrincipalId::try_from(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SetDissolveTimestampMetadata {
    #[serde(default)]
    pub neuron_index: u64,
    #[serde(rename = "dissolve_time_utc_seconds")]
    /// The number of seconds since Unix epoch.
    pub timestamp: Seconds,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ChangeAutoStakeMaturityMetadata {
    #[serde(default)]
    pub neuron_index: u64,
    #[serde(rename = "set_auto_stake_maturity")]
    pub requested_setting_for_auto_stake_maturity: bool,
}

impl TryFrom<ChangeAutoStakeMaturityMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ChangeAutoStakeMaturityMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ChangeAutoStakeMaturityMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ChangeAutoStakeMaturityMetadata to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for ChangeAutoStakeMaturityMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `neuron_index` from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<SetDissolveTimestampMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: SetDissolveTimestampMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert SetDissolveTimestampMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert SetDissolveTimestampMetadata to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for SetDissolveTimestampMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Set Dissolve Timestamp operation must have a 'dissolve_time_utc_seconds' metadata field.
                 The timestamp is a number of seconds since the Unix epoch.
                 This is represented as an unsigned 64 bit integer and encoded as a JSON string.

                 A Set Dissolve Timestamp operation may have a 'neuron_index' metadata field.
                 The 'neuron_index` field differentiates between neurons controlled by the user.

                 Parse Error: {}",
                e
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize)]
pub struct NeuronIdentifierMetadata {
    #[serde(default)]
    pub neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for NeuronIdentifierMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `neuron_index` from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<NeuronIdentifierMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: NeuronIdentifierMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert NeuronIdentifierMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert NeuronIdentifierMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct DisburseMetadata {
    #[serde(default)]
    pub neuron_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub recipient: Option<AccountIdentifier>,
}

impl TryFrom<Option<ObjectMap>> for DisburseMetadata {
    type Error = ApiError;

    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse DISBURSE operation metadata from a JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<DisburseMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: DisburseMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert DisburseMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert DisburseMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct KeyMetadata {
    #[serde(flatten)]
    pub key: PublicKeyOrPrincipal,
    #[serde(default)]
    pub neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for KeyMetadata {
    type Error = ApiError;

    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse hot key management operation metadata from a JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<KeyMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: KeyMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert KeyMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert KeyMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[test]
fn test_parse_key_metadata() {
    use std::str::FromStr;

    let m1: KeyMetadata = serde_json::from_str(
        r#"{ "principal" : "sp3em-jkiyw-tospm-2huim-jor4p-et4s7-ay35f-q7tnm-hi4k2-pyicb-xae" }"#,
    )
    .unwrap();
    assert_eq!(
        m1,
        KeyMetadata {
            neuron_index: 0,
            key: PublicKeyOrPrincipal::Principal(
                PrincipalId::from_str(
                    "sp3em-jkiyw-tospm-2huim-jor4p-et4s7-ay35f-q7tnm-hi4k2-pyicb-xae"
                )
                .unwrap()
            ),
        }
    );

    let m2: KeyMetadata = serde_json::from_str(
        r#"{ "public_key": {
          "hex_bytes":  "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f",
          "curve_type": "edwards25519"
        } }"#,
    )
    .unwrap();
    assert_eq!(
        m2,
        KeyMetadata {
            neuron_index: 0,
            key: PublicKeyOrPrincipal::PublicKey(models::PublicKey {
                hex_bytes: "1b400d60aaf34eaf6dcbab9bba46001a23497886cf11066f7846933d30e5ad3f"
                    .to_string(),
                curve_type: models::CurveType::Edwards25519
            }),
        }
    );
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct SpawnMetadata {
    #[serde(default)]
    #[serde(rename = "neuron_index")]
    pub neuron_index: u64,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<PublicKeyOrPrincipal>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage_to_spawn: Option<u32>,

    #[serde(rename = "spawned_neuron_index")]
    pub spawned_neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for SpawnMetadata {
    type Error = ApiError;

    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse SPAWN operation metadata from a JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<SpawnMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: SpawnMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert SpawnMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert SpawnMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct RegisterVoteMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal: Option<u64>,
    pub vote: i32,
    pub neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for RegisterVoteMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse REGISTER_VOTE operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<RegisterVoteMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: RegisterVoteMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert RegisterVoteMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert RegisterVoteMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct MergeMaturityMetadata {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage_to_merge: Option<u32>,
    #[serde(default)]
    pub neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for MergeMaturityMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse MERGE_MATURITY operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<MergeMaturityMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: MergeMaturityMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert MergeMaturityMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert MergeMaturityMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct StakeMaturityMetadata {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage_to_stake: Option<u32>,
    #[serde(default)]
    pub neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for StakeMaturityMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse STAKE_MATURITY operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<StakeMaturityMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: StakeMaturityMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert StakeMaturityMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert StakeMaturityMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct NeuronInfoMetadata {
    pub controller: Option<PublicKeyOrPrincipal>,
    #[serde(default)]
    pub neuron_index: u64,
}

impl TryFrom<PublicKeyOrPrincipal> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: PublicKeyOrPrincipal) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert PublicKeyOrPrincipal to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert PublicKeyOrPrincipal to ObjectMap: {:?}",err))),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for NeuronInfoMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse NEURON_INFO operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

#[test]
fn test_parse_neuron_info_metadata_public_key() {
    let m1 = r#"
            {
                "controller": {
                    "public_key": {
                        "hex_bytes": "ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d",
                        "curve_type": "edwards25519"
                     }
                },
                "neuron_index": 123456
            }
        "#;
    let m1: NeuronInfoMetadata = serde_json::from_str(m1).unwrap();
    assert_eq!(
        m1,
        NeuronInfoMetadata {
            neuron_index: 123456,
            controller: Some(PublicKeyOrPrincipal::PublicKey(models::PublicKey::new(
                "ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d"
                    .parse()
                    .unwrap(),
                models::CurveType::Edwards25519
            )))
        }
    );
}

#[test]
fn test_parse_neuron_info_metadata_principal() {
    use std::str::FromStr;
    let m1 = r#"
            {
                "controller": {
                    "principal": "4auul-2ca7l-khhsk-dcyds-qnj57-cc3ko-h3j6b-jcszz-nsjn4-ab2zb-oqe"
                },
                "neuron_index": 123456
            }
        "#;
    let m1: NeuronInfoMetadata = serde_json::from_str(m1).unwrap();
    let pid =
        PrincipalId::from_str("4auul-2ca7l-khhsk-dcyds-qnj57-cc3ko-h3j6b-jcszz-nsjn4-ab2zb-oqe")
            .expect("Invalid PrincipalId");
    assert_eq!(
        m1,
        NeuronInfoMetadata {
            neuron_index: 123456,
            controller: Some(PublicKeyOrPrincipal::Principal(pid))
        }
    );
}

impl TryFrom<NeuronInfoMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: NeuronInfoMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert NeuronInfoMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert NeuronInfoMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct FollowMetadata {
    pub topic: i32,
    pub followees: Vec<u64>,
    pub controller: Option<PublicKeyOrPrincipal>,
    #[serde(default)]
    pub neuron_index: u64,
}

impl TryFrom<Option<ObjectMap>> for FollowMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a FOLLOW operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<FollowMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: FollowMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert FollowMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert FollowMetadata to ObjectMap: {:?}",err))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ApproveMetadata {
    pub from: AccountIdentifier,
    pub spender: AccountIdentifier,
    pub allowance: Tokens,
    pub expected_allowance: Option<Tokens>,
    pub expires_at: Option<u64>,
}

impl TryFrom<Option<ObjectMap>> for ApproveMetadata {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a Approve operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl TryFrom<ApproveMetadata> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ApproveMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ApproveMetadata to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ApproveMetadata to ObjectMap: {:?}",err))),
        }
    }
}

/// Transaction is a bit of a misnomer, since operations can succeed or fail
/// independently from a Transaction.
#[derive(Default)]
pub struct TransactionBuilder {
    /// The next `OperationIdentifier` `index`.
    /// TODO Why is `OperationIdentifier.index` a signed integer?
    op_index: u64,
    ops: Vec<Operation>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> Vec<Operation> {
        self.ops
    }

    pub fn allocate_op_id(&mut self) -> OperationIdentifier {
        let id = OperationIdentifier::new(self.op_index);
        self.op_index += 1;
        id
    }

    /// Add a `Request::Transfer` to the Transaction.
    /// This handles `Send`, `Mint`, `Approve` and `Burn`.
    pub fn transfer(
        &mut self,
        operation: &LedgerOperation,
        token_name: &str,
    ) -> Result<(), ApiError> {
        let mut push_op = |_type: OperationType,
                           account: Option<crate::models::AccountIdentifier>,
                           amount: Option<crate::models::Amount>,
                           metadata: Option<ObjectMap>| {
            let operation_identifier = self.allocate_op_id();
            self.ops.push(Operation {
                operation_identifier,
                type_: _type.to_string(),
                status: None,
                account,
                amount,
                related_operations: None,
                coin_change: None,
                metadata,
            });
        };

        match operation {
            LedgerOperation::Burn { from, amount, .. } => {
                push_op(
                    OperationType::Burn,
                    Some(to_model_account_identifier(from)),
                    Some(signed_amount(-i128::from(amount.get_e8s()), token_name)),
                    None,
                );
            }
            LedgerOperation::Mint { to, amount } => {
                push_op(
                    OperationType::Mint,
                    Some(to_model_account_identifier(to)),
                    Some(signed_amount(i128::from(amount.get_e8s()), token_name)),
                    None,
                );
            }
            LedgerOperation::Approve {
                from,
                spender,
                fee,
                allowance,
                expected_allowance,
                expires_at,
            } => {
                push_op(
                    OperationType::Approve,
                    Some(to_model_account_identifier(from)),
                    None,
                    Some(
                        ApproveMetadata {
                            from: *from,
                            allowance: *allowance,
                            spender: *spender,
                            expected_allowance: *expected_allowance,
                            expires_at: expires_at.map(|ts| ts.as_nanos_since_unix_epoch()),
                        }
                        .try_into()?,
                    ),
                );
                push_op(
                    OperationType::Fee,
                    Some(to_model_account_identifier(from)),
                    Some(signed_amount(-i128::from(fee.get_e8s()), token_name)),
                    None,
                );
            }
            LedgerOperation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
            } => {
                let amount = i128::from(amount.get_e8s());
                push_op(
                    OperationType::Transaction,
                    Some(to_model_account_identifier(from)),
                    Some(signed_amount(-amount, token_name)),
                    None,
                );
                push_op(
                    OperationType::Transaction,
                    Some(to_model_account_identifier(to)),
                    Some(signed_amount(amount, token_name)),
                    None,
                );
                push_op(
                    OperationType::Fee,
                    Some(to_model_account_identifier(from)),
                    Some(signed_amount(-i128::from(fee.get_e8s()), token_name)),
                    None,
                );
            }
        };
        Ok(())
    }

    pub fn stake(&mut self, stake: &Stake) -> Result<(), ApiError> {
        let Stake {
            account,
            neuron_index,
        } = stake;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::Stake.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn set_dissolve_timestamp(
        &mut self,
        set_dissolve: &SetDissolveTimestamp,
    ) -> Result<(), ApiError> {
        let SetDissolveTimestamp {
            account,
            neuron_index,
            timestamp,
        } = set_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::SetDissolveTimestamp.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                SetDissolveTimestampMetadata {
                    neuron_index: *neuron_index,
                    timestamp: *timestamp,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn change_auto_stake_maturity(
        &mut self,
        setting_for_auto_stake_maturity: &ChangeAutoStakeMaturity,
    ) -> Result<(), ApiError> {
        let ChangeAutoStakeMaturity {
            account,
            neuron_index,
            requested_setting_for_auto_stake_maturity,
        } = setting_for_auto_stake_maturity;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::ChangeAutoStakeMaturity.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                ChangeAutoStakeMaturityMetadata {
                    neuron_index: *neuron_index,
                    requested_setting_for_auto_stake_maturity:
                        *requested_setting_for_auto_stake_maturity,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn start_dissolve(&mut self, start_dissolve: &StartDissolve) -> Result<(), ApiError> {
        let StartDissolve {
            account,
            neuron_index,
        } = start_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::StartDissolving.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn stop_dissolve(&mut self, stop_dissolve: &StopDissolve) -> Result<(), ApiError> {
        let StopDissolve {
            account,
            neuron_index,
        } = stop_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::StopDissolving.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn disburse(&mut self, disburse: &Disburse, token_name: &str) -> Result<(), ApiError> {
        let Disburse {
            account,
            amount,
            recipient,
            neuron_index,
        } = disburse;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::Disburse.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: amount
                .map(|a| tokens_to_amount(a, token_name).expect("failed to convert amount")),
            related_operations: None,
            coin_change: None,
            metadata: Some(
                DisburseMetadata {
                    recipient: *recipient,
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }
    pub fn add_hot_key(&mut self, key: &AddHotKey) -> Result<(), ApiError> {
        let AddHotKey {
            account,
            neuron_index,
            key,
        } = key;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::AddHotkey.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                KeyMetadata {
                    key: key.clone(),
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }
    pub fn remove_hotkey(&mut self, key: &RemoveHotKey) -> Result<(), ApiError> {
        let RemoveHotKey {
            account,
            neuron_index,
            key,
        } = key;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::RemoveHotkey.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                KeyMetadata {
                    key: key.clone(),
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }
    pub fn spawn(&mut self, spawn: &Spawn) -> Result<(), ApiError> {
        let Spawn {
            account,
            spawned_neuron_index,
            controller,
            percentage_to_spawn,
            neuron_index,
        } = spawn;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::Spawn.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                SpawnMetadata {
                    controller: controller.map(PublicKeyOrPrincipal::Principal),
                    neuron_index: *neuron_index,
                    percentage_to_spawn: *percentage_to_spawn,
                    spawned_neuron_index: *spawned_neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn register_vote(&mut self, register_vote: &RegisterVote) -> Result<(), ApiError> {
        let RegisterVote {
            account,
            proposal,
            vote,
            neuron_index,
        } = register_vote;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::RegisterVote.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                RegisterVoteMetadata {
                    proposal: *proposal,
                    vote: *vote,
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn merge_maturity(&mut self, merge: &MergeMaturity) -> Result<(), ApiError> {
        let MergeMaturity {
            account,
            percentage_to_merge,
            neuron_index,
        } = merge;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::MergeMaturity.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                MergeMaturityMetadata {
                    percentage_to_merge: Option::from(*percentage_to_merge),
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn stake_maturity(&mut self, stake: &StakeMaturity) -> Result<(), ApiError> {
        let StakeMaturity {
            account,
            percentage_to_stake,
            neuron_index,
        } = stake;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::StakeMaturity.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                StakeMaturityMetadata {
                    percentage_to_stake: *percentage_to_stake,
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn neuron_info(&mut self, req: &NeuronInfo) -> Result<(), ApiError> {
        let NeuronInfo {
            account,
            controller,
            neuron_index,
        } = req;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::NeuronInfo.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronInfoMetadata {
                    controller: pkp_from_principal(controller),
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }

    pub fn list_neurons(&mut self, req: &ListNeurons) -> Result<(), ApiError> {
        let ListNeurons { account } = req;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::ListNeurons.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: None,
        });
        Ok(())
    }

    pub fn follow(&mut self, follow: &Follow) -> Result<(), ApiError> {
        let Follow {
            account,
            topic,
            followees,
            controller,
            neuron_index,
        } = follow;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            type_: OperationType::Follow.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                FollowMetadata {
                    topic: *topic,
                    followees: followees.clone(),
                    controller: pkp_from_principal(controller),
                    neuron_index: *neuron_index,
                }
                .try_into()?,
            ),
        });
        Ok(())
    }
}

/// Converts an optional PrincipalId to an optional PublicKeyOrPrincipal.
fn pkp_from_principal(pid: &Option<PrincipalId>) -> Option<PublicKeyOrPrincipal> {
    pid.as_ref().map(|p| PublicKeyOrPrincipal::Principal(*p))
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RosettaStatus {
    pub rosetta_blocks_mode: RosettaBlocksMode,
}
