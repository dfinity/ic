use crate::models::amount::{signed_amount, tokens_to_amount};
use crate::models::operation::{OperationIdentifier, OperationType};
use crate::models::seconds::Seconds;
use crate::{
    convert::{principal_id_from_public_key, to_model_account_identifier},
    errors::ApiError,
    models::{self, operation::Operation, Object},
    transaction_id::TransactionIdentifier,
};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, BlockHeight, Operation as LedgerOperation, Tokens};
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
pub const DISBURSE: &str = "DISBURSE";
pub const DISSOLVE_TIME_UTC_SECONDS: &str = "dissolve_time_utc_seconds";
pub const ADD_HOT_KEY: &str = "ADD_HOT_KEY";
pub const REMOVE_HOTKEY: &str = "REMOVE_HOTKEY";
pub const SPAWN: &str = "SPAWN";
pub const MERGE_MATURITY: &str = "MERGE_MATURITY";
pub const NEURON_INFO: &str = "NEURON_INFO";
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
    #[serde(rename = "NEURON_INFO")]
    #[serde(alias = "NeuronInfo")]
    NeuronInfo {
        neuron_index: u64,
        controller: Option<PublicKeyOrPrincipal>,
    },
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
            RequestType::StartDissolve { .. } => START_DISSOLVE,
            RequestType::StopDissolve { .. } => STOP_DISSOLVE,
            RequestType::Disburse { .. } => DISBURSE,
            RequestType::AddHotKey { .. } => ADD_HOT_KEY,
            RequestType::RemoveHotKey { .. } => REMOVE_HOTKEY,
            RequestType::Spawn { .. } => SPAWN,
            RequestType::MergeMaturity { .. } => MERGE_MATURITY,
            RequestType::NeuronInfo { .. } => NEURON_INFO,
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
                | RequestType::StartDissolve { .. }
                | RequestType::StopDissolve { .. }
                | RequestType::Disburse { .. }
                | RequestType::AddHotKey { .. }
                | RequestType::RemoveHotKey { .. }
                | RequestType::Spawn { .. }
                | RequestType::MergeMaturity { .. }
                | RequestType::NeuronInfo { .. }
                | RequestType::Follow { .. }
        )
    }
}

impl From<RequestResultMetadata> for Object {
    fn from(d: RequestResultMetadata) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RequestResultMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub block_index: Option<BlockHeight>,
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

impl TryFrom<Option<Object>> for RequestResultMetadata {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
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
pub struct SetDissolveTimestamp {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    /// The number of seconds since Unix epoch.
    pub timestamp: Seconds,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StartDissolve {
    pub account: ledger_canister::AccountIdentifier,
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StopDissolve {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Stake {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Disburse {
    pub account: ledger_canister::AccountIdentifier,
    pub amount: Option<Tokens>,
    pub recipient: Option<ledger_canister::AccountIdentifier>,
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct AddHotKey {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    pub key: PublicKeyOrPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct RemoveHotKey {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_index: u64,
    pub key: PublicKeyOrPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Spawn {
    pub account: ledger_canister::AccountIdentifier,
    pub spawned_neuron_index: u64,
    pub controller: Option<PrincipalId>,
    pub percentage_to_spawn: Option<u32>,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeMaturity {
    pub account: ledger_canister::AccountIdentifier,
    pub percentage_to_merge: u32,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NeuronInfo {
    pub account: ledger_canister::AccountIdentifier,
    pub controller: Option<PrincipalId>,
    #[serde(default)]
    pub neuron_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Follow {
    pub account: ledger_canister::AccountIdentifier,
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
            PublicKeyOrPrincipal::PublicKey(pk) => principal_id_from_public_key(pk),
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

impl From<SetDissolveTimestampMetadata> for Object {
    fn from(m: SetDissolveTimestampMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Option<Object>> for SetDissolveTimestampMetadata {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
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

impl TryFrom<Option<Object>> for NeuronIdentifierMetadata {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `neuron_index` from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl From<NeuronIdentifierMetadata> for Object {
    fn from(m: NeuronIdentifierMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
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

impl TryFrom<Option<Object>> for DisburseMetadata {
    type Error = ApiError;

    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse DISBURSE operation metadata from a JSON object: {}",
                e
            ))
        })
    }
}
impl From<DisburseMetadata> for Object {
    fn from(m: DisburseMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
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

impl TryFrom<Option<Object>> for KeyMetadata {
    type Error = ApiError;

    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse hot key management operation metadata from a JSON object: {}",
                e
            ))
        })
    }
}

impl From<KeyMetadata> for Object {
    fn from(m: KeyMetadata) -> Self {
        match serde_json::to_value(&m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
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
    pub controller: Option<PrincipalId>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage_to_spawn: Option<u32>,

    #[serde(rename = "spawned_neuron_index")]
    pub spawned_neuron_index: u64,
}

impl TryFrom<Option<Object>> for SpawnMetadata {
    type Error = ApiError;

    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse SPAWN operation metadata from a JSON object: {}",
                e
            ))
        })
    }
}

impl From<SpawnMetadata> for Object {
    fn from(m: SpawnMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
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

impl TryFrom<Option<Object>> for MergeMaturityMetadata {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse MERGE_MATURITY operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl From<MergeMaturityMetadata> for Object {
    fn from(m: MergeMaturityMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct NeuronInfoMetadata {
    pub controller: Option<PublicKeyOrPrincipal>,
    #[serde(default)]
    pub neuron_index: u64,
}

impl From<PublicKeyOrPrincipal> for Object {
    fn from(p: PublicKeyOrPrincipal) -> Self {
        match serde_json::to_value(p) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Option<Object>> for NeuronInfoMetadata {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
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

impl From<NeuronInfoMetadata> for Object {
    fn from(m: NeuronInfoMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
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

impl TryFrom<Option<Object>> for FollowMetadata {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a FOLLOW operation metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl From<FollowMetadata> for Object {
    fn from(m: FollowMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

/// Transaction is a bit of a misnomer, since operations can succeed or fail
/// independently from a Transaction.
#[derive(Default)]
pub struct TransactionBuilder {
    /// The next `OperationIdentifier` `index`.
    /// TODO Why is `OperationIdentifier.index` a signed integer?
    op_index: i64,
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
    /// This handles `Send`, `Mint`, and `Burn`.
    pub fn transfer(
        &mut self,
        operation: &LedgerOperation,
        token_name: &str,
    ) -> Result<(), ApiError> {
        match operation {
            LedgerOperation::Burn { from, amount } => {
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: OperationType::Burn,
                    status: None,
                    account: Some(to_model_account_identifier(from)),
                    amount: Some(signed_amount(-i128::from(amount.get_e8s()), token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            LedgerOperation::Mint { to, amount } => {
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: OperationType::Mint,
                    status: None,
                    account: Some(to_model_account_identifier(to)),
                    amount: Some(tokens_to_amount(*amount, token_name)?),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            LedgerOperation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                let from_account = Some(to_model_account_identifier(from));
                let amount = i128::from(amount.get_e8s());

                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: OperationType::Transaction,
                    status: None,
                    account: from_account.clone(),
                    amount: Some(signed_amount(-amount, token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: OperationType::Transaction,
                    status: None,
                    account: Some(to_model_account_identifier(to)),
                    amount: Some(signed_amount(amount, token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: OperationType::Fee,
                    status: None,
                    account: from_account,
                    amount: Some(signed_amount(-(fee.get_e8s() as i128), token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
        };
        Ok(())
    }

    pub fn stake(&mut self, stake: &Stake) {
        let Stake {
            account,
            neuron_index,
        } = stake;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::Stake,
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index: *neuron_index,
                }
                .into(),
            ),
        });
    }

    pub fn set_dissolve_timestamp(&mut self, set_dissolve: &SetDissolveTimestamp) {
        let SetDissolveTimestamp {
            account,
            neuron_index,
            timestamp,
        } = set_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::SetDissolveTimestamp,
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
                .into(),
            ),
        });
    }

    pub fn start_dissolve(&mut self, start_dissolve: &StartDissolve) {
        let StartDissolve {
            account,
            neuron_index,
        } = start_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::StartDissolving,
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index: *neuron_index,
                }
                .into(),
            ),
        });
    }

    pub fn stop_dissolve(&mut self, stop_dissolve: &StopDissolve) {
        let StopDissolve {
            account,
            neuron_index,
        } = stop_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::StopDissolving,
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index: *neuron_index,
                }
                .into(),
            ),
        });
    }

    pub fn disburse(&mut self, disburse: &Disburse, token_name: &str) {
        let Disburse {
            account,
            amount,
            recipient,
            neuron_index,
        } = disburse;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::Disburse,
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
                .into(),
            ),
        });
    }
    pub fn add_hot_key(&mut self, key: &AddHotKey) {
        let AddHotKey {
            account,
            neuron_index,
            key,
        } = key;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::AddHotkey,
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
                .into(),
            ),
        });
    }
    pub fn remove_hotkey(&mut self, key: &RemoveHotKey) {
        let RemoveHotKey {
            account,
            neuron_index,
            key,
        } = key;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::RemoveHotkey,
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
                .into(),
            ),
        });
    }
    pub fn spawn(&mut self, spawn: &Spawn) {
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
            _type: OperationType::Spawn,
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                SpawnMetadata {
                    controller: *controller,
                    neuron_index: *neuron_index,
                    percentage_to_spawn: *percentage_to_spawn,
                    spawned_neuron_index: *spawned_neuron_index,
                }
                .into(),
            ),
        });
    }

    pub fn merge_maturity(&mut self, merge: &MergeMaturity) {
        let MergeMaturity {
            account,
            percentage_to_merge,
            neuron_index,
        } = merge;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::MergeMaturity,
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
                .into(),
            ),
        });
    }

    pub fn neuron_info(&mut self, req: &NeuronInfo) {
        let NeuronInfo {
            account,
            controller,
            neuron_index,
        } = req;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: OperationType::NeuronInfo,
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
                .into(),
            ),
        });
    }

    pub fn follow(&mut self, follow: &Follow) {
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
            _type: OperationType::Follow,
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
                .into(),
            ),
        });
    }
}

/// Converts an optional PrincipalId to an optional PublicKeyOrPrincipal.
fn pkp_from_principal(pid: &Option<PrincipalId>) -> Option<PublicKeyOrPrincipal> {
    pid.as_ref().map(|p| PublicKeyOrPrincipal::Principal(*p))
}
