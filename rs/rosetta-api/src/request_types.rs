use crate::{
    convert::{
        self, amount_, principal_id_from_public_key, signed_amount, to_model_account_identifier,
    },
    errors::ApiError,
    models::{self, Object, Operation, OperationIdentifier},
    time::Seconds,
    transaction_id::TransactionIdentifier,
};
use dfn_candid::CandidOne;
use ic_nns_governance::pb::v1::manage_neuron::{self, configure, Command, Configure};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, BlockHeight, Operation as LedgerOperation, Tokens};
use on_wire::FromWire;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::convert::{TryFrom, TryInto};

// Since our blockchain doesn't have smart contracts all operations are always a
// single value
pub const STATUS_COMPLETED: &str = "COMPLETED";

/// The operation associated with `Request::Transfer`.
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
pub const SPAWN: &str = "SPAWN";
pub const MERGE_MATURITY: &str = "MERGE_MATURITY";

/// `RequestType` contains all supported values of `Operation.type`.
/// Extra information, such as `neuron_index` should only be included
/// if it cannot be parsed from the submit payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
    #[serde(rename = "SPAWN")]
    #[serde(alias = "Spawn")]
    Spawn { neuron_index: u64 },
    #[serde(rename = "MERGE_MATURITY")]
    #[serde(alias = "MergeMaturity")]
    MergeMaturity { neuron_index: u64 },
}

impl RequestType {
    pub const fn into_str(self) -> &'static str {
        match self {
            RequestType::Send { .. } => TRANSACTION,
            RequestType::Stake { .. } => STAKE,
            RequestType::SetDissolveTimestamp { .. } => SET_DISSOLVE_TIMESTAMP,
            RequestType::StartDissolve { .. } => START_DISSOLVE,
            RequestType::StopDissolve { .. } => STOP_DISSOLVE,
            RequestType::Disburse { .. } => DISBURSE,
            RequestType::AddHotKey { .. } => ADD_HOT_KEY,
            RequestType::Spawn { .. } => SPAWN,
            RequestType::MergeMaturity { .. } => MERGE_MATURITY,
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
                | RequestType::Spawn { .. }
                | RequestType::MergeMaturity { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TransactionResults {
    pub operations: Vec<RequestResult>,
}

impl TransactionResults {
    pub fn retriable(&self) -> bool {
        self.operations
            .iter()
            .filter_map(|r| r.status.failed())
            .all(|e| e.retriable())
    }

    pub fn last_block_index(&self) -> Option<BlockHeight> {
        self.operations.iter().rev().find_map(|r| r.block_index)
    }

    pub fn last_transaction_id(&self) -> Option<&TransactionIdentifier> {
        self.operations
            .iter()
            .rev()
            .find_map(|r| r.transaction_identifier.as_ref())
    }

    /// Get the last failed Request error.
    /// There should only be one, since `construction_submit` stops
    /// when it encountered an error.
    pub fn error(&self) -> Option<&ApiError> {
        self.operations.iter().rev().find_map(|r| r.status.failed())
    }
}

impl From<TransactionResults> for Object {
    fn from(d: TransactionResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl From<&TransactionResults> for Object {
    fn from(d: &TransactionResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl TryFrom<Object> for TransactionResults {
    type Error = ApiError;
    fn try_from(o: Object) -> Result<Self, ApiError> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse RequestsResults from Object: {}",
                e
            ))
        })
    }
}

impl From<Vec<RequestResult>> for TransactionResults {
    fn from(operations: Vec<RequestResult>) -> Self {
        Self { operations }
    }
}

impl From<TransactionResults> for Vec<RequestResult> {
    fn from(r: TransactionResults) -> Self {
        r.operations
    }
}

impl From<TransactionResults> for ApiError {
    fn from(e: TransactionResults) -> Self {
        ApiError::OperationsErrors(e)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RequestResult {
    #[serde(rename = "type")]
    #[serde(flatten)]
    pub _type: Request,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub block_index: Option<BlockHeight>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub neuron_id: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub transaction_identifier: Option<TransactionIdentifier>,
    #[serde(flatten)]
    pub status: Status,
}

#[test]
fn request_result_serialization_test() {
    let account = AccountIdentifier::from(ic_types::PrincipalId::default());

    let neuron_index = 0;

    let rr = RequestResult {
        _type: Request::Stake(Stake {
            account,
            neuron_index,
        }),
        block_index: None,
        neuron_id: None,
        transaction_identifier: None,
        status: Status::Failed(ApiError::internal_error("foo")),
    };

    let se = serde_json::to_string(&rr).unwrap();
    let de: RequestResult = serde_json::from_str(&se).unwrap();
    let s = serde_json::from_str(
        r#"{
        "type":"STAKE",
        "account":"2d0e897f7e862d2b57d9bc9ea5c65f9a24ac6c074575f47898314b8d6cb0929d",
        "status":"FAILED",
        "response":{
            "code":700,
            "message":"Internal server error",
            "retriable":false,
            "details":{"error_message":"foo"}
        }
    }"#,
    )
    .unwrap();

    assert_eq!(rr, de);
    assert_eq!(rr, s);

    let rr = RequestResult {
        _type: Request::Stake(Stake {
            account,
            neuron_index,
        }),
        block_index: None,
        neuron_id: Some(5757483),
        transaction_identifier: None,
        status: Status::Completed,
    };

    let se = serde_json::to_string(&rr).unwrap();
    let de: RequestResult = serde_json::from_str(&se).unwrap();
    let s = serde_json::from_str(
        r#"{
        "type":"STAKE",
        "account":"2d0e897f7e862d2b57d9bc9ea5c65f9a24ac6c074575f47898314b8d6cb0929d",
        "neuron_id":5757483,
        "status":"COMPLETED"
    }"#,
    )
    .unwrap();

    assert_eq!(rr, de);
    assert_eq!(rr, s);
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
}

/// A `Request` is the deserialized representation of an `Operation`,
/// sans the `operation_identifier`, and `FEE` Operations.
/// Multiple `Request`s can be converted to `Operation`s via the
/// `TransactionBuilder`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Contains `Send`, `Mint`, and `Burn` operations.
    /// Attempting to serialize or deserialize any Mint, or Burn will error.
    #[serde(rename = "TRANSACTION")]
    #[serde(with = "send")]
    Transfer(LedgerOperation),
    #[serde(rename = "STAKE")]
    Stake(Stake),
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    SetDissolveTimestamp(SetDissolveTimestamp),
    #[serde(rename = "START_DISSOLVE")]
    StartDissolve(StartDissolve),
    #[serde(rename = "STOP_DISSOLVE")]
    StopDissolve(StopDissolve),
    #[serde(rename = "DISBURSE")]
    Disburse(Disburse),
    #[serde(rename = "ADD_HOT_KEY")]
    AddHotKey(AddHotKey),
    #[serde(rename = "SPAWN")]
    Spawn(Spawn),
    #[serde(rename = "MERGE_MATURITY")]
    MergeMaturity(MergeMaturity),
}

impl Request {
    pub fn request_type(&self) -> Result<RequestType, ApiError> {
        match self {
            Request::Stake(Stake { neuron_index, .. }) => Ok(RequestType::Stake {
                neuron_index: *neuron_index,
            }),
            Request::SetDissolveTimestamp(SetDissolveTimestamp { neuron_index, .. }) => {
                Ok(RequestType::SetDissolveTimestamp {
                    neuron_index: *neuron_index,
                })
            }
            Request::StartDissolve(StartDissolve { neuron_index, .. }) => {
                Ok(RequestType::StartDissolve {
                    neuron_index: *neuron_index,
                })
            }
            Request::StopDissolve(StopDissolve { neuron_index, .. }) => {
                Ok(RequestType::StopDissolve {
                    neuron_index: *neuron_index,
                })
            }
            Request::Disburse(Disburse { neuron_index, .. }) => Ok(RequestType::Disburse {
                neuron_index: *neuron_index,
            }),
            Request::AddHotKey(AddHotKey { neuron_index, .. }) => Ok(RequestType::AddHotKey {
                neuron_index: *neuron_index,
            }),
            Request::Transfer(LedgerOperation::Transfer { .. }) => Ok(RequestType::Send),
            Request::Transfer(LedgerOperation::Burn { .. }) => Err(ApiError::invalid_request(
                "Burn operations are not supported through rosetta",
            )),
            Request::Transfer(LedgerOperation::Mint { .. }) => Err(ApiError::invalid_request(
                "Mint operations are not supported through rosetta",
            )),
            Request::Spawn(Spawn { neuron_index, .. }) => Ok(RequestType::Spawn {
                neuron_index: *neuron_index,
            }),
            Request::MergeMaturity(MergeMaturity { neuron_index, .. }) => {
                Ok(RequestType::MergeMaturity {
                    neuron_index: *neuron_index,
                })
            }
        }
    }

    /// Builds a Transaction from a sequence of `Request`s.
    /// This is a thin wrapper over the `TransactionBuilder`.
    ///
    /// TODO We should capture the concept of a Transaction in a type.
    pub fn requests_to_operations(
        requests: &[Request],
        token_name: &str,
    ) -> Result<Vec<Operation>, ApiError> {
        let mut builder = TransactionBuilder::default();
        for request in requests {
            match request {
                Request::Transfer(o) => builder.transfer(o, token_name)?,
                Request::Stake(o) => builder.stake(o),
                Request::SetDissolveTimestamp(o) => builder.set_dissolve_timestamp(o),
                Request::StartDissolve(o) => builder.start_dissolve(o),
                Request::StopDissolve(o) => builder.stop_dissolve(o),
                Request::Disburse(o) => builder.disburse(o, token_name),
                Request::AddHotKey(o) => builder.add_hot_key(o),
                Request::Spawn(o) => builder.spawn(o),
                Request::MergeMaturity(o) => builder.merge_maturity(o),
            };
        }
        Ok(builder.build())
    }

    pub fn is_transfer(&self) -> bool {
        matches!(self, Request::Transfer(_))
    }

    pub fn is_neuron_management(&self) -> bool {
        matches!(
            self,
            Request::Stake(_)
                | Request::SetDissolveTimestamp(_)
                | Request::StartDissolve(_)
                | Request::StopDissolve(_)
                | Request::Disburse(_)
                | Request::AddHotKey(_)
                | Request::Spawn(_)
                | Request::MergeMaturity(_)
        )
    }
}

/// Sort of the inverse of `construction_payloads`.
impl TryFrom<&models::Request> for Request {
    type Error = ApiError;

    fn try_from(req: &models::Request) -> Result<Self, Self::Error> {
        let (request_type, calls) = req;
        let payload: &models::EnvelopePair = calls
            .first()
            .ok_or_else(|| ApiError::invalid_request("No request payload provided."))?;

        let pid =
            PrincipalId::try_from(payload.update_content().sender.clone().0).map_err(|e| {
                ApiError::internal_error(format!(
                    "Could not parse envelope sender's public key: {}",
                    e
                ))
            })?;

        let account = AccountIdentifier::from(pid);

        let manage_neuron = || {
            {
                CandidOne::<ic_nns_governance::pb::v1::ManageNeuron>::from_bytes(
                    payload.update_content().arg.0.clone(),
                )
                .map_err(|e| {
                    ApiError::invalid_request(format!("Could not parse manage_neuron: {}", e))
                })
            }
            .map(|m| m.0.command)
        };

        match request_type {
            RequestType::Send => {
                let ledger_canister::SendArgs {
                    to, amount, fee, ..
                } = convert::from_arg(payload.update_content().arg.0.clone())?;
                Ok(Request::Transfer(LedgerOperation::Transfer {
                    from: account,
                    to,
                    amount,
                    fee,
                }))
            }
            RequestType::Stake { neuron_index } => Ok(Request::Stake(Stake {
                account,
                neuron_index: *neuron_index,
            })),
            RequestType::SetDissolveTimestamp { neuron_index } => {
                let command = manage_neuron()?;
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::SetDissolveTimestamp(
                            manage_neuron::SetDissolveTimestamp {
                                dissolve_timestamp_seconds,
                                ..
                            },
                        )),
                })) = command
                {
                    Ok(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                        account,
                        neuron_index: *neuron_index,
                        timestamp: Seconds(dissolve_timestamp_seconds),
                    }))
                } else {
                    Err(ApiError::invalid_request(
                        "Request is missing set dissolve timestamp operation.",
                    ))
                }
            }
            RequestType::StartDissolve { neuron_index } => {
                Ok(Request::StartDissolve(StartDissolve {
                    account,
                    neuron_index: *neuron_index,
                }))
            }
            RequestType::StopDissolve { neuron_index } => Ok(Request::StopDissolve(StopDissolve {
                account,
                neuron_index: *neuron_index,
            })),
            RequestType::Disburse { neuron_index } => {
                let command = manage_neuron()?;
                if let Some(Command::Disburse(manage_neuron::Disburse { to_account, amount })) =
                    command
                {
                    let recipient = if let Some(a) = to_account {
                        Some((&a).try_into().map_err(|e| {
                            ApiError::invalid_request(format!(
                                "Could not parse recipient account identifier: {}",
                                e
                            ))
                        })?)
                    } else {
                        None
                    };

                    Ok(Request::Disburse(Disburse {
                        account,
                        amount: amount.map(|amount| Tokens::from_e8s(amount.e8s)),
                        recipient,
                        neuron_index: *neuron_index,
                    }))
                } else {
                    Err(ApiError::invalid_request("Request is missing recipient"))
                }
            }

            RequestType::AddHotKey { neuron_index } => {
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::AddHotKey(manage_neuron::AddHotKey {
                            new_hot_key: Some(pid),
                            ..
                        })),
                })) = manage_neuron()?
                {
                    Ok(Request::AddHotKey(AddHotKey {
                        account,
                        neuron_index: *neuron_index,
                        key: PublicKeyOrPrincipal::Principal(pid),
                    }))
                } else {
                    Err(ApiError::invalid_request("Request is missing set hotkey."))
                }
            }

            RequestType::Spawn { neuron_index } => {
                if let Some(Command::Spawn(manage_neuron::Spawn {
                    new_controller,
                    nonce,
                })) = manage_neuron()?
                {
                    if let Some(spawned_neuron_index) = nonce {
                        Ok(Request::Spawn(Spawn {
                            account,
                            spawned_neuron_index,
                            controller: new_controller,
                            neuron_index: *neuron_index,
                        }))
                    } else {
                        Err(ApiError::invalid_request(
                            "Spawned neuron index is required.",
                        ))
                    }
                } else {
                    Err(ApiError::invalid_request("Invalid spawn request."))
                }
            }
            RequestType::MergeMaturity { neuron_index } => {
                if let Some(Command::MergeMaturity(manage_neuron::MergeMaturity {
                    percentage_to_merge,
                })) = manage_neuron()?
                {
                    Ok(Request::MergeMaturity(MergeMaturity {
                        account,
                        percentage_to_merge,
                        neuron_index: *neuron_index,
                    }))
                } else {
                    Err(ApiError::invalid_request("Invalid merge maturity request."))
                }
            }
        }
    }
}

/// A helper for serializing `RequestResults`
mod send {
    use super::*;

    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<LedgerOperation, D::Error> {
        Send::deserialize(d)
            .map(LedgerOperation::from)
            .map_err(D::Error::from)
    }

    pub fn serialize<S: Serializer>(t: &LedgerOperation, s: S) -> Result<S::Ok, S::Error> {
        Send::try_from(t)
            .map_err(serde::ser::Error::custom)
            .and_then(|t| t.serialize(s))
    }

    #[derive(Copy, Clone, Deserialize, Serialize)]
    struct Send {
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: Tokens,
        fee: Tokens,
    }

    impl TryFrom<&LedgerOperation> for Send {
        type Error = String;

        fn try_from(transfer: &LedgerOperation) -> Result<Self, String> {
            match *transfer {
                LedgerOperation::Transfer {
                    from,
                    to,
                    amount,
                    fee,
                } => Ok(Send {
                    from,
                    to,
                    amount,
                    fee,
                }),
                LedgerOperation::Burn { .. } => {
                    Err("Burn operations are not supported through rosetta".to_owned())
                }
                LedgerOperation::Mint { .. } => {
                    Err("Mint operations are not supported through rosetta".to_owned())
                }
            }
        }
    }

    impl From<Send> for LedgerOperation {
        fn from(s: Send) -> Self {
            let Send {
                from,
                to,
                amount,
                fee,
            } = s;
            LedgerOperation::Transfer {
                from,
                to,
                amount,
                fee,
            }
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Spawn {
    pub account: ledger_canister::AccountIdentifier,
    pub spawned_neuron_index: u64,
    pub controller: Option<PrincipalId>,
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

#[derive(Debug, Clone, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
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
        match serde_json::to_value(m) {
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
                "Could not parse a `neuron_index` from metadata JSON object: {}",
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

/// Transaction is a bit of a misnomer, since operations can succeed or fail
/// independently from a Transaction.
pub struct TransactionBuilder {
    /// The next `OperationIdentifier` `index`.
    /// TODO Why is `OperationIdentifier.index` a signed integer?
    op_index: i64,
    ops: Vec<Operation>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self {
            op_index: 0,
            ops: Vec::default(),
        }
    }
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
                    _type: BURN.to_string(),
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
                    _type: MINT.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(to)),
                    amount: Some(amount_(*amount, token_name)?),
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
                    _type: TRANSACTION.to_string(),
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
                    _type: TRANSACTION.to_string(),
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
                    _type: FEE.to_string(),
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
            _type: STAKE.to_string(),
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
            _type: SET_DISSOLVE_TIMESTAMP.to_string(),
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
            _type: START_DISSOLVE.to_string(),
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
            _type: STOP_DISSOLVE.to_string(),
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
            _type: DISBURSE.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: amount.map(|a| amount_(a, token_name).expect("failed to convert amount")),
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
            _type: ADD_HOT_KEY.to_string(),
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
            neuron_index,
        } = spawn;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: SPAWN.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                SpawnMetadata {
                    controller: *controller,
                    neuron_index: *neuron_index,
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
            _type: MERGE_MATURITY.to_string(),
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
}
