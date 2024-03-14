use crate::common::types::OperationType;
use anyhow::anyhow;
use anyhow::bail;
use candid::{Decode, Nat};
use ic_agent::agent::Envelope;
use ic_agent::agent::EnvelopeContent;
use icrc_ledger_types::icrc1::transfer::TransferError;
use icrc_ledger_types::icrc2::approve::ApproveError;
use rosetta_core::objects::*;
use serde::Deserialize;
use serde::Serialize;
use std::cmp;
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConstructionMetadataRequestOptions {
    pub suggested_fee: bool,
}

impl TryFrom<ConstructionMetadataRequestOptions> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: ConstructionMetadataRequestOptions) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!("Could not convert ConstructionMetadataRequestOptions to ObjectMap. Expected type Object but received: {:?}",v)
            },Err(err) => anyhow::bail!("Could not convert ConstructionMetadataRequestOptions to ObjectMap: {:?}",err),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for ConstructionMetadataRequestOptions {
    type Error = String;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .map_err(|e| format!("Could not parse MetadataOptions from JSON object: {}", e))
    }
}

// Every transaction that we want to send to the IC consists of two envelopes that we have to send to the IC,
// the call with the content of our request and the read that fetches the result
// Each Envelope contains a valid signature of the request to the IC and the content of the request.
// For the Call request the content is the canister method call and for the State request the content is simply
// that we want to known whether there exists a result for the Call request yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopePair<'a> {
    pub call_envelope: Envelope<'a>,
    pub read_state_envelope: Envelope<'a>,
}

// A signed transaction contains a list of envelope pairs. The list exists because we do not know when we create the envelope pairs which ingress interval is going to be used by the user
// To support the 24h window of valid transactions a single signed transaction does not contain a single envelope pair but 24*3600/INGRESS_INTERVAL envelope pairs, one of every possible ingress interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction<'a> {
    pub envelope_pairs: Vec<EnvelopePair<'a>>,
}

impl<'a> ToString for SignedTransaction<'a> {
    fn to_string(&self) -> String {
        hex::encode(serde_cbor::ser::to_vec(self).unwrap())
    }
}

impl<'a> FromStr for SignedTransaction<'a> {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_cbor::from_slice(hex::decode(s)?.as_slice()).map_err(|err| anyhow!("{:?}", err))
    }
}
impl<'a> SignedTransaction<'a> {
    pub fn get_lowest_ingress_expiry(&self) -> Option<u64> {
        self.envelope_pairs
            .iter()
            .map(|pair| {
                cmp::min(
                    pair.call_envelope.content.ingress_expiry(),
                    pair.read_state_envelope.content.ingress_expiry(),
                )
            })
            .min()
    }

    pub fn get_highest_ingress_expiry(&self) -> Option<u64> {
        self.envelope_pairs
            .iter()
            .map(|pair| {
                cmp::max(
                    pair.call_envelope.content.ingress_expiry(),
                    pair.read_state_envelope.content.ingress_expiry(),
                )
            })
            .max()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanisterMethodName {
    Icrc2Approve,
    Icrc2TransferFrom,
    Icrc1Transfer,
}

impl CanisterMethodName {
    pub fn new_from_envelope_content(envelope_content: &EnvelopeContent) -> anyhow::Result<Self> {
        match envelope_content {
            EnvelopeContent::Call { method_name, .. } => {
                Ok(method_name.parse::<CanisterMethodName>()?)
            }
            _ => bail!(
                "EnvelopeContent has to be of type Call, but was {:?}",
                envelope_content
            ),
        }
    }

    pub fn new_from_rosetta_core_operations(
        operations: &Vec<rosetta_core::objects::Operation>,
    ) -> anyhow::Result<Self> {
        for operation in operations {
            let operation_type = operation.type_.parse::<OperationType>()?;
            match operation_type {
                OperationType::Transfer => return Ok(Self::Icrc1Transfer),
                OperationType::Approve => return Ok(Self::Icrc2Approve),
                // An icrc1 operation is made up of multiple rosetta_core operations, so we have to look for the definining operation
                _ => continue,
            }
        }
        bail!(
            "Could not derive a valid CanisterMethodName from the given operations vector: {:?} ",
            operations
        )
    }
}

impl ToString for CanisterMethodName {
    fn to_string(&self) -> String {
        match self {
            Self::Icrc2Approve => "icrc2_approve".to_string(),
            Self::Icrc2TransferFrom => "icrc2_transfer_from".to_string(),
            Self::Icrc1Transfer => "icrc1_transfer".to_string(),
        }
    }
}

impl FromStr for CanisterMethodName {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "icrc2_approve" => Ok(Self::Icrc2Approve),
            "icrc2_transfer_from" => Ok(Self::Icrc2TransferFrom),
            "icrc1_transfer" => Ok(Self::Icrc1Transfer),
            _ => bail!("Invalid CanisterMethodName: {}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub envelope_contents: Vec<EnvelopeContent>,
}

impl ToString for UnsignedTransaction {
    fn to_string(&self) -> String {
        hex::encode(serde_cbor::ser::to_vec(self).unwrap())
    }
}

impl FromStr for UnsignedTransaction {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_cbor::from_slice(hex::decode(s)?.as_slice()).map_err(|err| anyhow!("{:?}", err))
    }
}

impl UnsignedTransaction {
    pub fn get_lowest_ingress_expiry(&self) -> Option<u64> {
        self.envelope_contents
            .iter()
            .map(|ec: &EnvelopeContent| ec.ingress_expiry())
            .min()
    }

    pub fn get_highest_ingress_expiry(&self) -> Option<u64> {
        self.envelope_contents
            .iter()
            .map(|ec: &EnvelopeContent| ec.ingress_expiry())
            .max()
    }
}

/// Typed metadata of ConstructionPayloadsRequest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructionPayloadsRequestMetadata {
    /// The memo to use for a ledger transfer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<Vec<u8>>,

    /// The earliest acceptable expiry date for a ledger transfer.
    /// Must be within 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_start: Option<u64>,

    /// The latest acceptable expiry date for a ledger transfer.
    /// Must be within 24 hours from created_at_time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_end: Option<u64>,

    /// If present, overrides ledger transaction creation time.
    /// Represents number of nanoseconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_time: Option<u64>,
}

impl TryFrom<ConstructionPayloadsRequestMetadata> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: ConstructionPayloadsRequestMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(serde_json::Value::Object(o)) => Ok(o),
            Ok(o) => bail!("Could not convert ConstructionPayloadsRequestMetadata to ObjectMap. Expected type Object but received: {:?}",o),
            Err(err) => bail!("Could not convert ConstructionPayloadsRequestMetadata to ObjectMap: {:?}",err),
        }
    }
}

impl TryFrom<ObjectMap> for ConstructionPayloadsRequestMetadata {
    type Error = crate::common::types::Error;
    fn try_from(o: ObjectMap) -> Result<Self, crate::common::types::Error> {
        serde_json::from_value(serde_json::Value::Object(o))
            .map_err(|e| crate::common::types::Error::invalid_metadata(&e))
    }
}

impl TryFrom<Option<ObjectMap>> for ConstructionPayloadsRequestMetadata {
    type Error = String;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .map_err(|e| format!("Could not parse MetadataOptions from JSON object: {}", e))
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(tag = "status", content = "response")]
pub enum Status {
    Successful,
    Unsuccessful,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct IcrcLedgerResult {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Object>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstructionSubmitResponseMetadata {
    pub operations: Vec<Operation>,
    pub result: IcrcLedgerResult,
}

impl ConstructionSubmitResponseMetadata {
    pub fn new(operations: Vec<Operation>, bytes: Vec<u8>) -> anyhow::Result<Self> {
        let canister_method_name: CanisterMethodName =
            CanisterMethodName::new_from_rosetta_core_operations(&operations)?;
        let response = match canister_method_name {
            CanisterMethodName::Icrc1Transfer | CanisterMethodName::Icrc2TransferFrom => {
                match Decode!(bytes.as_slice(), Result<Nat, TransferError>)? {
                    Ok(nat) => IcrcLedgerResult {
                        status: Status::Successful,
                        response: Some(Object::from(serde_json::json!({
                            "block_index": nat.to_string()
                        }))),
                    },
                    Err(e) => IcrcLedgerResult {
                        status: Status::Unsuccessful,
                        response: Some(Object::from(serde_json::json!({
                            "transfer_error": format!("{:?}", e)
                        }))),
                    },
                }
            }
            CanisterMethodName::Icrc2Approve => {
                match Decode!(bytes.as_slice(), Result<Nat, ApproveError>)? {
                    Ok(nat) => IcrcLedgerResult {
                        status: Status::Successful,
                        response: Some(Object::from(serde_json::json!({
                            "block_index": nat.to_string()
                        }))),
                    },
                    Err(e) => IcrcLedgerResult {
                        status: Status::Unsuccessful,
                        response: Some(Object::from(serde_json::json!({
                            "approve_error": format!("{:?}", e)
                        }))),
                    },
                }
            }
        };

        Ok(Self {
            operations: operations.clone(),
            result: response,
        })
    }
}

impl TryFrom<ConstructionSubmitResponseMetadata> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: ConstructionSubmitResponseMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(serde_json::Value::Object(o)) => Ok(o),
            Ok(o) => bail!("Could not convert ConstructionSubmitResponseMetadata to ObjectMap. Expected type Object but received: {:?}",o),
            Err(err) => bail!("Could not convert ConstructionSubmitResponseMetadata to ObjectMap: {:?}",err),
        }
    }
}

impl TryFrom<ObjectMap> for ConstructionSubmitResponseMetadata {
    type Error = crate::common::types::Error;
    fn try_from(o: ObjectMap) -> Result<Self, crate::common::types::Error> {
        serde_json::from_value(serde_json::Value::Object(o))
            .map_err(|e| crate::common::types::Error::invalid_metadata(&e))
    }
}

impl TryFrom<Option<ObjectMap>> for ConstructionSubmitResponseMetadata {
    type Error = String;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            format!(
                "Could not parse ConstructionSubmitResponseMetadata from JSON object: {}",
                e
            )
        })
    }
}
