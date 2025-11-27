use crate::common::types::OperationType;
use anyhow::anyhow;
use anyhow::bail;
use ic_agent::agent::Envelope;
use ic_agent::agent::EnvelopeContent;
use rosetta_core::objects::*;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConstructionMetadataRequestOptions {
    pub suggested_fee: bool,
}

impl TryFrom<ConstructionMetadataRequestOptions> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: ConstructionMetadataRequestOptions) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert ConstructionMetadataRequestOptions to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!(
                "Could not convert ConstructionMetadataRequestOptions to ObjectMap: {:?}",
                err
            ),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for ConstructionMetadataRequestOptions {
    type Error = String;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .map_err(|e| format!("Could not parse MetadataOptions from JSON object: {e}"))
    }
}

// A signed transaction contains a list of envelopes. The list exists because we do not know when we create the envelopes which ingress interval is going to be used by the user
// To support the 24h window of valid transactions a single signed transaction does not contain a single envelope but 24*3600/INGRESS_INTERVAL envelopes, one for every possible ingress interval.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedTransaction<'a> {
    pub envelopes: Vec<Envelope<'a>>,
}

impl std::fmt::Display for SignedTransaction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(serde_cbor::ser::to_vec(self).unwrap()))
    }
}

impl FromStr for SignedTransaction<'_> {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_cbor::from_slice(hex::decode(s)?.as_slice()).map_err(|err| anyhow!("{:?}", err))
    }
}
impl SignedTransaction<'_> {
    pub fn get_lowest_ingress_expiry(&self) -> Option<u64> {
        self.envelopes
            .iter()
            .map(|envelope| envelope.content.ingress_expiry())
            .min()
    }

    pub fn get_highest_ingress_expiry(&self) -> Option<u64> {
        self.envelopes
            .iter()
            .map(|envelope| envelope.content.ingress_expiry())
            .max()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
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
        let operation_types = operations
            .iter()
            .map(|operation| operation.type_.parse::<OperationType>())
            .collect::<Result<Vec<OperationType>, strum::ParseError>>()?;

        if operation_types.contains(&OperationType::Transfer) {
            if operation_types.contains(&OperationType::Spender) {
                return Ok(Self::Icrc2TransferFrom);
            }
            return Ok(Self::Icrc1Transfer);
        }
        if operation_types.contains(&OperationType::Approve) {
            return Ok(Self::Icrc2Approve);
        }
        bail!(
            "Could not derive a valid CanisterMethodName from the given operations vector: {:?} ",
            operations
        )
    }
}

impl std::fmt::Display for CanisterMethodName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icrc2Approve => write!(f, "icrc2_approve"),
            Self::Icrc2TransferFrom => write!(f, "icrc2_transfer_from"),
            Self::Icrc1Transfer => write!(f, "icrc1_transfer"),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnsignedTransaction {
    pub envelope_contents: Vec<EnvelopeContent>,
}

impl std::fmt::Display for UnsignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(serde_cbor::ser::to_vec(self).unwrap()))
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
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
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
            Ok(o) => bail!(
                "Could not convert ConstructionPayloadsRequestMetadata to ObjectMap. Expected type Object but received: {:?}",
                o
            ),
            Err(err) => bail!(
                "Could not convert ConstructionPayloadsRequestMetadata to ObjectMap: {:?}",
                err
            ),
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
            .map_err(|e| format!("Could not parse MetadataOptions from JSON object: {e}"))
    }
}
