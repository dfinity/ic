use anyhow::anyhow;
use anyhow::bail;
use ic_agent::agent::Envelope;
use ic_agent::agent::EnvelopeContent;
use rosetta_core::objects::*;
use serde::Deserialize;
use serde::Serialize;
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
