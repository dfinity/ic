use rosetta_core::objects::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetadataOptions {
    pub suggested_fee: bool,
}

impl From<MetadataOptions> for ObjectMap {
    fn from(m: MetadataOptions) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for MetadataOptions {
    type Error = String;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .map_err(|e| format!("Could not parse MetadataOptions from JSON object: {}", e))
    }
}
