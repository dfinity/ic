use rosetta_core::objects::ObjectMap;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct QueryBlockRangeRequest {
    pub highest_block_index: u64,
    pub number_of_blocks: u64,
}

impl TryFrom<QueryBlockRangeRequest> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: QueryBlockRangeRequest) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert QueryBlockRangeRequest to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!(
                "Could not convert QueryBlockRangeRequest to ObjectMap: {:?}",
                err
            ),
        }
    }
}

impl TryFrom<ObjectMap> for QueryBlockRangeRequest {
    type Error = String;
    fn try_from(o: ObjectMap) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o))
            .map_err(|e| format!("Could not parse QueryBlockRangeRequest from JSON object: {e}"))
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct QueryBlockRangeResponse {
    pub blocks: Vec<rosetta_core::objects::Block>,
}

impl TryFrom<QueryBlockRangeResponse> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: QueryBlockRangeResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert QueryBlockRangeResponse to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!(
                "Could not convert QueryBlockRangeResponse to ObjectMap: {:?}",
                err
            ),
        }
    }
}

impl TryFrom<ObjectMap> for QueryBlockRangeResponse {
    type Error = String;
    fn try_from(o: ObjectMap) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o))
            .map_err(|e| format!("Could not parse QueryBlockRangeResponse from JSON object: {e}"))
    }
}
