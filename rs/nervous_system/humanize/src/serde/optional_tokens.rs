use crate::{parse_tokens, serde::tokens};
use ic_nervous_system_proto::pb::v1::Tokens;
use serde::{Deserialize, Deserializer, Serializer};

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Tokens>, D::Error>
where
    D: Deserializer<'de>,
{
    let string: Option<String> = Deserialize::deserialize(deserializer)?;
    string
        .map(|string| parse_tokens(&string).map_err(serde::de::Error::custom))
        .transpose()
}

pub fn serialize<S>(tokens: &Option<Tokens>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match tokens {
        None => serializer.serialize_none(),
        Some(tokens) => tokens::serialize(tokens, serializer),
    }
}
