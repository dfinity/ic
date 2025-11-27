use crate::{format_tokens, parse_tokens};
use ic_nervous_system_proto::pb::v1::Tokens;
use serde::{Deserialize, Deserializer, Serializer, ser::Error};

#[cfg(test)]
mod tokens_tests;

pub fn deserialize<'de, D>(deserializer: D) -> Result<Tokens, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    parse_tokens(&string).map_err(serde::de::Error::custom)
}

pub fn serialize<S>(tokens: &Tokens, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if tokens.e8s.is_none() {
        return Err(S::Error::custom(
            "Unable to format Tokens, because e8s is blank.",
        ));
    }
    serializer.serialize_str(&format_tokens(tokens))
}
