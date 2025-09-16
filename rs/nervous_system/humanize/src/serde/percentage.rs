use crate::{format_percentage, parse_percentage};
use ic_nervous_system_proto::pb::v1::Percentage;
use serde::{Deserialize, Deserializer, Serializer, ser::Error};

#[cfg(test)]
mod percentage_tests;

pub fn deserialize<'de, D>(deserializer: D) -> Result<Percentage, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    parse_percentage(&string).map_err(serde::de::Error::custom)
}

pub fn serialize<S>(percentage: &Percentage, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if percentage.basis_points.is_none() {
        return Err(S::Error::custom(
            "Unable to format Percentage, because basis_points is blank.",
        ));
    }
    serializer.serialize_str(&format_percentage(percentage))
}
