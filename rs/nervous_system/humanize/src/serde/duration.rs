use crate::{format_duration, parse_duration};
use ic_nervous_system_proto::pb::v1::Duration;
use serde::{Deserialize, Deserializer, Serializer, ser::Error};

#[cfg(test)]
mod duration_tests;

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    parse_duration(&string).map_err(serde::de::Error::custom)
}

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if duration.seconds.is_none() {
        return Err(S::Error::custom(
            "Unable to format Duration, because seconds is blank.",
        ));
    }
    serializer.serialize_str(&format_duration(duration))
}
