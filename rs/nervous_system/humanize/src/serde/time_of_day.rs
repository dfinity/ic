use crate::{format_time_of_day, parse_time_of_day};
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use serde::{Deserialize, Deserializer, Serializer, ser::Error};

#[cfg(test)]
mod time_of_day_tests;

pub fn deserialize<'de, D>(deserializer: D) -> Result<GlobalTimeOfDay, D::Error>
where
    D: Deserializer<'de>,
{
    let string: String = Deserialize::deserialize(deserializer)?;
    parse_time_of_day(&string).map_err(serde::de::Error::custom)
}

pub fn serialize<S>(time_of_day: &GlobalTimeOfDay, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if time_of_day.seconds_after_utc_midnight.is_none() {
        return Err(S::Error::custom(
            "Unable to format TimeOfDay, because seconds_after_utc_midnight is blank.",
        ));
    }
    serializer.serialize_str(&format_time_of_day(time_of_day))
}
