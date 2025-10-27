use crate::{format_time_of_day, parse_time_of_day};
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use serde::{Deserialize, Deserializer, Serializer, ser::Error};

#[cfg(test)]
mod optional_time_of_day_tests;

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<GlobalTimeOfDay>, D::Error>
where
    D: Deserializer<'de>,
{
    let string: Option<String> = Deserialize::deserialize(deserializer)?;

    let string = match string {
        None => return Ok(None),
        Some(string) => string,
    };

    let global_time_of_day = parse_time_of_day(&string).map_err(serde::de::Error::custom)?;
    Ok(Some(global_time_of_day))
}

pub fn serialize<S>(time_of_day: &Option<GlobalTimeOfDay>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let time_of_day = match time_of_day.as_ref() {
        None => return serializer.serialize_none(),
        Some(time_of_day) => time_of_day,
    };

    // Input was Some -> format it (i.e. convert to String).
    if time_of_day.seconds_after_utc_midnight.is_none() {
        return Err(S::Error::custom(
            "Unable to format TimeOfDay, because seconds_after_utc_midnight is blank.",
        ));
    }
    let string = format_time_of_day(time_of_day);

    // The string needs to be wrapped in Some. Otherwise, the round trip is
    // going to be missing an Option layer: look at the first line of
    // deserialize: we try to get an Option<String> from deserializer.
    serializer.serialize_some(&Some(string))
}
