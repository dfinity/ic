use serde::Serialize;
use serde_json::Value;

/// Supposed to be used in places where serialization to a [serde_json::Value]
/// can't fail.
pub fn assert_to_value<T>(value: T) -> Value
where
    T: Serialize,
{
    serde_json::to_value(value).expect("Failed to serialize json Value.")
}
