use crate::pb::v1::PreciseValue;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum ConversionError {
    FloatingPointNotSupported,
    NullNotSupported,
    NumberOutOfRange,
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConversionError::FloatingPointNotSupported => {
                write!(f, "Floating point numbers are not supported")
            }
            ConversionError::NullNotSupported => {
                write!(f, "Null values are not supported")
            }
            ConversionError::NumberOutOfRange => {
                write!(f, "Number is out of range for i64/u64")
            }
        }
    }
}

impl std::error::Error for ConversionError {}

impl TryFrom<Value> for PreciseValue {
    type Error = ConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(b) => Ok(PreciseValue::Bool(b)),
            Value::String(s) => Ok(PreciseValue::Text(s)),
            Value::Number(n) => {
                if n.is_f64() {
                    return Err(ConversionError::FloatingPointNotSupported);
                }

                // Attempt to convert to i64 or u64, although predicting the integer type is
                // not always possible. For example, a small positive integer (e.g., 42) could
                // be represented as either i64 or u64. We give preference to u64.
                if let Some(u) = n.as_u64() {
                    Ok(PreciseValue::Nat(u))
                } else if let Some(i) = n.as_i64() {
                    Ok(PreciseValue::Int(i))
                } else {
                    Err(ConversionError::NumberOutOfRange)
                }
            }
            Value::Array(arr) => {
                let mut converted_array = Vec::new();
                for item in arr {
                    converted_array.push(PreciseValue::try_from(item)?);
                }
                Ok(PreciseValue::Array(converted_array))
            }
            Value::Object(obj) => {
                let mut converted_map = BTreeMap::new();
                for (k, v) in obj {
                    converted_map.insert(k, PreciseValue::try_from(v)?);
                }
                Ok(PreciseValue::Map(converted_map))
            }
            Value::Null => Err(ConversionError::NullNotSupported),
        }
    }
}

/// Parses a string into a `PreciseValue`. Useful for command line arguments or configuration files.
///
/// Example usage:
/// ```
/// #[derive(Debug, Parser)]
/// pub struct MyCliArgs {
///     #[clap(long, value_parser = parse_precise_value)]
///     pub arg: Option<PreciseValue>,
/// }
/// ```
pub fn parse_precise_value(
    s: &str,
) -> Result<PreciseValue, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let value: Value = serde_json::from_str(s)?;
    let precise_value = PreciseValue::try_from(value)?;
    Ok(precise_value)
}
