//! Serde serialization and deserialization for Ethereum hexadecimal types (prefixed by `0x`).

#[cfg(test)]
mod tests;

use hex::{FromHex, ToHex};
use serde::Deserializer;
use serde::Serializer;
use serde::de::{Error, Visitor};
use std::fmt;
use std::marker::PhantomData;

/// Serializes `data` as Ethereum hex string.
pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: ToHex,
{
    let mut buf = data.encode_hex::<String>();
    buf.insert_str(0, "0x");
    serializer.serialize_str(&buf)
}

/// Deserializes an Ethereum data string into raw bytes.
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromHex,
    <T as FromHex>::Error: fmt::Display,
{
    struct HexStrVisitor<T>(PhantomData<T>);

    impl<T> Visitor<'_> for HexStrVisitor<T>
    where
        T: FromHex,
        <T as FromHex>::Error: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a hex-encoded DATA string")
        }

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if !data.starts_with("0x") {
                return Err(Error::custom("Ethereum DATA doesn't start with 0x"));
            }
            FromHex::from_hex(&data[2..]).map_err(Error::custom)
        }
    }

    deserializer.deserialize_str(HexStrVisitor(PhantomData))
}
