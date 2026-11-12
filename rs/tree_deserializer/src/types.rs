use std::convert::TryFrom;
use std::fmt;

/// 64-bit unsigned integer that is deserialized from a byte array using LEB-128
/// encoding.
#[derive(Eq, PartialEq, Debug)]
pub struct Leb128EncodedU64(pub u64);

/// Error indicating that conversion from bytes to an integer failed.
#[derive(Debug)]
pub enum LebDecodingError {
    /// The bytes contained a number bigger than u64::MAX.
    Overflow,
    /// The bytes contained a valid number, but there was extra data in the
    /// buffer.
    TrailingData,
    /// The bytes did not contain a complete LEB128-encoded number.
    IncompleteInput,
}

impl fmt::Display for LebDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => write!(f, "LEB128-encoded number overflows 64-bit unsigned int"),
            Self::TrailingData => write!(f, "input contained trailing data"),
            Self::IncompleteInput => {
                write!(f, "input did not contain a complete LEB128-encoded number")
            }
        }
    }
}

impl TryFrom<&'_ [u8]> for Leb128EncodedU64 {
    type Error = LebDecodingError;

    fn try_from(mut bytes: &[u8]) -> Result<Self, LebDecodingError> {
        use leb128::read::Error;

        let value = match leb128::read::unsigned(&mut bytes) {
            Ok(value) => Leb128EncodedU64(value),
            Err(Error::Overflow) => return Err(LebDecodingError::Overflow),
            // Reading from a byte slice fails with an I/O error only when there is not enough data
            Err(Error::IoError(_)) => return Err(LebDecodingError::IncompleteInput),
        };

        if !bytes.is_empty() {
            return Err(LebDecodingError::TrailingData);
        }

        Ok(value)
    }
}

impl<'de> serde::Deserialize<'de> for Leb128EncodedU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct LebU64Visitor;

        impl serde::de::Visitor<'_> for LebU64Visitor {
            type Value = Leb128EncodedU64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a LEB128 encoded U64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Leb128EncodedU64::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(LebU64Visitor)
    }
}
