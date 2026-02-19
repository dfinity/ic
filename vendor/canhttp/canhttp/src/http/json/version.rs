use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Display, Formatter};

/// Protocol Version
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// JSONRPC 2.0
    V2,
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Version::V2 => f.write_str("2.0"),
        }
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Version::V2 => serializer.serialize_str("2.0"),
        }
    }
}

impl<'a> Deserialize<'a> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_identifier(VersionVisitor)
    }
}

struct VersionVisitor;

impl<'a> Visitor<'a> for VersionVisitor {
    type Value = Version;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match value {
            "2.0" => Ok(Version::V2),
            _ => Err(serde::de::Error::custom(
                "expected JSON-RPC version \"2.0\"",
            )),
        }
    }
}
