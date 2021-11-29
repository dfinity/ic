/// Fast serialization and deserialization for `PageBytes`.
use ic_sys::PageBytes;
use serde::{de::Visitor, Deserializer, Serializer};
use std::convert::TryInto;

pub fn serialize<S>(bytes: &PageBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<PageBytes, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(PageBytesVisitor)
}

struct PageBytesVisitor;

impl<'de> Visitor<'de> for PageBytesVisitor {
    type Value = PageBytes;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("page bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let page: PageBytes = v
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(v.len(), &self))?;
        Ok(page)
    }
}
