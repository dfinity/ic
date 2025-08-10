/// Efficient deserializer for `Option<Vec<u8>>` using `serde_bytes::ByteBuf` internally
/// to speed up deserialization.
pub fn deserialize_option_blob<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let s: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
    Ok(s.map(|b| b.to_vec()))
}
