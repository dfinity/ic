//! Tools for managing stable storage of data in a canister.
use crate::stable;

/// Saves the storage into the stable memory.
///
/// This will override any value previously stored in stable memory.
pub fn stable_save<T>(t: T) -> Result<(), candid::Error>
where
    T: candid::utils::ArgumentEncoder,
{
    candid::write_args(&mut stable::StableWriter::default(), t)
}

/// Restores a value from the stable memory to the storage.
///
/// There can only be one value in stable memory, currently.
pub fn stable_restore<T>() -> Result<T, String>
where
    T: for<'de> candid::utils::ArgumentDecoder<'de>,
{
    let bytes = stable::stable_bytes();

    let mut de = candid::de::IDLDeserialize::new(bytes.as_slice()).map_err(|e| format!("{e:?}"))?;
    let res = candid::utils::ArgumentDecoder::decode(&mut de).map_err(|e| format!("{e:?}"))?;
    Ok(res)
}
