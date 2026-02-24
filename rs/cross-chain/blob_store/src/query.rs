use crate::Hash;
use crate::api::GetError;
use crate::storage::read_blob_store;

pub fn get(hash: &str) -> Result<Vec<u8>, GetError> {
    let parsed_hash: Hash = hash
        .parse()
        .map_err(|e: hex::FromHexError| GetError::InvalidHash(e.to_string()))?;
    read_blob_store(|store| store.get(&parsed_hash))
        .map(|blob| blob.into_data())
        .ok_or(GetError::NotFound)
}
