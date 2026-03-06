use crate::Hash;
use crate::api::{BlobMetadata, GetError};
use crate::storage::read_blob_store;

pub fn get(hash: &str) -> Result<Vec<u8>, GetError> {
    let parsed_hash: Hash = hash
        .parse()
        .map_err(|e: hex::FromHexError| GetError::InvalidHash {
            reason: e.to_string(),
        })?;
    read_blob_store(|store| store.get(parsed_hash))
        .map(|blob| blob.into_data())
        .ok_or(GetError::NotFound)
}

pub fn get_metadata(hash: &str) -> Result<BlobMetadata, GetError> {
    let parsed_hash: Hash = hash
        .parse()
        .map_err(|e: hex::FromHexError| GetError::InvalidHash {
            reason: e.to_string(),
        })?;
    read_blob_store(|store| store.get_metadata(parsed_hash)).ok_or(GetError::NotFound)
}
