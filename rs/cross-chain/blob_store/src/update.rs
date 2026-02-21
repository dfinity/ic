use crate::api::InsertError;
use crate::storage::mutate_blob_store;
use crate::{Blob, Hash};

pub fn insert(caller: candid::Principal, hash: &str, data: Vec<u8>) -> Result<Hash, InsertError> {
    if !ic_cdk::api::is_controller(&caller) {
        return Err(InsertError::NotAuthorized);
    }
    let expected_hash: Hash = hash
        .parse()
        .map_err(|e: hex::FromHexError| InsertError::InvalidHash(e.to_string()))?;
    let blob = Blob::from(data);
    let actual_hash = blob.hash();

    if expected_hash != *actual_hash {
        return Err(InsertError::HashMismatch {
            expected: expected_hash.to_string(),
            actual: actual_hash.to_string(),
        });
    }

    mutate_blob_store(|store| store.insert(blob).ok_or(InsertError::AlreadyExists))
}
