pub mod api;
pub mod storage;

use crate::storage::{Blob, Hash, mutate_blob_store};
use api::RecordError;

pub fn record(caller: candid::Principal, hash: &str, data: Vec<u8>) -> Result<Hash, RecordError> {
    if !ic_cdk::api::is_controller(&caller) {
        return Err(RecordError::NotAuthorized);
    }
    let expected_hash: Hash = hash
        .parse()
        .map_err(|e: hex::FromHexError| RecordError::InvalidHash(e.to_string()))?;
    let blob = Blob::from(data);
    let actual_hash = blob.hash();

    if expected_hash != *actual_hash {
        return Err(RecordError::HashMismatch {
            expected: expected_hash.to_string(),
            actual: actual_hash.to_string(),
        });
    }

    mutate_blob_store(|store| store.insert(blob).ok_or(RecordError::AlreadyExists))
}
