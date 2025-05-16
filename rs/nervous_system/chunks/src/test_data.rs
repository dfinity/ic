use super::CHUNK_SIZE_BYTES;

use ic_crypto_sha2::Sha256;
use lazy_static::lazy_static;

lazy_static! {
    // A big Vec<u8> (vs. > 2x CHUNK_SIZE_BYTES).
    //
    // Only useful for tests (but not harmful if used elsewhere).
    pub static ref MEGA_BLOB: Vec<u8> = {
        const MOD: u64 = u8::MAX as u64 + 1;

        (0..5_000_000)
            .map(|i| {
                let result = (i * 57 + 42) % MOD;
                result as u8
            })
            .collect()
    };

    pub static ref MEGA_BLOB_CHUNK_KEYS: Vec<Vec<u8>> = {
        let mut result = vec![];
        let mut remainder = MEGA_BLOB.clone();

        while !remainder.is_empty() {
            let next_chunk_size = std::cmp::min(CHUNK_SIZE_BYTES, remainder.len());
            let chunk = remainder
                .drain(..next_chunk_size)
                .collect::<Vec<u8>>();

            let sha256 = Sha256::hash(&chunk).to_vec();

            result.push(sha256);
        }

        result
    };
}
