use super::CHUNK_SIZE_BYTES;

use ic_crypto_sha2::Sha256;
use lazy_static::lazy_static;
use prost::Message;

#[derive(::prost::Message, PartialEq, Eq, Clone)]
pub struct MegaBlob {
    #[prost(bytes = "vec", tag = "1")]
    pub content: Vec<u8>,
}

lazy_static! {
    pub static ref MEGA_BLOB_CONTENT: Vec<u8> = {
        const MOD: u64 = u8::MAX as u64 + 1;

        (0..5_000_000)
            .map(|i| {
                let result = (i * 57 + 42) % MOD;
                result as u8
            })
            .collect()
    };

    // A big Vec<u8> (len > 2x CHUNK_SIZE_BYTES).
    //
    // Only useful for tests (but not harmful if used elsewhere).
    //
    // Can be deserialized as a MegaBlob. Many tests do not actually need this,
    // but some do.
    pub static ref MEGA_BLOB: Vec<u8> = {
        let message = MegaBlob {
            content: MEGA_BLOB_CONTENT.clone(),
        };

        let len = message.encoded_len();
        assert!(len > 2 * CHUNK_SIZE_BYTES, "{} vs. {}", len, 2 * CHUNK_SIZE_BYTES);

        message.encode_to_vec()
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
