use candid::{CandidType, Principal};
use ic_base_types::CanisterId;
use ic_nervous_system_clients::Request;
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::CallCanisters;

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

// ```candid
// type upload_chunk_args = record {
//     canister_id : principal;
//     chunk : blob;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
struct UploadChunkArgs {
    pub canister_id: Principal,
    pub chunk: Vec<u8>,
}

// ```candid
// type chunk_hash = record {
//   hash : blob;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct ChunkHash {
    pub hash: Vec<u8>,
}

// ```candid
// type upload_chunk_result = chunk_hash;
// ```
type UploadChunksResult = ChunkHash;

impl Request for UploadChunkArgs {
    type Response = UploadChunksResult;
    const METHOD: &'static str = "upload_chunk";
    const UPDATE: bool = true;
}

async fn upload_chunk<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
    chunk: Vec<u8>,
) -> Result<ChunkHash, C::Error> {
    let response = agent
        .call(
            Principal::management_canister(),
            UploadChunkArgs {
                canister_id: store_canister_id.get().0,
                chunk,
            },
        )
        .await?;

    Ok(response)
}

// ```candid
// type stored_chunks_args = record {
//     canister_id : canister_id;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
struct StoredChunksArgs {
    pub canister_id: Principal,
}

// ```
// type chunk_hash = record {
//   hash : blob;
// };
// type stored_chunks_result = vec chunk_hash;
// ```
type StoredChunksResult = Vec<ChunkHash>;

impl Request for StoredChunksArgs {
    type Response = StoredChunksResult;
    const METHOD: &'static str = "stored_chunks";
    const UPDATE: bool = false;
}

pub async fn stored_chunks<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
) -> Result<Vec<ChunkHash>, C::Error> {
    let response = agent
        .call(
            Principal::management_canister(),
            StoredChunksArgs {
                canister_id: store_canister_id.get().0,
            },
        )
        .await?;

    Ok(response)
}

fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub async fn upload_wasm_as_chunks<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
    wasm_bytes: Vec<u8>,
    num_chunks_expected: usize,
) -> Result<Vec<ChunkHash>, C::Error> {
    let mut uploaded_chunk_hashes = Vec::new();

    for chunk in wasm_bytes.chunks(CHUNK_SIZE) {
        let uploaded_chunk_hash = upload_chunk(agent, store_canister_id, chunk.to_vec()).await?;

        uploaded_chunk_hashes.push(uploaded_chunk_hash);
    }

    // Smoke test
    {
        let stored_chunk_hashes = stored_chunks(agent, store_canister_id).await?;

        let stored_chunk_hashes = stored_chunk_hashes
            .into_iter()
            .map(|chunk_hash| format_full_hash(&chunk_hash.hash))
            .collect::<Vec<_>>();

        let stored_chunk_hashes = BTreeSet::from_iter(stored_chunk_hashes.iter());

        let uploaded_chunk_hashes = uploaded_chunk_hashes
            .iter()
            .map(|chunk_hash| format_full_hash(&chunk_hash.hash))
            .collect::<Vec<_>>();
        let uploaded_chunk_hashes = BTreeSet::from_iter(uploaded_chunk_hashes.iter());

        assert!(uploaded_chunk_hashes.is_subset(&stored_chunk_hashes));
        assert_eq!(uploaded_chunk_hashes.len(), num_chunks_expected);
    }

    Ok(uploaded_chunk_hashes)
}
