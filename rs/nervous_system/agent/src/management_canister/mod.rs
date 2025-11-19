use candid::Principal;
use ic_base_types::CanisterId;

use crate::CallCanisters;
use std::collections::BTreeSet;

pub mod requests;

use requests::*;

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

pub async fn canister_status<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
) -> Result<CanisterStatusResult, C::Error> {
    let response = agent
        .call(
            Principal::management_canister(),
            CanisterStatusArgs {
                canister_id: canister_id.get().0,
            },
        )
        .await?;

    Ok(response)
}

pub async fn stop_canister<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
) -> Result<(), C::Error> {
    agent
        .call(
            Principal::management_canister(),
            StopCanisterArgs {
                canister_id: canister_id.get().0,
            },
        )
        .await
}

pub async fn delete_canister<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
) -> Result<(), C::Error> {
    agent
        .call(
            Principal::management_canister(),
            DeleteCanisterArgs {
                canister_id: canister_id.get().0,
            },
        )
        .await
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
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Uploads a potentially large Wasm, in chunks of size `CHUNK_SIZE` bytes, the the chunk store
/// of `store_canister_id`.
///
/// `progress_reporter`, if supplied, is called after each successful call to `upload_chunk`.
/// - The 1st argument is the current chunk's serial number (starting from 1).
/// - The 2nd argument is the total number of chunks that are expected to be uploaded.
/// - The 3rd argument is the SHA256 sum of the chunk.
pub async fn upload_wasm<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
    wasm_bytes: Vec<u8>,
    progress_reporter: Option<fn(usize, usize, &Vec<u8>)>,
) -> Result<Vec<ChunkHash>, C::Error> {
    let num_chunks_expected = {
        let num_full_chunks = wasm_bytes.len() / CHUNK_SIZE;
        let remainder = wasm_bytes.len() % CHUNK_SIZE;
        if remainder == 0 {
            num_full_chunks
        } else {
            num_full_chunks + 1
        }
    };

    let mut uploaded_chunk_hashes = Vec::new();

    for (chunk_index, chunk) in wasm_bytes.chunks(CHUNK_SIZE).enumerate() {
        let uploaded_chunk_hash = upload_chunk(agent, store_canister_id, chunk.to_vec()).await?;

        if let Some(progress_reporter) = progress_reporter {
            progress_reporter(
                chunk_index.saturating_add(1),
                num_chunks_expected,
                &uploaded_chunk_hash.hash,
            );
        }

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
