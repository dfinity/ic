use candid::Principal;
use ic_cdk::management_canister::{
    clear_chunk_store, create_canister_with_extra_cycles, install_chunked_code, stored_chunks,
    upload_chunk, CanisterInstallMode, ChunkHash, ClearChunkStoreArgs, CreateCanisterArgs,
    InstallChunkedCodeArgs, StoredChunksArgs, UploadChunkArgs,
};
use ic_cdk::update;

#[update]
async fn call_create_canister() -> Principal {
    create_canister_with_extra_cycles(&CreateCanisterArgs::default(), 1_000_000_000_000u128)
        .await
        .unwrap()
        .canister_id
}

#[update]
async fn call_upload_chunk(canister_id: Principal, chunk: Vec<u8>) -> Vec<u8> {
    let arg = UploadChunkArgs {
        canister_id,
        chunk: chunk.clone(),
    };
    upload_chunk(&arg).await.unwrap().hash
}

#[update]
async fn call_stored_chunks(canister_id: Principal) -> Vec<Vec<u8>> {
    let arg = StoredChunksArgs { canister_id };
    let hashes = stored_chunks(&arg).await.unwrap();
    hashes.into_iter().map(|v| v.hash).collect()
}

#[update]
async fn call_clear_chunk_store(canister_id: Principal) {
    let arg = ClearChunkStoreArgs { canister_id };
    clear_chunk_store(&arg).await.unwrap();
}

#[update]
async fn call_install_chunked_code(
    canister_id: Principal,
    chunk_hashes_list: Vec<Vec<u8>>,
    wasm_module_hash: Vec<u8>,
) {
    let chunk_hashes_list = chunk_hashes_list
        .iter()
        .map(|v| ChunkHash { hash: v.clone() })
        .collect();
    let arg = InstallChunkedCodeArgs {
        mode: CanisterInstallMode::Install,
        target_canister: canister_id,
        store_canister: None,
        chunk_hashes_list,
        wasm_module_hash,
        arg: vec![],
    };
    install_chunked_code(&arg).await.unwrap();
}

fn main() {}
