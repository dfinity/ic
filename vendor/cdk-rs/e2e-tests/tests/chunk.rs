use candid::Principal;
use sha2::Digest;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn test_chunk() {
    let wasm = cargo_build_canister("chunk");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    let (target_canister_id,): (Principal,) =
        update(&pic, canister_id, "call_create_canister", ()).unwrap();

    let wasm_module = b"\x00asm\x01\x00\x00\x00".to_vec();
    let wasm_module_hash = sha2::Sha256::digest(&wasm_module).to_vec();
    let chunk1 = wasm_module[..4].to_vec();
    let chunk2 = wasm_module[4..].to_vec();
    let hash1_expected = sha2::Sha256::digest(&chunk1).to_vec();
    let hash2_expected = sha2::Sha256::digest(&chunk2).to_vec();

    let (hash1_return,): (Vec<u8>,) = update(
        &pic,
        canister_id,
        "call_upload_chunk",
        (target_canister_id, chunk1.clone()),
    )
    .unwrap();
    assert_eq!(&hash1_return, &hash1_expected);

    let () = update(
        &pic,
        canister_id,
        "call_clear_chunk_store",
        (target_canister_id,),
    )
    .unwrap();

    let (_hash1_return,): (Vec<u8>,) = update(
        &pic,
        canister_id,
        "call_upload_chunk",
        (target_canister_id, chunk1),
    )
    .unwrap();
    let (_hash2_return,): (Vec<u8>,) = update(
        &pic,
        canister_id,
        "call_upload_chunk",
        (target_canister_id, chunk2),
    )
    .unwrap();

    let (hashes,): (Vec<Vec<u8>>,) = update(
        &pic,
        canister_id,
        "call_stored_chunks",
        (target_canister_id,),
    )
    .unwrap();
    // the hashes returned are not guaranteed to be in order
    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains(&hash1_expected));
    assert!(hashes.contains(&hash2_expected));

    let () = update(
        &pic,
        canister_id,
        "call_install_chunked_code",
        (
            target_canister_id,
            // the order of the hashes matters
            vec![hash1_expected, hash2_expected],
            wasm_module_hash,
        ),
    )
    .unwrap();
}
