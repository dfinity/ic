use pocket_ic::query_candid;
use serde_bytes::ByteBuf;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

/// Checks that a canister that uses [`ic_cdk::storage::stable_save`]
/// and [`ic_cdk::storage::stable_restore`] functions can keep its data
/// across upgrades.
#[test]
fn test_storage_roundtrip() {
    let wasm = cargo_build_canister("simple_kv_store");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm.clone(), vec![], None);

    let () = update(&pic, canister_id, "insert", (&"candid", &b"did"))
        .expect("failed to insert 'candid'");

    pic.upgrade_canister(canister_id, wasm, vec![], None)
        .expect("failed to upgrade the simple_kv_store canister");

    let (result,): (Option<ByteBuf>,) =
        query_candid(&pic, canister_id, "lookup", (&"candid",)).expect("failed to lookup 'candid'");
    assert_eq!(result, Some(ByteBuf::from(b"did".to_vec())));
}
