mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn test_management_canister() {
    let wasm = cargo_build_canister("management_canister");
    // Setup pocket-ic with an II subnet which is required by the "provisional" test.
    let pic = pic_base().with_ii_subnet().build();

    let canister_id = pic.create_canister();
    let subnet_id = pic.get_subnet(canister_id).unwrap();
    pic.add_cycles(canister_id, 10_000_000_000_000u128); // 10 T
    pic.install_canister(canister_id, wasm.clone(), vec![], None);
    let () = update(&pic, canister_id, "basic", ()).unwrap();
    let () = update(&pic, canister_id, "env_var", ()).unwrap();
    let () = update(&pic, canister_id, "ecdsa", ()).unwrap();
    let () = update(&pic, canister_id, "schnorr", ()).unwrap();
    let () = update(&pic, canister_id, "metrics", (subnet_id,)).unwrap();
    let () = update(&pic, canister_id, "subnet", (subnet_id,)).unwrap();
    let () = update(&pic, canister_id, "snapshots", ()).unwrap();

    // provisional
    // Install the test canister on the II subnet, so that it can provisional create canisters on the same subnet.
    let ii_subnet_id = pic.topology().get_ii().unwrap();
    let canister_id_on_ii = pic.create_canister_on_subnet(None, None, ii_subnet_id);
    pic.add_cycles(canister_id_on_ii, 10_000_000_000_000u128); // 10 T
    pic.install_canister(canister_id_on_ii, wasm, vec![], None);
    let () = update(&pic, canister_id_on_ii, "provisional", ()).unwrap();

    // vetkd
    const VETKD_TRANSPORT_SECRET_KEY_SEED: [u8; 32] = [13; 32];
    let transport_key =
        ic_vetkd_utils::TransportSecretKey::from_seed(VETKD_TRANSPORT_SECRET_KEY_SEED.to_vec())
            .expect("Failed to generate transport secret key");
    let transport_public_key = transport_key.public_key();
    let () = update(&pic, canister_id, "vetkd", (transport_public_key,)).unwrap();
}
