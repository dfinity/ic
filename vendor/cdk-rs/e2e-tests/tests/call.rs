mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn call() {
    let wasm = cargo_build_canister("call");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    let _: () = update(&pic, canister_id, "call_foo", ()).unwrap();
    let _: () = update(&pic, canister_id, "call_echo", ()).unwrap();
    let _: () = update(&pic, canister_id, "retry_calls", ()).unwrap();
    let _: () = update(&pic, canister_id, "join_calls", ()).unwrap();
    let _: () = update(
        &pic,
        canister_id,
        "insufficient_liquid_cycle_balance_error",
        (),
    )
    .unwrap();

    let _: () = update(&pic, canister_id, "call_error_ext", ()).unwrap();
}
