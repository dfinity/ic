use candid::Principal;
use pocket_ic::PocketIcBuilder;

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

fn benchmark() {
    let pocket_ic = PocketIcBuilder::new()
        .with_max_request_time_ms(None)
        .with_benchmarking_application_subnet()
        .build();
    let canister_id = pocket_ic.create_canister();
    pocket_ic.add_cycles(canister_id, 1_000_000_000_000_000);
    pocket_ic.install_canister(canister_id, test_canister_wasm(), vec![], None);
    pocket_ic
        .query_call(
            canister_id,
            Principal::anonymous(),
            "run",
            b"DIDL\x00\x00".to_vec(),
        )
        .unwrap();
}

#[test]
fn poc() {
    for _ in 0..10 {
        let start = std::time::Instant::now();
        benchmark();
        println!("elapsed: {:?}", start.elapsed());
    }
    assert!(false);
}
