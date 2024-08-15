use candid::Encode;
use ic_state_machine_tests::StateMachine;
use std::time::Duration;

fn index_ng_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-index-ng",
        &[],
    )
}

#[test]
fn test_ledger_growing() {
    let env = &StateMachine::new();
    let index_id = env
        .install_canister(index_ng_wasm(), Encode!().unwrap(), None)
        .unwrap();

    let print_mem = || {
        use chrono::offset::Utc;
        use chrono::DateTime;
        let datetime: DateTime<Utc> = env.time().into();
        let mem = env
            .canister_status(index_id)
            .unwrap()
            .unwrap()
            .memory_size()
            .get();
        println!(
            "total memory: {}, time {}",
            mem,
            datetime.format("%d/%m/%Y %T")
        );
    };

    loop {
        env.advance_time(Duration::from_secs(1));
        env.tick();
        print_mem();
    }
}
