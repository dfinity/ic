use candid::{Decode, Encode};
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    finalize_registry, PrincipalId, StateMachineBuilder, StateMachineConfig,
};
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use slog::Level;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::sync::RwLock;

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for &byte in bytes.iter().take(8).rev() {
        result = (result << 8) | byte as u64;
    }
    result
}

fn read_main_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("FUZZ_CANISTER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn read_ledger_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("LEDGER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn main() {
    let subnets = Arc::new(RwLock::new(BTreeMap::new()));
    let config = StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig::default(),
    );
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

    let test = StateMachineBuilder::new()
        .no_dts()
        .with_log_level(Some(Level::Critical))
        .with_config(Some(config))
        .with_subnet_seed([1; 32])
        .with_registry_data_provider(registry_data_provider.clone())
        .build_with_subnets(subnets);

    // subnet x registry setup
    let subnet_id = test.get_subnet_id();
    let range = CanisterIdRange {
        start: CanisterId::from_u64(0),
        end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
    };
    let mut routing_table = RoutingTable::new();
    routing_table.insert(range, subnet_id).unwrap();
    let subnet_list = vec![subnet_id];

    finalize_registry(
        subnet_id,
        routing_table,
        subnet_list,
        registry_data_provider,
    );

    test.reload_registry();

    // Install ledger canister
    let ledger_canister_id = test
        .install_canister_with_cycles(
            read_ledger_canister_bytes(),
            vec![],
            None,
            Cycles::new(5_000_000_000_000),
        )
        .unwrap();

    // Install main canister
    let main_canister_id = test
        .install_canister_with_cycles(
            read_main_canister_bytes(),
            Encode!(&ledger_canister_id).unwrap(),
            None,
            Cycles::new(5_000_000_000_000),
        )
        .unwrap();

    // Prepare the main canister
    // Adds a local balance of 10_000_000 to anonymous principal
    test.execute_ingress(main_canister_id, "update_balance", Encode!().unwrap())
        .unwrap();

    // Prepare the ledger canister
    // Adds a ledger balance of 10_000_000 to main_canister_id
    test.execute_ingress(
        ledger_canister_id,
        "setup_balance",
        Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
    )
    .unwrap();

    // Assert both balances match
    let b1 = match test
        .query(main_canister_id, "get_total_balance", Encode!().unwrap())
        .unwrap()
    {
        WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    let b2 = match test.query(
        ledger_canister_id,
        "get_balance",
        Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
    ) {
        Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    // should never fail
    assert_eq!(b1, b2);

    let bytes = include_bytes!("/ic/rs/canister_fuzzing/trap_after_await/crashes/b9a09e1886048420");
    let trap = bytes_to_u64(bytes) % 500_000;
    println!("Trap {}", trap);
    // let trap = 3278_u64;

    // Synchronous setup ABAB
    for _ in 0..2 {
        let _result = test.execute_ingress_as(
            PrincipalId::new_anonymous(),
            main_canister_id,
            "refund_balance",
            Encode!(&trap).unwrap(),
        );
    }

    // Asynchronous setup AABB
    // for _ in 0..2 {
    //     let _messaage_id = test
    //         .submit_ingress_as(
    //             PrincipalId::new_anonymous(),
    //             main_canister_id,
    //             "refund_balance",
    //             Encode!(&trap).unwrap(),
    //         )
    //         .unwrap();
    // }
    // test.execute_round();

    // Assert both balances match
    let b1 = match test
        .query(main_canister_id, "get_total_balance", Encode!().unwrap())
        .unwrap()
    {
        WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    let b2 = match test.query(
        ledger_canister_id,
        "get_balance",
        Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
    ) {
        Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
        _ => panic!("Unable to get result"),
    };

    // can fail
    if b1 != b2 {
        println!("Results fail b1 : {}, b2 : {}", b1, b2);
        panic!("Ledger balance doesn't match");
    }
}
