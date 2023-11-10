use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_ic00_types::{EcdsaCurve, EcdsaKeyId};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::types::ids::{subnet_test_id, user_test_id};
use ic_types::{
    ingress::{IngressStatus, WasmResult},
    CanisterId, Cycles, SubnetId,
};
use ic_universal_canister::{wasm, CallArgs, UNIVERSAL_CANISTER_WASM};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

fn test_setup(
    subnets: Arc<RwLock<HashMap<SubnetId, Arc<StateMachine>>>>,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    subnet_list: Vec<SubnetId>,
    routing_table: RoutingTable,
    now: std::time::SystemTime,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
) -> Arc<StateMachine> {
    let config =
        StateMachineConfig::new(SubnetConfig::new(subnet_type), HypervisorConfig::default());
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_id(subnet_id)
        .with_subnet_list(subnet_list)
        .with_routing_table(routing_table)
        .with_registry_data_provider(registry_data_provider)
        .with_ecdsa_keys(vec![EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: format!("master_ecdsa_public_key_{}", subnet_id),
        }])
        .build_with_subnets(subnets);
    env.set_time(now);
    env
}

#[test]
fn counter_canister_call_test() {
    const MAX_TICKS: usize = 100;
    let user_id = user_test_id(1).get();

    // Set up routing table with two subnets.
    let subnet_id1 = subnet_test_id(1);
    let subnet_id2 = subnet_test_id(2);
    let range1 = CanisterIdRange {
        start: CanisterId::from_u64(0),
        end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
    };
    let range2 = CanisterIdRange {
        start: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET),
        end: CanisterId::from_u64(2 * CANISTER_IDS_PER_SUBNET - 1),
    };
    let mut routing_table = RoutingTable::new();
    routing_table.insert(range1, subnet_id1).unwrap();
    routing_table.insert(range2, subnet_id2).unwrap();

    // Set up subnet list for registry.
    let subnet_list = vec![subnet_id1, subnet_id2];

    // Set up registry data provider.
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

    // Set up the two state machines for the two (app) subnets.
    let subnets = Arc::new(RwLock::new(HashMap::new()));
    let now = std::time::SystemTime::now();
    let env1 = test_setup(
        subnets.clone(),
        subnet_id1,
        SubnetType::Application,
        subnet_list.clone(),
        routing_table.clone(),
        now,
        registry_data_provider.clone(),
    );
    let env2 = test_setup(
        subnets.clone(),
        subnet_id2,
        SubnetType::Application,
        subnet_list,
        routing_table,
        now,
        registry_data_provider.clone(),
    );

    // Reload registry on the two state machines to make sure
    // the registry contains all subnet records
    // added incrementally to the registry data provider
    // when creating the individual state machines.
    env1.reload_registry();
    env2.reload_registry();

    // Create a canister on each of the two subnets.
    let canister_id1 = env1
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let canister_id2 = env2
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Make a self-call with a large argument.
    let msg_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id1,
                    CallArgs::default().eval_other_side(
                        wasm()
                            .push_bytes_wasm_push_bytes_and_reply(10_000_000)
                            .build(),
                    ),
                )
                .build(),
        )
        .unwrap();
    env1.execute_round();
    let wasm_result = env1.await_ingress(msg_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, 10_000_000_u32.to_le_bytes()),
        _ => panic!("unreachable"),
    };

    // Make a xnet-call with too large argument.
    let msg_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().eval_other_side(
                        wasm()
                            .push_bytes_wasm_push_bytes_and_reply(10_000_000)
                            .build(),
                    ),
                )
                .build(),
        )
        .unwrap();
    env1.execute_round();
    let wasm_result = env1.await_ingress(msg_id, MAX_TICKS).unwrap();
    match wasm_result {
        // The call fails with CANISTER_ERROR reject code (5).
        WasmResult::Reject(reject) => assert_eq!(reject.as_bytes(), 5_u32.to_le_bytes().to_vec()),
        _ => panic!("unreachable"),
    };

    // Set global data on the 1st subnet.
    let msg1_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .set_global_data(&vec![42; 2000000])
                .get_global_data()
                .append_and_reply()
                .build(),
        )
        .unwrap();
    env1.execute_round();
    let wasm_result = env1.await_ingress(msg1_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![42; 2000000]),
        _ => panic!("unreachable"),
    };

    // Set global data on the 2nd subnet.
    let msg2_id = env2
        .submit_ingress_as(
            user_id,
            canister_id2,
            "update",
            wasm()
                .set_global_data(&vec![123; 2000000])
                .get_global_data()
                .append_and_reply()
                .build(),
        )
        .unwrap();
    env2.execute_round();
    let wasm_result = env2.await_ingress(msg2_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![123; 2000000]),
        _ => panic!("unreachable"),
    };

    // Invoke a method on the 1st subnet calling into the 2nd subnet.
    let msg3_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(wasm().get_global_data().append_and_reply()),
                )
                .build(),
        )
        .unwrap();

    // We execute a round on the 1st subnet to start processing the ingress message,
    // then we execute a round on the 2nd subnet to process the downstream
    // inter-canister call, and finally we execute a round on the 1st subnet
    // to process the callback of the inter-canister call and finish processing
    // the ingress message.
    env1.execute_round();
    env2.execute_round();
    env1.execute_round();

    let wasm_result = env1.await_ingress(msg3_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![123; 2000000]),
        _ => panic!("unreachable"),
    };

    // Invoke a method on the 1st subnet calling into the 2nd subnet multiple times.
    let msg10_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![0; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();
    let msg11_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![1; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();
    let msg12_id = env1
        .submit_ingress_as(
            user_id,
            canister_id1,
            "update",
            wasm()
                .inter_update(
                    canister_id2,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![2; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();

    // Invoke a method on the 2nd subnet calling into the 1st subnet.
    let msg20_id = env2
        .submit_ingress_as(
            user_id,
            canister_id2,
            "update",
            wasm()
                .inter_update(
                    canister_id1,
                    CallArgs::default().other_side(
                        wasm()
                            .set_global_data(&vec![3; 2000000])
                            .get_global_data()
                            .append_and_reply(),
                    ),
                )
                .build(),
        )
        .unwrap();

    // This time we need to execute multiple rounds on the 1st subnet
    // to induct all ingress messages with large payloads.
    // In particular, the third ingress message is not yet picked up
    // from the ingress pool after a single round.
    env1.execute_round();
    assert!(matches!(
        env1.ingress_status(&msg10_id),
        IngressStatus::Known { .. }
    ));
    assert!(matches!(
        env1.ingress_status(&msg11_id),
        IngressStatus::Known { .. }
    ));
    assert!(matches!(
        env1.ingress_status(&msg12_id),
        IngressStatus::Unknown
    ));
    // The third ingress message is only inducted after a repeated
    // call to execute a round.
    env1.execute_round();
    assert!(matches!(
        env1.ingress_status(&msg12_id),
        IngressStatus::Known { .. }
    ));
    // We also need execute to multiple rounds on the 2nd subnet
    // to induct the ingress message with large payload
    // and all three inter-canister calls with large arguments
    // from the 1st subnet.
    env2.execute_round();
    assert!(matches!(
        env2.ingress_status(&msg20_id),
        IngressStatus::Known { .. }
    ));
    env2.execute_round();
    env2.execute_round();
    // Finally, we need to execute multiple rounds on the 1st subnet
    // to induct all (large) responses from the 2nd subnet
    // and an inter-canister call from the 2nd into the 1st subnet
    // with large argument.
    env1.execute_round();
    env1.execute_round();
    env1.execute_round();
    env1.execute_round();

    let wasm_result = env1.await_ingress(msg10_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![0; 2000000]),
        _ => panic!("unreachable"),
    };
    let wasm_result = env1.await_ingress(msg11_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![1; 2000000]),
        _ => panic!("unreachable"),
    };
    let wasm_result = env1.await_ingress(msg12_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![2; 2000000]),
        _ => panic!("unreachable"),
    };

    // This time, we also need to execute one more round on the 2nd subnet
    // to process the response callback of the inter-canister call
    // to the 1st subnet.
    env2.execute_round();

    let wasm_result = env2.await_ingress(msg20_id, MAX_TICKS).unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => assert_eq!(bytes, vec![3; 2000000]),
        _ => panic!("unreachable"),
    };
}
