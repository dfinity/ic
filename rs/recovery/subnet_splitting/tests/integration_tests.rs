use std::{io::Write, sync::Arc};

use candid::Encode;
use ic_management_canister_types_private::{CanisterHttpResponsePayload, HttpMethod};
use ic_registry_routing_table::CanisterIdRange;
use ic_state_machine_tests::{StateMachine, two_subnets_simple};
use ic_subnet_splitting::post_split_estimations::{Estimates, LoadEstimates, StateSizeEstimates};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{CanisterId, Cycles};
use ic_universal_canister::{call_args, wasm};
use proxy_canister::{RemoteHttpRequest, UnvalidatedCanisterHttpRequestArgs};

#[test]
/// Tests that three tools needed for subnet splitting are compatible with each other:
/// 1. `state-tool`, which extracts load metrics and manifest from the replicated state,
/// 2. TODO(CON-1569): a tool which takes the output of the `state-tool` and proposes a good split,
/// 3. `subnet-splitting-tool`, which takes the outputs from the above to tools, and returns
///    estimated loads/sizes after splitting a subnet.
fn load_metrics_e2e_test() {
    let dir = ic_test_utilities_tmpdir::tmpdir("testdir");
    let state_machine = set_up(/*canisters_count=*/ 100);
    state_machine.checkpointed_tick();
    state_machine.state_manager.flush_tip_channel();
    let state_layout = state_machine.state_manager.state_layout();
    let checkpoint_dir = std::fs::read_dir(state_layout.checkpoints())
        .unwrap()
        .last()
        .expect("There should be at least one checkpoint")
        .unwrap()
        .path();

    // Use `state-tool` to compute the state manifest.
    let manifest_path = dir.path().join("manifest.data");
    let content = ic_state_tool::commands::manifest::compute_manifest(&checkpoint_dir)
        .expect("Should compute the manifest for a valid checkpoint");
    let mut output_file = std::fs::File::create(&manifest_path).unwrap();
    write!(output_file, "{content}").unwrap();

    // Use `state-tool` to extract the canister metrics from the replicated state.
    let load_samples_path = dir.path().join("load_samples.csv");
    ic_state_tool::commands::canister_metrics::get(
        checkpoint_dir,
        state_machine.get_subnet_type(),
        &load_samples_path,
    )
    .expect("Should compute canister metrics for a valid checkpoint");

    // TODO(CON-1569): use a tool for finding a good split, once it's in the `ic-public` repo.
    // For now we use a static set of ranges.
    let mut canister_ids = state_machine.get_canister_ids();
    canister_ids.sort();
    // middle half of the canisters
    let canister_id_ranges = vec![CanisterIdRange {
        start: canister_ids[50],
        end: canister_ids[150],
    }];

    // And finally use the `subnet-splitting-tool` to estimate the loads on each subnet after a
    // split.
    let (
        StateSizeEstimates { states_sizes_bytes },
        LoadEstimates {
            instructions_used,
            ingress_messages_executed,
            xnet_messages_executed,
            intranet_messages_executed,
            http_outcalls_executed,
        },
    ) = ic_subnet_splitting::post_split_estimations::estimate(
        canister_id_ranges,
        manifest_path,
        load_samples_path,
        /*load_samples_reference_path=*/ None,
    )
    .expect("Should succeed given valid inputs");

    assert_eq!(
        states_sizes_bytes,
        Estimates {
            source: 44847850,
            destination: 46085253,
        }
    );
    assert_eq!(
        instructions_used,
        Estimates {
            source: 79165267,
            destination: 80352880,
        }
    );
    assert_eq!(
        ingress_messages_executed,
        Estimates {
            source: 196,
            destination: 203,
        }
    );
    assert_eq!(
        xnet_messages_executed,
        Estimates {
            source: 49,
            destination: 51,
        }
    );
    assert_eq!(
        intranet_messages_executed,
        Estimates {
            source: 146,
            destination: 152,
        }
    );
    assert_eq!(
        http_outcalls_executed,
        Estimates {
            source: 50,
            destination: 50,
        }
    );
}

/// Sets up two state machines which talk to each other and sends a couple of ingress messages to
/// them.
fn set_up(canisters_count: usize) -> Arc<StateMachine> {
    let (state_machine, other_state_machine) = two_subnets_simple();

    let uc_wasm_path = std::env::var("UNIVERSAL_CANISTER_WASM_PATH")
        .expect("UNIVERSAL_CANISTER_WASM_PATH not set");
    let uc_wasm = std::fs::read(&uc_wasm_path).unwrap();

    let http_outcalls_wasm_path =
        std::env::var("PROXY_WASM_PATH").expect("PROXY_WASM_PATH not set");
    let http_outcalls_wasm = std::fs::read(&http_outcalls_wasm_path).unwrap();

    let canister_id_on_the_other_subnet =
        create_canister(other_state_machine.as_ref(), uc_wasm.to_vec());

    let mut previous_canister_id = None;
    for _ in 0..canisters_count {
        let canister_id = create_canister(state_machine.as_ref(), uc_wasm.to_vec());
        let http_outcalls_canister_id =
            create_canister(state_machine.as_ref(), http_outcalls_wasm.to_vec());

        // Grow the canister a bit
        state_machine
            .execute_ingress(
                canister_id,
                "update",
                wasm()
                    .stable_grow(100)
                    .stable_write(0, &vec![1; 100_000])
                    .reply()
                    .build(),
            )
            .unwrap();

        // Tell the canister to make an http outcall.
        let msg_id = state_machine
            .submit_ingress_as(
                user_test_id(0).get(),
                http_outcalls_canister_id,
                "send_request",
                Encode!(&RemoteHttpRequest {
                    request: UnvalidatedCanisterHttpRequestArgs {
                        url: String::from("http://this.url.should_hopefully_be_invalid.ch"),
                        max_response_bytes: None,
                        headers: vec![],
                        body: None,
                        method: HttpMethod::GET,
                        transform: None,
                        is_replicated: None,
                        pricing_version: None,
                    },
                    cycles: 1_000_000_000_000,
                })
                .unwrap(),
            )
            .unwrap();
        state_machine.execute_round();
        state_machine.execute_round();
        state_machine.handle_http_call("unused", |_| CanisterHttpResponsePayload {
            status: 200,
            headers: vec![],
            body: vec![],
        });
        state_machine
            .await_ingress(msg_id, /*max_ticks=*/ 100)
            .unwrap();

        // Tell the canister to send a xnet message
        let msg_id = state_machine
            .submit_ingress_as(
                user_test_id(0).get(),
                canister_id,
                "update",
                wasm()
                    .inter_update(
                        canister_id_on_the_other_subnet,
                        call_args().other_side(wasm().build()),
                    )
                    .build(),
            )
            .unwrap();
        state_machine.execute_round();
        state_machine.execute_xnet();
        other_state_machine.execute_round();
        other_state_machine.execute_xnet();
        state_machine.execute_round();
        state_machine
            .await_ingress(msg_id, /*max_ticks=*/ 100)
            .unwrap();

        // Send an intranet message
        if let Some(previous_canister_id) = previous_canister_id {
            state_machine
                .execute_ingress(
                    canister_id,
                    "update",
                    wasm()
                        .inter_update(previous_canister_id, call_args().other_side(wasm().build()))
                        .build(),
                )
                .unwrap();
        }

        previous_canister_id = Some(canister_id);
    }

    state_machine
}

fn create_canister(state_machine: &StateMachine, module: Vec<u8>) -> CanisterId {
    let canister_id = state_machine.create_canister_with_cycles(
        /*specified_id=*/ None,
        Cycles::new(u128::MAX),
        /*settings=*/ None,
    );

    state_machine
        .install_existing_canister(canister_id, module, /*payload=*/ vec![])
        .unwrap();

    canister_id
}
