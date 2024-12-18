use candid::{Decode, Encode};
use canister_test::Project;
use downstream_calls_test::{CallOrResponse, State};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, WasmResult};
use ic_test_utilities_metrics::fetch_histogram_stats;
use ic_test_utilities_types::ids::SUBNET_0;
use ic_types::Cycles;
use std::collections::VecDeque;

struct CallTreeTestFixture(StateMachine);

impl CallTreeTestFixture {
    /// Creates a new state machine with a specific number of 'downstream-calls-test-canisters`
    /// installed and started.
    fn with_num_canisters(num_canisters: u64) -> (Self, Vec<CanisterId>) {
        let env = StateMachineBuilder::new()
            .with_subnet_id(SUBNET_0)
            .with_subnet_type(SubnetType::Application)
            .with_routing_table({
                let mut routing_table = RoutingTable::new();
                routing_table_insert_subnet(&mut routing_table, SUBNET_0).unwrap();
                routing_table
            })
            .build();

        // Install `num_canisters` canisters.
        let wasm = Project::cargo_bin_maybe_from_env("downstream-calls-test-canister", &[]).bytes();
        let canister_ids = (0..num_canisters)
            .map(|_| {
                env.install_canister_with_cycles(
                    wasm.clone(),
                    Vec::new(),
                    None,
                    Cycles::new(u128::MAX / 2),
                )
                .expect("Installing downstream-calls-test-canister failed")
            })
            .collect::<Vec<_>>();

        // Start canisters.
        for canister_id in canister_ids.iter() {
            env.start_canister(*canister_id)
                .expect("failed to start canister");
        }

        (Self(env), canister_ids)
    }

    /// Runs a test using an action sequence (a list of call and response commands) and an entry
    /// canister Id.
    ///
    /// The test is iniated by an ingress message to the entry canister. From there the actions
    /// list is passed from canister to canister until it is exhausted, after which responses are
    /// handed down until they eventually form the response to the initiating ingress message.
    ///
    /// While traversing the call tree corresponding to the actions list, the number of calls made
    /// and the sum of the call depth at which they are made is kept track of. After the fact,
    /// these counters should match the stats tracked in the metrics for
    /// 'execution_environment_request_call_tree_depth'.
    fn run_actions_sequence_test(
        &self,
        entry_canister_id: CanisterId,
        actions: VecDeque<CallOrResponse>,
    ) {
        let payload = Encode!(&State {
            actions,
            call_count: 0,
            current_depth: 0,
            depth_total: 0,
        })
        .unwrap();

        let result = self
            .0
            .execute_ingress_as(
                PrincipalId::new_anonymous(),
                entry_canister_id,
                "reply_or_defer",
                payload,
            )
            .unwrap();

        if let WasmResult::Reply(msg) = result {
            let state = Decode!(&msg, State).unwrap();
            let stats = fetch_histogram_stats(
                self.0.metrics_registry(),
                "execution_environment_request_call_tree_depth",
            )
            .unwrap();

            assert_eq!(state.call_count, stats.count);
            assert_eq!(state.depth_total as f64, stats.sum);
        } else {
            unreachable!();
        }
    }
}

/// Test the metrics are recorded as expected for a sequence of canisters.
/// ```text
/// tree:              call tree depth:
///
/// ingress              _
///    \
///     A                0
///      \
///       B              1
///        \
///         C            2
///          \
///           D          3
///            \
///             E        4
/// ```
#[test]
fn test_linear_sequence_call_tree_depth() {
    use CallOrResponse::*;
    let (fixture, mut canister_ids) = CallTreeTestFixture::with_num_canisters(5);
    let entry_canister_id = canister_ids.pop().unwrap();

    fixture.run_actions_sequence_test(
        entry_canister_id, // Call A.
        [
            Call(canister_ids[0]), // Call B from A.
            Call(canister_ids[1]), // Call C from B.
            Call(canister_ids[2]), // Call D from C.
            Call(canister_ids[3]), // Call E from D.
        ]
        .into(),
    );
}

/// Test the metrics are recorded as expected for a call tree with multiple branches.
/// ```text
/// tree:            call tree depth:
///
///    ingress         _
///       |
///       A            0
///      / \
///     B   C          1
///        / \
///       D   E        2
/// ```
#[test]
fn test_multiple_branches_call_tree_depth() {
    use CallOrResponse::*;
    let (fixture, mut canister_ids) = CallTreeTestFixture::with_num_canisters(5);
    let entry_canister_id = canister_ids.pop().unwrap();

    fixture.run_actions_sequence_test(
        entry_canister_id, // Call A.
        [
            Call(canister_ids[0]), // Call B from A.
            Response,              // Response from B, back to A.
            Call(canister_ids[1]), // Call C from A.
            Call(canister_ids[2]), // Call D from C.
            Response,              // Response from D, back to C.
            Call(canister_ids[3]), // Call E from C.
        ]
        .into(),
    );
}
