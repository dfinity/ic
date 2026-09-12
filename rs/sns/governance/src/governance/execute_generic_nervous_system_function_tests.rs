use super::*;
use crate::{
    MAX_SCALAR_FIELD_LEN_BYTES,
    governance::test_helpers::{DoNothingLedger, basic_governance_proto, execute_proposal},
    pb::v1::nervous_system_function::{FunctionType, GenericNervousSystemFunction},
    types::test_helpers::NativeEnvironment,
};
use ic_nervous_system_canisters::cmc::FakeCmc;
use maplit::btreemap;

const TARGET_CANISTER_ID: CanisterId = CanisterId::from_u64(600);
const TARGET_METHOD: &str = "do_something";
const FUNCTION_ID: u64 = 1000;

fn new_valid_generic_nervous_system_function() -> NervousSystemFunction {
    NervousSystemFunction {
        id: FUNCTION_ID,
        name: "Test Function".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: None,
                target_canister_id: Some(TARGET_CANISTER_ID.get()),
                target_method_name: Some(TARGET_METHOD.to_string()),
                validator_canister_id: Some(TARGET_CANISTER_ID.get()),
                validator_method_name: Some(TARGET_METHOD.to_string()),
            },
        )),
    }
}

/// A proposal with a single decisive Yes ballot, ready to be executed by
/// `execute_proposal` (mirrors the pattern used by the SNS-upgrade tests in
/// `assorted_governance_tests.rs`).
fn new_ready_to_execute_proposal(payload: Vec<u8>) -> ProposalData {
    let action = Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
        function_id: FUNCTION_ID,
        payload,
    });

    ProposalData {
        action: (&action).into(),
        id: Some(1.into()),
        ballots: btreemap! {
            "neuron 1".to_string() => Ballot {
                vote: Vote::Yes as i32,
                voting_power: 9001,
                cast_timestamp_seconds: 1,
            },
        },
        wait_for_quiet_state: Some(WaitForQuietState::default()),
        proposal: Some(Proposal {
            title: "Execute Generic Nervous System Function".to_string(),
            action: Some(action),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn new_governance(proposal: ProposalData, env: NativeEnvironment) -> Governance {
    Governance::new(
        GovernanceProto {
            proposals: btreemap! { 1u64 => proposal },
            id_to_nervous_system_functions: btreemap! {
                FUNCTION_ID => new_valid_generic_nervous_system_function(),
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    )
}

#[test]
fn test_execute_generic_nervous_system_function_stores_reply_on_proposal() {
    // Step 1: Prepare the world.
    let payload = b"the-payload".to_vec();
    let expected_reply = b"the-reply-bytes".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        payload.clone(),
        Ok(expected_reply.clone()),
    );

    let mut governance = new_governance(new_ready_to_execute_proposal(payload), env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, 1);

    // Step 3: Verify result(s).
    assert_eq!(proposal_data.execution_reply, Some(expected_reply));
    assert_ne!(proposal_data.executed_timestamp_seconds, 0);
    assert_eq!(proposal_data.failure_reason, None);
}

#[test]
fn test_execute_generic_nervous_system_function_call_failure_leaves_execution_reply_unset() {
    // Step 1: Prepare the world.
    let payload = b"the-payload".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        payload.clone(),
        Err((Some(1), "target canister rejected the call".to_string())),
    );

    let mut governance = new_governance(new_ready_to_execute_proposal(payload), env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, 1);

    // Step 3: Verify result(s). Existing failure-path behavior is unchanged.
    assert_eq!(proposal_data.execution_reply, None);
    assert!(proposal_data.failure_reason.is_some());
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);
}

#[test]
fn test_execute_generic_nervous_system_function_truncates_oversized_reply() {
    // Step 1: Prepare the world.
    let payload = b"the-payload".to_vec();
    let oversized_reply = vec![7u8; MAX_SCALAR_FIELD_LEN_BYTES + 100];

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        payload.clone(),
        Ok(oversized_reply.clone()),
    );

    let mut governance = new_governance(new_ready_to_execute_proposal(payload), env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, 1);

    // Step 3: Verify result(s).
    let stored_reply = proposal_data.execution_reply.expect("reply should be set");
    assert_eq!(stored_reply.len(), MAX_SCALAR_FIELD_LEN_BYTES);
    assert_eq!(stored_reply, oversized_reply[..MAX_SCALAR_FIELD_LEN_BYTES]);
}
