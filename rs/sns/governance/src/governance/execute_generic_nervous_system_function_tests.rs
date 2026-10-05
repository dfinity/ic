use super::*;
use crate::{
    MAX_SCALAR_FIELD_LEN_BYTES,
    governance::test_helpers::{DoNothingLedger, basic_governance_proto, execute_proposal},
    pb::v1::nervous_system_function::{FunctionType, GenericNervousSystemFunction},
    types::test_helpers::NativeEnvironment,
};
use ic_nervous_system_canisters::cmc::FakeCmc;
use lazy_static::lazy_static;
use maplit::btreemap;

const TARGET_CANISTER_ID: CanisterId = CanisterId::from_u64(600);
const TARGET_METHOD: &str = "do_something";
const VALIDATOR_METHOD: &str = "validate_do_something";
const FUNCTION_ID: u64 = 1000;
const PAYLOAD: &[u8] = b"the-payload";

lazy_static! {
    static ref VALID_GENERIC_NERVOUS_SYSTEM_FUNCTION: NervousSystemFunction =
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
                    validator_method_name: Some(VALIDATOR_METHOD.to_string()),
                },
            )),
        };

    // A proposal with one Yes vote, ready for `execute_proposal` to run (same
    // pattern as the SNS-upgrade tests in `assorted_governance_tests.rs`).
    static ref READY_TO_EXECUTE_PROPOSAL: ProposalData = {
        let action =
            Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
                function_id: FUNCTION_ID,
                payload: PAYLOAD.to_vec(),
            });

        ProposalData {
            action: u64::from(&action),
            id: Some(ProposalId { id: 1 }),
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
    };
}

fn new_governance(proposal: ProposalData, env: NativeEnvironment) -> Governance {
    Governance::new(
        GovernanceProto {
            proposals: btreemap! { 1_u64 => proposal },
            id_to_nervous_system_functions: btreemap! {
                FUNCTION_ID => VALID_GENERIC_NERVOUS_SYSTEM_FUNCTION.clone(),
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
    let expected_reply = b"the-reply-bytes".to_vec();

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        PAYLOAD.to_vec(),
        Ok(expected_reply.clone()),
    );

    let mut governance = new_governance(READY_TO_EXECUTE_PROPOSAL.clone(), env);

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
    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        PAYLOAD.to_vec(),
        Err((Some(1), "target canister rejected the call".to_string())),
    );

    let mut governance = new_governance(READY_TO_EXECUTE_PROPOSAL.clone(), env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, 1);

    // Step 3: Verify result(s). Existing failure-path behavior is unchanged.
    assert_eq!(proposal_data.execution_reply, None);

    let failure_reason = proposal_data
        .failure_reason
        .expect("failure_reason should be set");
    assert_eq!(failure_reason.error_type, ErrorType::External as i32);

    assert_eq!(proposal_data.executed_timestamp_seconds, 0);
}

#[test]
fn test_execute_generic_nervous_system_function_truncates_oversized_reply() {
    // Step 1: Prepare the world.
    let oversized_reply = vec![7_u8; MAX_SCALAR_FIELD_LEN_BYTES + 100];

    let mut env = NativeEnvironment::default();
    env.set_call_canister_response(
        TARGET_CANISTER_ID,
        TARGET_METHOD,
        PAYLOAD.to_vec(),
        Ok(oversized_reply.clone()),
    );

    let mut governance = new_governance(READY_TO_EXECUTE_PROPOSAL.clone(), env);

    // Step 2: Run the code under test.
    let proposal_data = execute_proposal(&mut governance, 1);

    // Step 3: Verify result(s).
    let stored_reply = proposal_data.execution_reply.expect("reply should be set");
    assert_eq!(stored_reply.len(), MAX_SCALAR_FIELD_LEN_BYTES);
    assert_eq!(stored_reply, oversized_reply[..MAX_SCALAR_FIELD_LEN_BYTES]);
    assert_ne!(proposal_data.executed_timestamp_seconds, 0);
    assert_eq!(proposal_data.failure_reason, None);
}
