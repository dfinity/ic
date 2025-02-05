use candid::Principal;
use ic_base_types::PrincipalId;
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload},
    recovery_init::RecoveryInitArgs,
    simple_node_operator_record::SimpleNodeOperatorRecord,
    Ballot, VerifyIntegirty,
};
use pocket_ic::{PocketIc, PocketIcBuilder};

use crate::tests::{get_pending, vote_with_only_ballot};

use super::{fetch_canister_wasm, get_current_node_operators, submit_proposal, NodeOperatorArg};

fn setup_and_install_canister(initial_arg: RecoveryInitArgs) -> (PocketIc, Principal) {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let app_subnets = pic.topology().get_app_subnets();

    let subnet_id = app_subnets.first().expect("Should contain one app subnet");
    let canister = pic.create_canister_on_subnet(None, None, *subnet_id);
    pic.add_cycles(canister, 100_000_000_000_000);
    let encoded = candid::encode_one(initial_arg).unwrap();
    println!("Sending: {:?}", encoded);
    println!("Size: {}", encoded.len());
    pic.install_canister(
        canister,
        fetch_canister_wasm("BACKUP_ROOT_WASM_PATH"),
        encoded,
        None,
    );

    (pic, canister)
}

fn initialize_node_operators(num: usize) -> Vec<NodeOperatorArg> {
    (0..num).map(|_| NodeOperatorArg::new(0)).collect()
}

#[test]
fn set_initial_args() {
    let initial_arg = RecoveryInitArgs {
        initial_node_operator_records: vec![SimpleNodeOperatorRecord {
            operator_id: PrincipalId::new_user_test_id(1).0,
            nodes: vec![],
        }],
    };
    let (pic, canister) = setup_and_install_canister(initial_arg);

    let node_operators = get_current_node_operators(&pic, canister);

    assert!(node_operators.len().eq(&1))
}

#[test]
fn initial_operators_should_be_able_to_place_proposals_and_vote() {
    let mut initial_node_operators = initialize_node_operators(5);
    let initial_arg = RecoveryInitArgs {
        initial_node_operator_records: initial_node_operators
            .iter()
            .map(|no| no.clone().into())
            .collect(),
    };

    let (pic, canister) = setup_and_install_canister(initial_arg);

    let first = initial_node_operators.first().unwrap();
    let response = submit_proposal(
        &pic,
        canister,
        first.principal.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );

    assert!(response.is_ok());

    // All of the operators vote on the proposal
    for operator in initial_node_operators.iter_mut() {
        let response = vote_with_only_ballot(&pic, canister, operator, Ballot::Yes);
        assert!(response.is_ok());

        // Even if their vote is efectively 0, they cannot
        // vote twice
        let response = vote_with_only_ballot(&pic, canister, operator, Ballot::Yes);
        assert!(response.is_err())
    }

    let pending = get_pending(&pic, canister);
    let last = pending.last().unwrap();
    assert!(!last.is_byzantine_majority_yes());
    assert!(last.verify().is_ok())
}
