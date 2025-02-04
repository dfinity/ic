use candid::Principal;
use ic_nns_handler_recovery::recovery_proposal::{
    Ballot, NewRecoveryProposal, RecoveryPayload, VoteOnRecoveryProposal,
};
use ic_registry_subnet_type::SubnetType;
use pocket_ic::PocketIc;

use crate::tests::{get_pending, vote};

use super::{
    extract_node_operators_from_init_data, init_pocket_ic, submit_proposal,
    RegistryPreparationArguments,
};

// First proposal tests
// TODO: Allow to place multiple recover subnets proposals
#[test]
fn place_first_proposal() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let first = node_operators.keys().next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );

    assert!(response.is_ok());

    let response = vote(
        &pic,
        canister,
        first.0.clone(),
        VoteOnRecoveryProposal {
            payload: "Not important yet".as_bytes().to_vec(),
            signature: "Not important yet".as_bytes().to_vec(),
            ballot: Ballot::Yes,
        },
    );
    assert!(response.is_ok());

    let pending_proposals = get_pending(&pic, canister);

    assert!(pending_proposals.len().eq(&1));
    let only_proposal = pending_proposals.first().unwrap();

    let registered_votes: Vec<_> = only_proposal
        .node_operator_ballots
        .iter()
        .filter(|ballot| ballot.ballot != Ballot::Undecided)
        .collect();

    assert!(registered_votes.len().eq(&1));

    let only_vote = registered_votes.first().unwrap();
    assert_eq!(only_vote.ballot, Ballot::Yes);

    let number_of_nodes_for_first = node_operators.get(first).unwrap();
    assert!(only_vote
        .nodes_tied_to_ballot
        .len()
        .eq(&(*number_of_nodes_for_first as usize)));
    assert_eq!(&only_vote.principal, first)
}

#[test]
fn place_non_halt_first_proposal() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let first = node_operators.keys().next().unwrap();

    let invalid_first_proposals = vec![
        NewRecoveryProposal {
            payload: RecoveryPayload::DoRecovery {
                height: 123,
                state_hash: "123".to_string(),
            },
        },
        NewRecoveryProposal {
            payload: RecoveryPayload::Unhalt,
        },
    ];

    for proposal in invalid_first_proposals {
        let response = submit_proposal(&pic, canister, first.0.clone(), proposal);

        assert!(response.is_err());
        let pending_proposals = get_pending(&pic, canister);
        assert!(pending_proposals.is_empty());
    }
}

#[test]
fn replace_first_proposal_after_voting_no_on_the_first() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_ok());

    // Try resubmitting
    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_err());

    // To achieve byzantine majority in default setup 7
    // node operators should vote "no"
    // This will remove the proposal
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                payload: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::No,
            },
        );

        assert!(response.is_ok());
    }

    // Resubmit
    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_ok());
}

#[test]
fn disallow_unknown_node_operators_from_placing_proposals() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let response = submit_proposal(
        &pic,
        canister,
        Principal::anonymous(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_err());
}

#[test]
fn disallow_node_operators_from_different_subnets_from_placing_proposals() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let non_system_subnet = args
        .subnet_node_operators
        .iter()
        .find_map(|subnet| match !subnet.subnet_type.eq(&SubnetType::System) {
            false => None,
            true => Some(subnet.node_operators.clone()),
        })
        .unwrap();
    let first_node_operator = non_system_subnet.keys().next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first_node_operator.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_err());
}

// Second proposal tests
fn place_and_execute_first_proposal(
    args: &mut RegistryPreparationArguments,
) -> (PocketIc, Principal) {
    let (pic, canister) = init_pocket_ic(args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_ok());

    // To achieve byzantine majority in default setup 7
    // node operators should vote "Yes"
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
                payload: "Not important yet".as_bytes().to_vec(),
            },
        );

        assert!(response.is_ok());
    }

    let pending_proposals = get_pending(&pic, canister);
    let first_proposal = pending_proposals.first().unwrap();
    assert!(first_proposal.is_byzantine_majority_yes());
    (pic, canister)
}

#[test]
fn place_second_proposal_recovery() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    let pending_proposals = get_pending(&pic, canister);
    let latest_proposal = pending_proposals.last().unwrap();
    assert!(latest_proposal.payload.eq(&new_proposal.payload));
    assert!(
        !latest_proposal.is_byzantine_majority_no() && !latest_proposal.is_byzantine_majority_yes()
    )
}

#[test]
fn place_second_proposal_unhalt() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    let pending_proposals = get_pending(&pic, canister);
    let latest_proposal = pending_proposals.last().unwrap();
    assert!(latest_proposal.payload.eq(&new_proposal.payload));
    assert!(
        !latest_proposal.is_byzantine_majority_no() && !latest_proposal.is_byzantine_majority_yes()
    )
}

#[test]
fn place_second_proposal_halt() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );
    assert!(response.is_err());
}

#[test]
fn second_proposal_vote_against() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the second
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 votes to vote against this
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::No,
                payload: "Not important yet".as_bytes().to_vec(),
            },
        );
        assert!(response.is_ok())
    }

    let pending = get_pending(&pic, canister);
    assert!(pending.len().eq(&1))
}

#[test]
fn second_proposal_recovery_vote_in() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the second
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 to vote in
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
                payload: "Not important yet".as_bytes().to_vec(),
            },
        );
        assert!(response.is_ok())
    }

    let pending = get_pending(&pic, canister);
    assert!(pending.len().eq(&2));
    let latest_proposal = pending.last().unwrap();
    assert!(latest_proposal.is_byzantine_majority_yes())
}

#[test]
fn second_proposal_recovery_vote_in_and_resubmit() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the second
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 to vote in
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
                payload: "Not important yet".as_bytes().to_vec(),
            },
        );
        assert!(response.is_ok())
    }

    let resubmitted_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 456,
            state_hash: "456".to_string(),
        },
    };
    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        resubmitted_proposal.clone(),
    );
    assert!(response.is_ok());

    let pending = get_pending(&pic, canister);
    assert!(pending.len().eq(&2));

    let last = pending.last().unwrap();
    assert!(!last.is_byzantine_majority_no() && !last.is_byzantine_majority_yes());
    assert_eq!(last.payload, resubmitted_proposal.payload)
}

#[test]
fn second_proposal_unhalt_vote_in() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the second
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 to vote it in
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
                payload: "Not important yet".as_bytes().to_vec(),
            },
        );
        assert!(response.is_ok())
    }

    let pending = get_pending(&pic, canister);
    assert!(pending.is_empty());
}

// Third proposal tests
#[test]
fn submit_first_two_second_not_voted_in_place_third() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_first_proposal(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the second
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // Place the third
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_err());
}

fn place_and_execute_second_proposal(
    args: &mut RegistryPreparationArguments,
) -> (PocketIc, Principal) {
    let (pic, canister) = place_and_execute_first_proposal(args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the second
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 to vote it in
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                payload: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
            },
        );
        assert!(response.is_ok())
    }

    let pending = get_pending(&pic, canister);
    assert!(pending.len().eq(&2));
    let latest = pending.last().unwrap();
    assert!(latest.is_byzantine_majority_yes());
    (pic, canister)
}

#[test]
fn submit_first_two_second_voted_in_place_third() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_second_proposal(&mut args);
    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the third
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    let pending = get_pending(&pic, canister);
    assert!(pending.len().eq(&3));
    let latest = pending.last().unwrap();
    assert!(!latest.is_byzantine_majority_no() && !latest.is_byzantine_majority_yes())
}

#[test]
fn vote_against_last_proposal() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_second_proposal(&mut args);
    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the third
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 votes to vote against this proposal
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                payload: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::No,
            },
        );

        assert!(response.is_ok())
    }

    let pending = get_pending(&pic, canister);
    assert!(pending.len().eq(&2));
    let latest = pending.last().unwrap();
    // Poping the 3rd proposal doesn't affect the 2nd
    assert!(latest.is_byzantine_majority_yes());
}

#[test]
fn vote_in_last_proposal() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_second_proposal(&mut args);
    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the third
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    // We need 7 votes to vote for this proposal
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                payload: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
            },
        );

        assert!(response.is_ok())
    }

    // Reset back to the initial state
    let pending = get_pending(&pic, canister);
    assert!(pending.is_empty());
}

// Nth proposal tests
#[test]
fn place_any_proposal_after_there_are_three() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = place_and_execute_second_proposal(&mut args);
    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    // Place the third
    let new_proposal = NewRecoveryProposal {
        payload: RecoveryPayload::Unhalt,
    };
    let response = submit_proposal(&pic, canister, first.0.clone(), new_proposal.clone());
    assert!(response.is_ok());

    let payloads = vec![
        RecoveryPayload::Halt,
        RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
        },
        RecoveryPayload::Unhalt,
    ];
    for payload in payloads {
        let response = submit_proposal(
            &pic,
            canister,
            first.0.clone(),
            NewRecoveryProposal { payload },
        );

        assert!(response.is_err())
    }
}
