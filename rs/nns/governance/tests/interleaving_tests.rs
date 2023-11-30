//! Tests that rely on interleaving two method calls on the governance canister
//! (in particular, when one method is suspended when it calls out to the ledger
//! canister).
use crate::interleaving::{
    drain_receiver_channel,
    test_data::{
        CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL, GET_SNS_CANISTERS_SUMMARY_RESPONSE,
        GET_STATE_RESPONSE, LIST_DEPLOYED_SNSES_RESPONSE, OPEN_SNS_TOKEN_SWAP_PROPOSAL,
    },
    EnvironmentControlMessage, InterleavingTestEnvironment,
};
use common::{increase_dissolve_delay_raw, set_dissolve_delay_raw};
use fixtures::{principal, NNSBuilder, NeuronBuilder, NNS};
use futures::{channel::mpsc, future::FutureExt, StreamExt};
use ic_nervous_system_common::{ledger::IcpLedger, E8};
use ic_neurons_fund::{PolynomialMatchingFunction, SerializableFunction};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance::{
    governance::{Environment, Governance, ONE_YEAR_SECONDS},
    pb::v1::{
        manage_neuron::Disburse, neurons_fund_snapshot::NeuronsFundNeuronPortion, proposal::Action,
        settle_community_fund_participation, settle_community_fund_participation::Committed,
        settle_neurons_fund_participation_request, CreateServiceNervousSystem,
        IdealMatchedParticipationFunction, NetworkEconomics, NeuronsFundData,
        NeuronsFundParticipation, NeuronsFundSnapshot, OpenSnsTokenSwap, Proposal, ProposalData,
        SettleCommunityFundParticipation, SettleNeuronsFundParticipationRequest,
        SwapParticipationLimits,
    },
};
use ic_sns_swap::pb::v1::{CfNeuron, CfParticipant, Lifecycle};
use ic_sns_wasm::pb::v1::DeployedSns;
use icp_ledger::AccountIdentifier;
use interleaving::{InterleavingTestLedger, LedgerControlMessage};
use std::{
    pin::Pin,
    sync::{atomic, atomic::Ordering as AOrdering},
    thread,
};

mod common;
mod fixtures;
mod interleaving;

// Test for NNS1-829
#[test]
fn test_cant_increase_dissolve_delay_while_disbursing() {
    // We set up a single neuron that we'll disburse, and then try to increase its
    // dissolve delay simultaneously
    let neuron_id_u64 = 1;
    let neuron_id = NeuronId { id: neuron_id_u64 };
    let owner = principal(1);

    // We use channels to control how the disbursing and delay increase are
    // interleaved
    let (tx, mut rx) = mpsc::unbounded::<LedgerControlMessage>();
    // Once we're done with disbursing, we will need to manually close the above
    // channel to terminate the test.
    let finish_tx = tx.clone();

    let nns = NNSBuilder::new()
        .add_neuron(
            NeuronBuilder::new(neuron_id_u64, 10, owner)
                .set_dissolve_state(None)
                .set_kyc_verified(true),
        )
        .add_ledger_transform(Box::new(move |l| {
            Box::new(InterleavingTestLedger::new(l, tx))
        }))
        .set_economics(NetworkEconomics::default())
        .create();

    let now = nns.now();

    // The governance canister relies on a static variable that's reused by multiple
    // canister calls. To avoid using static variables in the test, and yet
    // allow two mutable references to the same value, we'll take both a mutable
    // reference and a raw pointer to it that we'll (unsafely) dereference later.
    // To make sure that the pointer keeps pointing to the same reference, we'll pin
    // the mutable reference.
    let mut boxed = Box::pin(nns.governance);
    let raw_ptr = unsafe {
        let mut_ref = boxed.as_mut();
        Pin::get_unchecked_mut(mut_ref) as *mut Governance
    };

    // Spawn disbursing in a new thread; meanwhile, on the main thread we'll await
    // for the signal that the ledger transfer has been initiated
    let neuron_id_clone = neuron_id;
    thread::spawn(move || {
        let disburse = Disburse {
            amount: None,
            to_account: Some(AccountIdentifier::new(owner, None).into()),
        };
        let disburse_future = boxed.disburse_neuron(&neuron_id_clone, &owner, &disburse);
        let disburse_result = tokio_test::block_on(disburse_future);
        assert!(
            disburse_result.is_ok(),
            "Got an unexpected error while disbursing: {:?}",
            disburse_result
        );
        // As the main thread will try to drain the channel, it's important to close the
        // channel once disbursing is done, otherwise the main thread will hang.
        finish_tx.close_channel();
    });

    // Block the current thread until the ledger transfer is initiated, then try to
    // increase the dissolve delay
    let (_msg, continue_disbursing) = tokio_test::block_on(async { rx.next().await.unwrap() });
    // I'm unsure how the Rust memory model interacts with unsafe code -
    // in particular, whether passing a mutable reference obtained with raw
    // pointers, as in the call to increase_dissolve_delay, puts fences anywhere.
    // To be on the safe side, there are fences in the interleaving ledger and here,
    // which make sure that increase_dissolve_delay_raw sees the changes made by
    // disburse_neuron (in particular, the locks).
    atomic::fence(AOrdering::SeqCst);
    let increase_dissolve_result =
        increase_dissolve_delay_raw(unsafe { &mut *raw_ptr }, &owner, neuron_id, 1)
            .now_or_never()
            .unwrap();

    // This assert used to fail before fixing NNS-829
    assert!(
        increase_dissolve_result.is_err(),
        "Shouldn't be able to increase the dissolve delay of a neuron while it's being disbursed, but got: {:?}",
        increase_dissolve_result
    );

    let set_dissolve_result =
        set_dissolve_delay_raw(unsafe { &mut *raw_ptr }, &owner, neuron_id, now + 86400)
            .now_or_never()
            .unwrap();
    // This assert used to fail before fixing NNS-829
    assert!(
        set_dissolve_result.is_err(),
        "Shouldn't be able to increase the dissolve delay of a neuron while it's being disbursed, but got: {:?}",
        set_dissolve_result
    );

    // Drain the channel to finish the test.
    assert!(
        continue_disbursing.send(Ok(())).is_ok(),
        "Error in trying to continue disbursing",
    );
    tokio_test::block_on(async {
        while let Some((_msg, tx)) = rx.next().await {
            assert!(
                tx.send(Ok(())).is_ok(),
                "Error in trying to continue disbursing",
            );
        }
    });
}

/// Test that interleaving calls to settle_neurons_fund_participation are handled correctly.
/// Interleaved calls should return a successful result without doing any work.
#[test]
fn test_cant_interleave_calls_to_settle_neurons_fund() {
    // Prepare identifiers used throughout the test
    let swap_canister_id = principal(1);
    let sns_governance_canister_id = principal(2);
    let nf_neurons_controller = principal(3);
    let nf_neuron_id_u64 = 42_u64;
    let nf_neuron_maturity = 1_000_000 * E8;
    let proposal_id = ProposalId { id: 1 };
    let sns_governance_treasury_account = AccountIdentifier::new(sns_governance_canister_id, None);
    let total_nf_maturity_equivalent_icp_e8s = 1_000_000 * E8;
    let min_direct_participation_icp_e8s = 50_000 * E8;
    let max_direct_participation_icp_e8s = 200_000 * E8;
    let effective_direct_participation_icp_e8s = 100_000 * E8;
    let effective_nf_participation_icp_e8s = 5_015_003_742_481;
    let max_participant_icp_e8s = 100_000 * E8;
    let matching_function =
        PolynomialMatchingFunction::new(total_nf_maturity_equivalent_icp_e8s).unwrap();

    // We use channels to control how the cals are interleaved
    let (tx, mut rx) = mpsc::unbounded::<LedgerControlMessage>();
    // Once we're done with the successful settle, we will need to manually close the above
    // channel to terminate the test.
    let finish_tx = tx.clone();

    let mut nns = NNSBuilder::new()
        // Add the proposal that will be used in the settle_cf_participant method
        .add_proposal(ProposalData {
            id: Some(proposal_id),
            proposal: Some(Proposal {
                action: Some(Action::CreateServiceNervousSystem(
                    CreateServiceNervousSystem {
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }),
            cf_participants: vec![],
            neurons_fund_data: Some(NeuronsFundData {
                initial_neurons_fund_participation: Some(NeuronsFundParticipation {
                    ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                        serialized_representation: Some(matching_function.serialize()),
                    }),
                    neurons_fund_reserves: Some(NeuronsFundSnapshot {
                        neurons_fund_neuron_portions: vec![NeuronsFundNeuronPortion {
                            nns_neuron_id: Some(NeuronId {
                                id: nf_neuron_id_u64,
                            }),
                            amount_icp_e8s: Some(nf_neuron_maturity),
                            maturity_equivalent_icp_e8s: Some(nf_neuron_maturity),
                            hotkey_principal: Some(nf_neurons_controller),
                            is_capped: Some(false),
                        }],
                    }),
                    swap_participation_limits: Some(SwapParticipationLimits {
                        min_direct_participation_icp_e8s: Some(min_direct_participation_icp_e8s),
                        max_direct_participation_icp_e8s: Some(max_direct_participation_icp_e8s),
                        min_participant_icp_e8s: Some(E8),
                        max_participant_icp_e8s: Some(max_participant_icp_e8s),
                    }),
                    direct_participation_icp_e8s: Some(max_direct_participation_icp_e8s),
                    total_maturity_equivalent_icp_e8s: Some(total_nf_maturity_equivalent_icp_e8s),
                    max_neurons_fund_swap_participation_icp_e8s: Some(
                        max_direct_participation_icp_e8s,
                    ),
                    intended_neurons_fund_participation_icp_e8s: Some(
                        max_direct_participation_icp_e8s,
                    ),
                    allocated_neurons_fund_participation_icp_e8s: Some(nf_neuron_maturity),
                }),
                final_neurons_fund_participation: None,
                neurons_fund_refunds: None,
            }),
            sns_token_swap_lifecycle: Some(Lifecycle::Open as i32),
            ..Default::default()
        })
        .add_neuron(
            NeuronBuilder::new(nf_neuron_id_u64, 100, nf_neurons_controller)
                .set_maturity(nf_neuron_maturity)
                .set_joined_community_fund(100),
        )
        .add_account_for(sns_governance_canister_id, 0) // Setup the treasury account
        .add_ledger_transform(Box::new(move |l| {
            Box::new(InterleavingTestLedger::new(l, tx))
        }))
        .set_economics(NetworkEconomics::default())
        .create();
    let sns_wasm_response = ic_sns_wasm::pb::v1::ListDeployedSnsesResponse {
        instances: vec![DeployedSns {
            swap_canister_id: Some(swap_canister_id),
            ..Default::default()
        }],
    };
    nns.push_mocked_canister_reply(sns_wasm_response.clone());
    nns.push_mocked_canister_reply(sns_wasm_response.clone());
    nns.push_mocked_canister_reply(sns_wasm_response);

    // The governance canister relies on a static variable that's reused by multiple
    // canister calls. To avoid using static variables in the test, and yet
    // allow two mutable references to the same value, we'll take both a mutable
    // reference and a raw pointer to it that we'll (unsafely) dereference later.
    // To make sure that the pointer keeps pointing to the same reference, we'll pin
    // the mutable reference.
    let mut boxed = Box::pin(nns);
    let raw_ptr = unsafe {
        let mut_ref = boxed.as_mut();
        Pin::get_unchecked_mut(mut_ref) as *mut NNS
    };

    // Create the request object used in interleaved calls
    let settle_nf_request = SettleNeuronsFundParticipationRequest {
        nns_proposal_id: Some(proposal_id.id),
        result: Some(
            settle_neurons_fund_participation_request::Result::Committed(
                settle_neurons_fund_participation_request::Committed {
                    sns_governance_canister_id: Some(sns_governance_canister_id),
                    total_direct_participation_icp_e8s: Some(
                        effective_direct_participation_icp_e8s,
                    ),
                    total_neurons_fund_participation_icp_e8s: Some(
                        effective_nf_participation_icp_e8s,
                    ),
                },
            ),
        ),
    };

    // Clone the request so it can be moved into the closure
    let settle_nf_request_clone = settle_nf_request.clone();

    let thread_handle = thread::spawn(move || {
        let settle_nf_future = boxed
            .governance
            .settle_neurons_fund_participation(swap_canister_id, settle_nf_request_clone.clone());
        let settle_nf_result = tokio_test::block_on(settle_nf_future);

        let expected_sns_treasury_balance_icp_e8s: u64 = if let Ok(ref snapshot) = settle_nf_result
        {
            snapshot.total_amount_icp_e8s()
        } else {
            panic!("Expected Ok settle result, got {:?}", settle_nf_result);
        };

        assert!(
            settle_nf_result.is_ok(),
            "Got an unexpected error while settling NF for the first time: {:?}",
            settle_nf_result,
        );

        // Repeat the call; the response should be the same
        let second_settle_nf_future = boxed
            .governance
            .settle_neurons_fund_participation(swap_canister_id, settle_nf_request_clone);
        let second_settle_nf_result = tokio_test::block_on(second_settle_nf_future);

        assert_eq!(settle_nf_result, second_settle_nf_result);

        // As the main thread will try to drain the channel, it's important to close the
        // channel once disbursing is done, otherwise the main thread will hang.
        finish_tx.close_channel();

        // Check the balance of the SNS Governance Treasury account to verify the
        // commitment occurred.
        let balance = boxed
            .account_balance(sns_governance_treasury_account)
            .now_or_never()
            .unwrap()
            .expect("Expected the balance operation not to fail");
        assert_eq!(balance.get_e8s(), expected_sns_treasury_balance_icp_e8s);
    });

    // Block the current thread until the ledger transfer is initiated, then try to
    // settle again.
    let (_msg, ledger_control_message) = tokio_test::block_on(async { rx.next().await.unwrap() });

    // Put atomic fences such that the rust memory model plays nicely with the mutable reference
    // and changes to the state are observed.
    atomic::fence(AOrdering::SeqCst);

    // Get the balance of the SNS Treasury account.
    let balance = unsafe { &mut *raw_ptr }
        .account_balance(sns_governance_treasury_account)
        .now_or_never()
        .unwrap()
        .expect("Expected the balance operation not to fail");
    assert_eq!(balance.get_e8s(), 0);

    // Now that the first request to settle is awaiting a response from the ledger, attempt to
    // call settle_neurons_fund_participation again. This should result in an Err() response as
    // the ultimate NF participants are still being computed by the previous call.
    let settle_nf_result = unsafe { &mut *raw_ptr }
        .governance
        .settle_neurons_fund_participation(swap_canister_id, settle_nf_request.clone())
        .now_or_never()
        .unwrap();
    assert!(
        settle_nf_result.is_err(),
        "Got an unexpected response while settling NF for the second time: {:?}",
        settle_nf_result
    );

    // Get the balance of the SNS Treasury account again. It should still be zero
    // as no work was done.
    let balance = unsafe { &mut *raw_ptr }
        .account_balance(sns_governance_treasury_account)
        .now_or_never()
        .unwrap()
        .expect("Expected balance to exist");
    assert_eq!(balance.get_e8s(), 0);

    ledger_control_message
        .send(Ok(()))
        .expect("Error when continuing blocked settle");

    // Drain the channel.
    tokio_test::block_on(async {
        while let Some((_msg, tx)) = rx.next().await {
            assert!(
                tx.send(Ok(())).is_ok(),
                "Error in trying to continue settling",
            );
        }
    });

    // Join the thread_handle to make sure the thread didn't exit unexpectedly
    thread_handle
        .join()
        .expect("Expected the spawned thread to succeed");
}

/// Test that interleaving calls to settle_community_fund_participation is not possible. Interleaved
/// calls should return a successful result without doing any work.
///
/// TODO[NNS1-2632]: Remove this test once `settle_community_fund_participation` is deprecated.
#[test]
fn test_cant_interleave_calls_to_settle_community_fund() {
    // Prepare identifiers used throughout the test
    let swap_canister_id = principal(1);
    let sns_governance_canister_id = principal(2);
    let proposal_id = ProposalId { id: 1 };
    let sns_governance_treasury_account = AccountIdentifier::new(sns_governance_canister_id, None);

    // We use channels to control how the cals are interleaved
    let (tx, mut rx) = mpsc::unbounded::<LedgerControlMessage>();
    // Once we're done with the successful settle, we will need to manually close the above
    // channel to terminate the test.
    let finish_tx = tx.clone();

    let nns = NNSBuilder::new()
        // Add the proposal that will be used in the settle_cf_participant method
        .add_proposal(ProposalData {
            id: Some(proposal_id),
            proposal: Some(Proposal {
                action: Some(Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
                    target_swap_canister_id: Some(swap_canister_id),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            cf_participants: vec![CfParticipant {
                cf_neurons: vec![CfNeuron {
                    amount_icp_e8s: E8,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            sns_token_swap_lifecycle: Some(Lifecycle::Open as i32),
            ..Default::default()
        })
        .add_account_for(sns_governance_canister_id, 0) // Setup the treasury account
        .add_ledger_transform(Box::new(move |l| {
            Box::new(InterleavingTestLedger::new(l, tx))
        }))
        .set_economics(NetworkEconomics::default())
        .create();

    // The governance canister relies on a static variable that's reused by multiple
    // canister calls. To avoid using static variables in the test, and yet
    // allow two mutable references to the same value, we'll take both a mutable
    // reference and a raw pointer to it that we'll (unsafely) dereference later.
    // To make sure that the pointer keeps pointing to the same reference, we'll pin
    // the mutable reference.
    let mut boxed = Box::pin(nns);
    let raw_ptr = unsafe {
        let mut_ref = boxed.as_mut();
        Pin::get_unchecked_mut(mut_ref) as *mut NNS
    };

    // Create the request object used in interleaved calls
    let settle_cf_request = SettleCommunityFundParticipation {
        open_sns_token_swap_proposal_id: Some(proposal_id.id),
        result: Some(settle_community_fund_participation::Result::Committed(
            Committed {
                sns_governance_canister_id: Some(sns_governance_canister_id),
                total_direct_contribution_icp_e8s: None,
                total_neurons_fund_contribution_icp_e8s: None,
            },
        )),
    };

    // Clone the request so it can be moved into the closure
    let settle_cf_request_clone = settle_cf_request.clone();

    let thread_handle = thread::spawn(move || {
        let settle_cf_future = boxed
            .governance
            .settle_community_fund_participation(swap_canister_id, &settle_cf_request_clone);
        let settle_cf_result = tokio_test::block_on(settle_cf_future);
        assert!(
            settle_cf_result.is_ok(),
            "Got an unexpected error while settling CF: {:?}",
            settle_cf_result
        );
        // As the main thread will try to drain the channel, it's important to close the
        // channel once disbursing is done, otherwise the main thread will hang.
        finish_tx.close_channel();

        // Check the balance of the SNS Governance Treasury account to verify the
        // commitment occurred.
        let balance = boxed
            .account_balance(sns_governance_treasury_account)
            .now_or_never()
            .unwrap()
            .expect("Expected the balance operation not to fail");
        assert_eq!(balance.get_e8s(), E8);
    });

    // Block the current thread until the ledger transfer is initiated, then try to
    // settle again.
    let (_msg, ledger_control_message) = tokio_test::block_on(async { rx.next().await.unwrap() });

    // Put atomic fences such that the rust memory model plays nicely with the mutable reference
    // and changes to the state are observed.
    atomic::fence(AOrdering::SeqCst);

    // Get the balance of the SNS Treasury account.
    let balance = unsafe { &mut *raw_ptr }
        .account_balance(sns_governance_treasury_account)
        .now_or_never()
        .unwrap()
        .expect("Expected the balance operation not to fail");
    assert_eq!(balance.get_e8s(), 0);

    // Now that the first request to settle is awaiting a response from the ledger, attempt to
    // call settle_community_fund_participation again. This should result in an Ok() response as
    // this is seen as an idempotent call.
    let settle_cf_result = unsafe { &mut *raw_ptr }
        .governance
        .settle_community_fund_participation(swap_canister_id, &settle_cf_request)
        .now_or_never()
        .unwrap();
    assert!(settle_cf_result.is_ok());

    // Get the balance of the SNS Treasury account again. It should still be zero
    // as no work was done.
    let balance = unsafe { &mut *raw_ptr }
        .account_balance(sns_governance_treasury_account)
        .now_or_never()
        .unwrap()
        .expect("Expected balance to exist");
    assert_eq!(balance.get_e8s(), 0);

    ledger_control_message
        .send(Ok(()))
        .expect("Error when continuing blocked settle");

    // Drain the channel to finish the test.
    tokio_test::block_on(async {
        while let Some((_msg, tx)) = rx.next().await {
            assert!(
                tx.send(Ok(())).is_ok(),
                "Error in trying to continue settling",
            );
        }
    });

    // Join the thread_handle to make sure the thread didn't exit unexpectedly
    thread_handle
        .join()
        .expect("Expected the spawned thread to succeed");
}

/// Test that interleaving calls to submit OpenSnsTokenSwap or CreateServiceNervousSystem proposals
/// is not possible. Concurrent proposal submissions should be rejected.
#[test]
fn test_open_sns_token_swap_proposals_block_other_sns_proposals() {
    // Step 0: Setup the world

    // We set up a single neuron that will try to make the simultaneous proposals
    let neuron_id_u64 = 1;
    let neuron_id = NeuronId { id: neuron_id_u64 };
    let owner = principal(1);

    // We use channels to control how the cals are interleaved
    let (tx, mut rx) = mpsc::unbounded::<EnvironmentControlMessage>();

    let mut nns = NNSBuilder::new()
        // Add Neuron's who can make the proposals
        .add_neuron(
            NeuronBuilder::new(neuron_id_u64, 10 * E8, owner).set_dissolve_delay(ONE_YEAR_SECONDS),
        )
        // Create a second neuron so the proposal is not immediately executed
        .add_neuron(
            NeuronBuilder::new(2, 100 * E8, principal(2)).set_dissolve_delay(ONE_YEAR_SECONDS),
        )
        .add_environment_transform(Box::new(move |l| {
            Box::new(InterleavingTestEnvironment::new(l, tx))
        }))
        .set_economics(NetworkEconomics::default())
        .create();

    // Add the mocked canister calls that will be made when creating the first proposal
    nns.push_mocked_canister_reply(LIST_DEPLOYED_SNSES_RESPONSE.clone());
    nns.push_mocked_canister_reply(GET_STATE_RESPONSE.clone());
    nns.push_mocked_canister_reply(GET_STATE_RESPONSE.clone());
    nns.push_mocked_canister_reply(GET_SNS_CANISTERS_SUMMARY_RESPONSE.clone());

    // The governance canister relies on a static variable that's reused by multiple
    // canister calls. To avoid using static variables in the test, and yet
    // allow two mutable references to the same value, we'll take both a mutable
    // reference and a raw pointer to it that we'll (unsafely) dereference later.
    // To make sure that the pointer keeps pointing to the same reference, we'll pin
    // the mutable reference.
    let mut boxed = Box::pin(nns);
    let raw_ptr = unsafe {
        let mut_ref = boxed.as_mut();
        Pin::get_unchecked_mut(mut_ref) as *mut NNS
    };

    // Spawn creating a OSTS proposal in a new thread; meanwhile, on the main thread we'll await
    // for the signal that the call to the swap canister has been initiated
    let neuron_id_clone = neuron_id;
    let thread_handle = thread::spawn(move || {
        let proposal = OPEN_SNS_TOKEN_SWAP_PROPOSAL.clone();
        let make_proposal_future =
            boxed
                .governance
                .make_proposal(&neuron_id_clone, &owner, &proposal);
        let make_proposal_result = tokio_test::block_on(make_proposal_future);
        assert!(
            make_proposal_result.is_ok(),
            "Got an unexpected error while submitting a proposal: {:?}",
            make_proposal_result
        );
    });

    // Block until the first proposal submission in the other thread has reached a async call
    let (_msg, continue_proposal_submission) =
        tokio_test::block_on(async { rx.next().await.unwrap() });

    // While the other proposal is awaiting response from another canister, try to submit
    // another OpenSnsTokenSwap proposal.
    atomic::fence(AOrdering::SeqCst);
    let proposal = OPEN_SNS_TOKEN_SWAP_PROPOSAL.clone();
    let make_proposal_result = unsafe { &mut *raw_ptr }
        .governance
        .make_proposal(&neuron_id, &owner, &proposal)
        .now_or_never()
        .unwrap();

    // This used to fail before NNS1-2464
    assert!(
        make_proposal_result.is_err(),
        "Shouldn't be able to submit simultaneous SNS proposals but got {:?}",
        make_proposal_result
    );

    // While the other proposal is awaiting response from another canister, try to submit
    // another CreateServiceNervousSystem proposal.
    atomic::fence(AOrdering::SeqCst);
    let proposal = CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL.clone();
    let make_proposal_result = unsafe { &mut *raw_ptr }
        .governance
        .make_proposal(&neuron_id, &owner, &proposal)
        .now_or_never()
        .unwrap();

    // This used to fail before NNS1-2464
    assert!(
        make_proposal_result.is_err(),
        "Shouldn't be able to submit simultaneous SNS proposals but got {:?}",
        make_proposal_result
    );

    // Drain the channel to finish the test.
    assert!(
        continue_proposal_submission.send(Ok(())).is_ok(),
        "Error in trying to continue to submit the first proposal",
    );

    tokio_test::block_on(drain_receiver_channel(&mut rx));

    // Join the thread_handle to make sure the thread didn't exit unexpectedly
    thread_handle
        .join()
        .expect("Expected the spawned thread to succeed");
}
