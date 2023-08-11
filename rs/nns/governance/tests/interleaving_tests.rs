//! Tests that rely on interleaving two method calls on the governance canister
//! (in particular, when one method is suspended when it calls out to the ledger
//! canister).
use crate::interleaving::{
    drain_receiver_channel,
    test_data::{
        CREATE_SERVICE_NERVOUS_SYSYEM_PROPOSAL, GET_SNS_CANISTERS_SUMMARY_RESPONSE,
        GET_STATE_RESPONSE, LIST_DEPLOYED_SNSES_RESPONSE, OPEN_SNS_TOKEN_SWAP_PROPOSAL,
    },
    EnvironmentControlMessage, InterleavingTestEnvironment,
};
use common::{increase_dissolve_delay_raw, set_dissolve_delay_raw};
use fixtures::{principal, NNSBuilder, NeuronBuilder, NNS};
use futures::{channel::mpsc, future::FutureExt, StreamExt};
use ic_nervous_system_common::{ledger::IcpLedger, E8};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance::{
    governance::{Environment, Governance, ONE_YEAR_SECONDS},
    pb::v1::{
        manage_neuron::Disburse, proposal::Action, settle_community_fund_participation,
        settle_community_fund_participation::Committed, NetworkEconomics, OpenSnsTokenSwap,
        Proposal, ProposalData, SettleCommunityFundParticipation,
    },
};
use ic_sns_swap::pb::v1::{CfNeuron, CfParticipant, Lifecycle};
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

/// Test that interleaving calls to settle_community_fund_participation is not possible. Interleaved
/// calls should return a successful result without doing any work.
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
    let proposal = CREATE_SERVICE_NERVOUS_SYSYEM_PROPOSAL.clone();
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
