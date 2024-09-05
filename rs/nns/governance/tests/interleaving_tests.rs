//! Tests that rely on interleaving two method calls on the governance canister
//! (in particular, when one method is suspended when it calls out to the ledger
//! canister).
use assert_matches::assert_matches;
use common::{increase_dissolve_delay_raw, set_dissolve_delay_raw};
use fixtures::{principal, NNSBuilder, NeuronBuilder, NNS};
use futures::{channel::mpsc, future::FutureExt, StreamExt};
use ic_nervous_system_common::{ledger::IcpLedger, E8};
use ic_neurons_fund::{
    NeuronsFundParticipationLimits, PolynomialMatchingFunction, SerializableFunction,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance::{
    governance::{Environment, Governance},
    pb::v1::{
        manage_neuron::Disburse, neuron::DissolveState,
        neurons_fund_snapshot::NeuronsFundNeuronPortion, proposal::Action,
        settle_neurons_fund_participation_request, CreateServiceNervousSystem,
        IdealMatchedParticipationFunction, NetworkEconomics, NeuronsFundData,
        NeuronsFundParticipation, NeuronsFundSnapshot, Proposal, ProposalData,
        SettleNeuronsFundParticipationRequest, SwapParticipationLimits,
    },
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::DeployedSns;
use icp_ledger::AccountIdentifier;
use interleaving::{InterleavingTestLedger, LedgerControlMessage};
use rust_decimal_macros::dec;
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
    #[allow(clippy::disallowed_methods)]
    let (tx, mut rx) = mpsc::unbounded::<LedgerControlMessage>();
    // Once we're done with disbursing, we will need to manually close the above
    // channel to terminate the test.
    let finish_tx = tx.clone();

    let nns = NNSBuilder::new()
        .add_neuron(
            NeuronBuilder::new(neuron_id_u64, 10, owner)
                .set_dissolve_state(Some(DissolveState::WhenDissolvedTimestampSeconds(0)))
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
    let nf_neuron_maturity = 2_000_000 * E8;
    let proposal_id = ProposalId { id: 1 };
    let sns_governance_treasury_account = AccountIdentifier::new(sns_governance_canister_id, None);
    let total_nf_maturity_equivalent_icp_e8s = 2_000_000 * E8;
    let min_direct_participation_icp_e8s = 50_000 * E8;
    let max_direct_participation_icp_e8s = 200_000 * E8;
    let effective_direct_participation_icp_e8s = 100_000 * E8;
    let effective_nf_participation_icp_e8s = 5_015_003_742_481;
    let max_participant_icp_e8s = 100_000 * E8;
    let matching_function = PolynomialMatchingFunction::new(
        total_nf_maturity_equivalent_icp_e8s,
        NeuronsFundParticipationLimits {
            max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
            contribution_threshold_icp: dec!(33_000.0),
            one_third_participation_milestone_icp: dec!(100_000.0),
            full_participation_milestone_icp: dec!(167_000.0),
        },
        false,
    )
    .unwrap();

    // We use channels to control how the cals are interleaved
    #[allow(clippy::disallowed_methods)]
    let (tx, mut rx) = mpsc::unbounded::<LedgerControlMessage>();
    // Once we're done with the successful settle, we will need to manually close the above
    // channel to terminate the test.
    let finish_tx = tx.clone();

    #[allow(deprecated)]
    let initial_neurons_fund_participation = NeuronsFundParticipation {
        ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
            serialized_representation: Some(matching_function.serialize()),
        }),
        neurons_fund_reserves: Some(NeuronsFundSnapshot {
            neurons_fund_neuron_portions: vec![NeuronsFundNeuronPortion {
                nns_neuron_id: Some(NeuronId {
                    id: nf_neuron_id_u64,
                }),
                amount_icp_e8s: Some(max_direct_participation_icp_e8s),
                maturity_equivalent_icp_e8s: Some(nf_neuron_maturity),
                controller: Some(nf_neurons_controller),
                hotkeys: Vec::new(),
                is_capped: Some(false),
                // TODO(NNS1-3198): Remove this field once it's deprecated
                hotkey_principal: Some(nf_neurons_controller),
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
        max_neurons_fund_swap_participation_icp_e8s: Some(max_direct_participation_icp_e8s),
        intended_neurons_fund_participation_icp_e8s: Some(max_direct_participation_icp_e8s),
        allocated_neurons_fund_participation_icp_e8s: Some(max_direct_participation_icp_e8s),
    };

    assert_matches!(initial_neurons_fund_participation.validate(), Ok(_));

    let mut nns = NNSBuilder::new()
        // Add the proposal that will be used in `settle_neurons_fund_participation`.
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
            neurons_fund_data: Some(NeuronsFundData {
                initial_neurons_fund_participation: Some(initial_neurons_fund_participation),
                final_neurons_fund_participation: None,
                neurons_fund_refunds: None,
            }),
            sns_token_swap_lifecycle: Some(Lifecycle::Open as i32),
            ..Default::default()
        })
        .add_neuron(
            NeuronBuilder::new(nf_neuron_id_u64, 100, nf_neurons_controller)
                .set_dissolve_state(Some(DissolveState::WhenDissolvedTimestampSeconds(0)))
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
            snapshot.total_amount_icp_e8s().unwrap()
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
