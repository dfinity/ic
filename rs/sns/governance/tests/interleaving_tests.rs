//! Tests that rely on interleaving two method calls on the governance canister
//! (in particular, when one method is suspended when it calls out to the ledger
//! canister).
use crate::fixtures::{GovernanceCanisterFixtureBuilder, NeuronBuilder, TargetLedger, neuron_id};
use futures::{FutureExt, StreamExt, channel::mpsc};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_utils::{
    InterleavingTestLedger, LedgerControlMessage, drain_receiver_channel,
};
use ic_sns_governance::{
    governance::Governance as GovernanceCanister,
    pb::v1::{
        Account, ManageNeuron, ManageNeuronResponse, NervousSystemParameters, NeuronId,
        NeuronPermission, manage_neuron, manage_neuron::Disburse,
    },
};
use std::{
    pin::Pin,
    sync::{atomic, atomic::Ordering as AOrdering},
    thread,
};

// TODO - remove macro when used in tests - NNS1-1260
#[allow(dead_code)]
mod fixtures;

// Test for NNS1-829
#[test]
fn test_cant_increase_dissolve_delay_while_disbursing() {
    // We set up a single neuron that we'll disburse, and then try to increase its
    // dissolve delay simultaneously
    let user_principal = PrincipalId::new_user_test_id(0);
    let memo = 0;
    let neuron_id = neuron_id(user_principal, memo);
    let canister_fixture_builder = GovernanceCanisterFixtureBuilder::new()
        .add_neuron(
            NeuronBuilder::new(
                neuron_id.clone(),
                E8,
                NeuronPermission::all(&user_principal),
            )
            .set_dissolve_state(None),
        )
        .set_nervous_system_parameters(NervousSystemParameters::with_default_values());

    // We use channels to control how the disbursing and delay increase are
    // interleaved
    #[allow(clippy::disallowed_methods)]
    let (tx, mut rx) = mpsc::unbounded::<LedgerControlMessage>();

    let canister_fixture = canister_fixture_builder
        .add_ledger_transform(
            Box::new(move |l| Box::new(InterleavingTestLedger::new(l, tx))),
            TargetLedger::Sns,
        )
        .create();

    let now = canister_fixture.now();

    // The governance canister relies on a static variable that's reused by multiple
    // canister calls. To avoid using static variables in the test, and yet
    // allow two mutable references to the same value, we'll take both a mutable
    // reference and a raw pointer to it that we'll (unsafely) dereference later.
    // To make sure that the pointer keeps pointing to the same reference, we'll pin
    // the mutable reference.
    let mut boxed = Box::pin(canister_fixture.governance);
    let raw_ptr = unsafe {
        let mut_ref = boxed.as_mut();
        Pin::get_unchecked_mut(mut_ref) as *mut GovernanceCanister
    };

    // Spawn disbursing in a new thread; meanwhile, on the main thread we'll await
    // for the signal that the ledger transfer has been initiated
    let neuron_id_clone = neuron_id.clone();
    let thread_handle = thread::spawn(move || {
        let manage_neuron = ManageNeuron {
            subaccount: neuron_id_clone.id,
            command: Some(manage_neuron::Command::Disburse(Disburse {
                amount: None,
                to_account: Some(Account {
                    owner: Some(user_principal),
                    subaccount: None,
                }),
            })),
        };

        let disburse_future = boxed.manage_neuron(&manage_neuron, &user_principal);
        let disburse_result = tokio_test::block_on(disburse_future);
        assert!(
            disburse_result.is_ok(),
            "Got an unexpected error while disbursing: {disburse_result:?}"
        );
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
    unsafe {
        println!("{:#?}", &mut (*raw_ptr).proto.in_flight_commands);
    }
    let increase_dissolve_result = increase_dissolve_delay(
        unsafe { &mut *raw_ptr },
        &user_principal,
        neuron_id.clone(),
        1,
    )
    .now_or_never()
    .unwrap();

    // This assert used to fail before fixing NNS-829
    assert!(
        increase_dissolve_result.is_err(),
        "Shouldn't be able to increase the dissolve delay of a neuron while it's being disbursed, but got: {increase_dissolve_result:?}"
    );

    let set_dissolve_result = set_dissolve_delay(
        unsafe { &mut *raw_ptr },
        &user_principal,
        neuron_id,
        now + 86400,
    )
    .now_or_never()
    .unwrap();
    // This assert used to fail before fixing NNS-829
    assert!(
        set_dissolve_result.is_err(),
        "Shouldn't be able to increase the dissolve delay of a neuron while it's being disbursed, but got: {set_dissolve_result:?}"
    );

    // Drain the channel to finish the test.
    assert!(
        continue_disbursing.send(Ok(())).is_ok(),
        "Error in trying to continue disbursing",
    );
    tokio_test::block_on(drain_receiver_channel(&mut rx));

    thread_handle
        .join()
        .expect("Expected the spawned thread to succeed");
}

pub async fn increase_dissolve_delay(
    gov: &mut GovernanceCanister,
    principal_id: &PrincipalId,
    neuron_id: NeuronId,
    delay_increase: u32,
) -> ManageNeuronResponse {
    gov.manage_neuron(
        &ManageNeuron {
            subaccount: neuron_id.id,
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::IncreaseDissolveDelay(
                        manage_neuron::IncreaseDissolveDelay {
                            additional_dissolve_delay_seconds: delay_increase,
                        },
                    )),
                },
            )),
        },
        principal_id,
    )
    .await
}

pub async fn set_dissolve_delay(
    gov: &mut GovernanceCanister,
    principal_id: &PrincipalId,
    neuron_id: NeuronId,
    timestamp_seconds: u64,
) -> ManageNeuronResponse {
    gov.manage_neuron(
        &ManageNeuron {
            subaccount: neuron_id.id,
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::SetDissolveTimestamp(
                        manage_neuron::SetDissolveTimestamp {
                            dissolve_timestamp_seconds: timestamp_seconds,
                        },
                    )),
                },
            )),
        },
        principal_id,
    )
    .await
}
