//! Tests that rely on interleaving two method calls on the governance canister
//! (in particular, when one method is suspended when it calls out to the ledger
//! canister).
use futures::channel::mpsc;
use futures::future::FutureExt;
use futures::StreamExt;
use std::pin::Pin;
use std::sync::atomic;
use std::sync::atomic::Ordering as AOrdering;
use std::thread;

use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::governance::{Environment, Governance};
use ic_nns_governance::pb::v1::{manage_neuron::Disburse, NetworkEconomics};
use ledger_canister::AccountIdentifier;

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fixtures;
use fixtures::{principal, NNSBuilder, NeuronBuilder};

mod interleaving;
use interleaving::{InterleavingTestLedger, LedgerControlMessage};

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod common;
use common::{increase_dissolve_delay_raw, set_dissolve_delay_raw};

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
    let neuron_id_clone = neuron_id.clone();
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
        increase_dissolve_delay_raw(unsafe { &mut *raw_ptr }, &owner, neuron_id.clone(), 1)
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
