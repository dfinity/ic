use super::*;

use crate::{
    pb::v1::{governance::neuron_in_flight_command::SyncCommand, manage_neuron::Split},
    test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger},
};

use std::sync::Arc;

thread_local! {
    static TEST_GOVERNANCE: RefCell<Governance> = RefCell::new(new_governance_for_test());
}

fn new_governance_for_test() -> Governance {
    Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(Default::default(), 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    )
}

/// The unsafe accessor similar to the one in the production code, but on `TEST_GOVERNANCE`.
pub fn test_governance_mut() -> &'static mut Governance {
    unsafe { &mut *TEST_GOVERNANCE.with(|g| g.as_ptr()) }
}

#[test]
fn test_neuron_async_lock_different_neurons_both_locked() {
    let command = Command::Split(Split {
        amount_e8s: 1,
        memo: None,
    });
    let _neuron_lock_1 = Governance::acquire_neuron_async_lock(
        &TEST_GOVERNANCE,
        NeuronId { id: 1 },
        1,
        command.clone(),
    )
    .unwrap();

    Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, NeuronId { id: 2 }, 1, command)
        .unwrap();
}

#[test]
fn test_neuron_async_lock_same_neuron_cannot_lock_twice() {
    let neuron_id = NeuronId { id: 1 };
    let command = Command::Split(Split {
        amount_e8s: 1,
        memo: None,
    });

    let _neuron_lock =
        Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command.clone())
            .unwrap();

    assert!(
        Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command).is_err()
    );
}

#[test]
fn test_neuron_async_lock_same_neuron_can_lock_after_unlock() {
    let neuron_id = NeuronId { id: 1 };
    let command = Command::Split(Split {
        amount_e8s: 1,
        memo: None,
    });

    {
        let _neuron_lock_1 =
            Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command.clone())
                .unwrap();
    }

    Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command).unwrap();
}

#[test]
fn test_neuron_async_lock_same_neuron_cannot_lock_after_retained() {
    let neuron_id = NeuronId { id: 1 };
    let command = Command::Split(Split {
        amount_e8s: 1,
        memo: None,
    });

    {
        let mut neuron_lock =
            Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command.clone())
                .unwrap();
        neuron_lock.retain();
    }

    assert!(
        Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command).is_err()
    );
}

#[test]
#[should_panic(expected = "SyncCommand is not supported")]
fn test_neuron_async_lock_does_not_work_with_sync_command() {
    Governance::acquire_neuron_async_lock(
        &TEST_GOVERNANCE,
        NeuronId { id: 1 },
        1,
        Command::SyncCommand(SyncCommand {}),
    )
    .unwrap();
}

#[test]
fn test_ledger_update_lock_different_neurons_both_locked() {
    let inflight_command = NeuronInFlightCommand {
        command: Some(Command::Split(Split {
            amount_e8s: 1,
            memo: None,
        })),
        timestamp: 1,
    };
    let _neuron_lock = test_governance_mut()
        .lock_neuron_for_command(1, inflight_command.clone())
        .unwrap();
    test_governance_mut()
        .lock_neuron_for_command(2, inflight_command)
        .unwrap();
}

#[test]
fn test_ledger_update_lock_same_neuron_cannot_lock_twice() {
    let neuron_id = NeuronId { id: 1 };
    let inflight_command = NeuronInFlightCommand {
        command: Some(Command::Split(Split {
            amount_e8s: 1,
            memo: None,
        })),
        timestamp: 1,
    };

    let _neuron_lock = test_governance_mut()
        .lock_neuron_for_command(neuron_id.id, inflight_command.clone())
        .unwrap();

    assert!(
        test_governance_mut()
            .lock_neuron_for_command(neuron_id.id, inflight_command)
            .is_err()
    );
}

#[test]
fn test_ledger_update_lock_same_neuron_can_lock_after_unlock() {
    let neuron_id = NeuronId { id: 1 };
    let inflight_command = NeuronInFlightCommand {
        command: Some(Command::Split(Split {
            amount_e8s: 1,
            memo: None,
        })),
        timestamp: 1,
    };

    {
        let _neuron_lock = test_governance_mut()
            .lock_neuron_for_command(neuron_id.id, inflight_command.clone())
            .unwrap();
    }

    test_governance_mut()
        .lock_neuron_for_command(neuron_id.id, inflight_command)
        .unwrap();
}

#[test]
fn test_ledger_update_lock_same_neuron_cannot_lock_after_retained() {
    let neuron_id = NeuronId { id: 1 };
    let inflight_command = NeuronInFlightCommand {
        command: Some(Command::Split(Split {
            amount_e8s: 1,
            memo: None,
        })),
        timestamp: 1,
    };

    {
        let mut neuron_lock = test_governance_mut()
            .lock_neuron_for_command(neuron_id.id, inflight_command.clone())
            .unwrap();
        neuron_lock.retain();
    }

    assert!(
        test_governance_mut()
            .lock_neuron_for_command(neuron_id.id, inflight_command)
            .is_err()
    );
}

#[test]
fn test_ledger_update_lock_compatible_with_neuron_async_lock() {
    // In this test we make sure that a neuron locked with `lock_neuron_for_command` cannot
    // `acquire_neuron_async_lock`, and vice versa.
    let neuron_id = NeuronId { id: 1 };
    let command = Command::Split(Split {
        amount_e8s: 1,
        memo: None,
    });
    let inflight_command = NeuronInFlightCommand {
        command: Some(command.clone()),
        timestamp: 1,
    };

    {
        let _neuron_lock = test_governance_mut()
            .lock_neuron_for_command(neuron_id.id, inflight_command.clone())
            .unwrap();
        assert!(
            Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command.clone())
                .is_err()
        );
    }

    {
        let _neuron_lock =
            Governance::acquire_neuron_async_lock(&TEST_GOVERNANCE, neuron_id, 1, command.clone())
                .unwrap();
        assert!(
            test_governance_mut()
                .lock_neuron_for_command(neuron_id.id, inflight_command)
                .is_err()
        );
    }
}
