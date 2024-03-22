#![allow(unused)]
use crate::{
    neuron_store::NeuronStore,
    pb::v1::{GovernanceError, Neuron},
};

use ic_nervous_system_common::ledger::IcpLedger;

/// An object that represents the burning of neuron fees.
#[derive(Clone, Debug, PartialEq)]
pub struct BurnNeuronFees {
    pub amount_e8s: u64,
}

impl BurnNeuronFees {
    /// Burns the neuron fees by calling ledger and changing the neuron. Recoverable errors are returned
    /// while unrecoverable errors cause a panic.
    pub async fn burn_neuron_fees_with_ledger(
        self,
        ledger: &dyn IcpLedger,
        neuron_store: &mut NeuronStore,
        now_seconds: u64,
    ) -> Result<(), GovernanceError> {
        Ok(())
    }

    /// Burns the neuron fees without calling ledger.
    pub fn burn_neuron_fees_without_ledger(self, neuron: &mut Neuron) {}
}

#[derive(Clone, Debug, PartialEq)]
pub struct NeuronStakeTransfer {
    pub amount_to_target_e8s: u64,
    pub transaction_fee_e8s: u64,
}

impl NeuronStakeTransfer {
    /// Transfers the stake from one neuron to another by calling ledger and changing the neurons.
    /// Recoverable errors are returned while unrecoverable errors cause a panic.
    pub async fn transfer_neuron_stake_with_ledger(
        self,
        ledger: &dyn IcpLedger,
        neuron_store: &mut NeuronStore,
        now_seconds: u64,
    ) -> Result<(), GovernanceError> {
        Ok(())
    }

    /// Transfers the stake from one neuron to another without calling ledger.
    pub fn transfer_neuron_stake_without_ledger(
        self,
        source_neuron: &mut Neuron,
        target_neuron: &mut Neuron,
    ) {
    }
}
