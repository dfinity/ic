use crate::{
    governance::{governance_minting_account, neuron_subaccount},
    neuron::Neuron,
    neuron_store::NeuronStore,
    pb::v1::{GovernanceError, governance_error::ErrorType},
};

use ic_nervous_system_canisters::ledger::IcpLedger;
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::AccountIdentifier;

/// An object that represents the burning of neuron fees.
#[derive(Clone, PartialEq, Debug)]
pub struct BurnNeuronFeesOperation {
    pub neuron_id: NeuronId,
    pub amount_e8s: u64,
}

impl BurnNeuronFeesOperation {
    /// Burns the neuron fees by calling ledger and changing the neuron. Recoverable errors are
    /// returned while unrecoverable errors cause a panic. A neuron lock should be held before
    /// calling this.
    pub async fn burn_neuron_fees_with_ledger(
        self,
        ledger: &dyn IcpLedger,
        neuron_store: &mut NeuronStore,
        now_seconds: u64,
    ) -> Result<(), GovernanceError> {
        let subaccount = neuron_store.with_neuron(&self.neuron_id, |neuron| neuron.subaccount())?;

        // If the ledger call fails, it's recoverable since nothing else has been changed.
        ledger
            .transfer_funds(
                self.amount_e8s,
                0, // This is a burn, and there is no transaction fee for burning.
                Some(subaccount),
                governance_minting_account(), // A transfer into the minting account is a burn.
                now_seconds,
            )
            .await
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Failed to burn fees: {err}"),
                )
            })?;

        // After the ledger call, failing to update the neuron will be non-recoverable. Therefore we
        // panic and therefore retaining the neuron lock.
        neuron_store
            .with_neuron_mut(&self.neuron_id, |neuron| {
                self.apply_to_neuron(neuron);
            })
            .expect("Neuron not found after burning fees");
        Ok(())
    }

    /// Burns the neuron fees without calling ledger. This is used for simulating a neuron
    /// operation.
    pub fn burn_neuron_fees_without_ledger(self, neuron: &mut Neuron) {
        self.apply_to_neuron(neuron);
    }

    fn apply_to_neuron(&self, neuron: &mut Neuron) {
        neuron.neuron_fees_e8s = neuron.neuron_fees_e8s.saturating_sub(self.amount_e8s);
        neuron.cached_neuron_stake_e8s = neuron
            .cached_neuron_stake_e8s
            .saturating_sub(self.amount_e8s);
    }
}

/// An object that represents the transfer of stake from one neuron to another.
#[derive(Clone, PartialEq, Debug)]
pub struct NeuronStakeTransferOperation {
    pub source_neuron_id: NeuronId,
    pub target_neuron_id: NeuronId,
    pub amount_to_target_e8s: u64,
    pub transaction_fees_e8s: u64,
}

impl NeuronStakeTransferOperation {
    /// Transfers the stake from one neuron to another by calling ledger and changing the neurons.
    /// Recoverable errors are returned while unrecoverable errors cause a panic.
    pub async fn transfer_neuron_stake_with_ledger(
        self,
        ledger: &dyn IcpLedger,
        neuron_store: &mut NeuronStore,
        now_seconds: u64,
    ) -> Result<(), GovernanceError> {
        // Get the subaccounts of source and target. Any errors are recoverable since no changes have been
        // made to the neurons.
        let source_subaccount =
            neuron_store.with_neuron(&self.source_neuron_id, |neuron| neuron.subaccount())?;
        let target_subaccount =
            neuron_store.with_neuron(&self.target_neuron_id, |neuron| neuron.subaccount())?;

        // This is the first mutation step and therefore recoverable if it fails.
        neuron_store.with_neuron_mut(&self.source_neuron_id, |source_neuron| {
            self.subtract_stake_from_source(source_neuron);
        })?;

        // If the ledger call fails, we try to refund the stake to the source neuron, and it would
        // be recoverable if the refund succeeds.
        ledger
            .transfer_funds(
                self.amount_to_target_e8s,
                self.transaction_fees_e8s,
                Some(source_subaccount),
                neuron_subaccount(target_subaccount),
                now_seconds,
            )
            .await
            .map_err(|err| {
                // Refund the stake to the source neuron.
                neuron_store
                    .with_neuron_mut(&self.source_neuron_id, |source_neuron| {
                        self.add_stake_to_source(source_neuron);
                    })
                    .expect("Source neuron not found after failing to transfer stake");
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Failed to transfer stake: {err}"),
                )
            })?;

        neuron_store
            .with_neuron_mut(&self.target_neuron_id, |target_neuron| {
                self.add_stake_to_target(target_neuron);
            })
            .expect("Target neuron not found after transferring stake");
        Ok(())
    }

    /// Transfers the stake from one neuron to another without calling ledger. This is used for
    /// simulating a neuron operation.
    pub fn transfer_neuron_stake_without_ledger(
        self,
        source_neuron: &mut Neuron,
        target_neuron: &mut Neuron,
    ) {
        self.subtract_stake_from_source(source_neuron);
        self.add_stake_to_target(target_neuron);
    }

    fn subtract_stake_from_source(&self, source: &mut Neuron) {
        source.cached_neuron_stake_e8s = source
            .cached_neuron_stake_e8s
            .saturating_sub(self.amount_from_source_e8s());
    }

    fn add_stake_to_source(&self, source: &mut Neuron) {
        source.cached_neuron_stake_e8s = source
            .cached_neuron_stake_e8s
            .saturating_add(self.amount_from_source_e8s());
    }

    fn add_stake_to_target(&self, target: &mut Neuron) {
        target.cached_neuron_stake_e8s = target
            .cached_neuron_stake_e8s
            .saturating_add(self.amount_to_target_e8s);
    }

    fn amount_from_source_e8s(&self) -> u64 {
        self.amount_to_target_e8s
            .saturating_add(self.transaction_fees_e8s)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct MintIcpOperation {
    account: AccountIdentifier,
    amount_e8s: u64,
}

impl MintIcpOperation {
    pub fn new(account: AccountIdentifier, amount_e8s: u64) -> Self {
        Self {
            amount_e8s,
            account,
        }
    }

    /// Mints ICP by calling ledger.
    pub async fn mint_icp_with_ledger(
        self,
        ledger: &dyn IcpLedger,
        now_seconds: u64,
    ) -> Result<(), GovernanceError> {
        let _ = ledger
            .transfer_funds(self.amount_e8s, 0, None, self.account, now_seconds)
            .await
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Failed to mint ICP: {err}"),
                )
            })?;
        Ok(())
    }
}
