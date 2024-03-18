#![allow(unused)]
use crate::{
    governance::ledger_helper::{BurnNeuronFees, NeuronStakeTransfer},
    neuron::types::DissolveStateAndAge,
    neuron_store::NeuronStore,
    pb::v1::{
        manage_neuron::Merge, manage_neuron_response::MergeResponse, GovernanceError, Neuron,
    },
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;

// A validated merge neurons request. The source and target is guaranteed to be different.
#[derive(Clone, Debug)]
pub struct ValidMergeNeuronsRequest {
    source_neuron_id: NeuronId,
    target_neuron_id: NeuronId,
    caller: PrincipalId,
}

impl ValidMergeNeuronsRequest {
    pub fn try_new(
        neuron_id: &NeuronId,
        merge_neuron: &Merge,
        caller: &PrincipalId,
    ) -> Result<Self, MergeNeuronsError> {
        todo!()
    }

    pub fn source_neuron_id(&self) -> NeuronId {
        self.source_neuron_id
    }

    pub fn target_neuron_id(&self) -> NeuronId {
        self.target_neuron_id
    }
}

/// All possible effect of merging 2 neurons.
#[derive(Clone, Debug)]
pub struct MergeNeuronsEffect {
    /// The burning of neuron fees for the source neuron.
    pub source_burn_fees: Option<BurnNeuronFees>,
    /// The stake transfer between the source and target neuron.
    pub stake_transfer: Option<NeuronStakeTransfer>,
    /// The effect of merge neurons on the source neuron (other than the ones involving ledger).
    pub source_effect: MergeNeuronsSourceEffect,
    /// The effect of merge neurons on the target neuron (other than the ones involving ledger).
    pub target_effect: MergeNeuronsTargetEffect,
}

impl MergeNeuronsEffect {
    fn new(maturity_transfer: u64, staked_maturity_transfer: u64) -> Self {
        todo!()
    }
}

/// The effect of merge neurons on the source neuron (other than the ones involving ledger).
#[derive(Clone, Debug)]
pub struct MergeNeuronsSourceEffect {
    source_neuron_dissolve_state_and_age: DissolveStateAndAge,
    maturity_transfer: u64,
    staked_maturity_transfer: u64,
}

impl MergeNeuronsSourceEffect {
    pub fn apply(self, source_neuron: &mut Neuron) {
        todo!()
    }
}

/// The effect of merge neurons on the target neuron (other than the ones involving ledger).
#[derive(Clone, Debug)]
pub struct MergeNeuronsTargetEffect {
    target_neuron_dissolve_state_and_age: DissolveStateAndAge,
    maturity_transfer: u64,
    staked_maturity_transfer: u64,
}

impl MergeNeuronsTargetEffect {
    pub fn apply(self, target_neuron: &mut Neuron) {
        todo!()
    }
}

/// All possible errors that can occur when merging neurons
#[derive(Clone, Copy, Debug)]
pub enum MergeNeuronsError {
    SourceAndTargetSame,
    NoSourceNeuronId,
    SourceNeuronNotFound,
    TargetNeuronNotFound,
    SourceInvalidAccount,
    TargetInvalidAccount,
    SourceNeuronNotHotKeyOrController,
    TargetNeuronNotHotKeyOrController,
    SourceNeuronNotController,
    TargetNeuronNotController,
    SourceNeuronSpawning,
    TargetNeuronSpawning,
    SourceNeuronDissolving,
    TargetNeuronDissolving,
    SourceNeuronInNeuronsFund,
    TargetNeuronInNeuronsFund,
    NeuronManagersNotSame,
    KycVerifiedNotSame,
    NotForProfitNotSame,
    NeuronTypeNotSame,
    SourceOrTargetInvolvedInProposal,
}

impl From<MergeNeuronsError> for GovernanceError {
    fn from(error: MergeNeuronsError) -> Self {
        todo!()
    }
}

/// Calculates the effects of merging two neurons.
pub fn calculate_merge_neurons_effect(
    request: &ValidMergeNeuronsRequest,
    neuron_store: &NeuronStore,
    transaction_fees_e8s: u64,
    now_seconds: u64,
) -> Result<MergeNeuronsEffect, MergeNeuronsError> {
    todo!()
}

/// Builds merge neurons response.
pub fn build_merge_neurons_response(
    source: &Neuron,
    target: &Neuron,
    now_seconds: u64,
) -> MergeResponse {
    todo!()
}
