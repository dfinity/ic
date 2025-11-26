use crate::{
    governance::ledger_helper::{BurnNeuronFeesOperation, NeuronStakeTransferOperation},
    neuron::{DissolveStateAndAge, Neuron, combine_aged_stakes},
    neuron_store::NeuronStore,
    pb::v1::{
        GovernanceError, NeuronState, ProposalData, ProposalStatus, VotingPowerEconomics,
        governance_error::ErrorType,
        manage_neuron::{Merge, NeuronIdOrSubaccount},
    },
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::manage_neuron_response::MergeResponse;
use icp_ledger::Subaccount;
use std::collections::BTreeMap;

/// All possible effect of merging 2 neurons.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MergeNeuronsEffect {
    /// The source neuron id.
    source_neuron_id: NeuronId,
    /// The target neuron id.
    target_neuron_id: NeuronId,
    /// The burning of neuron fees for the source neuron.
    source_burn_fees_e8s: Option<u64>,
    /// The stake transfer between the source and target neuron.
    stake_transfer_to_target_e8s: Option<u64>,
    /// The maturity to transfer from source to target.
    transfer_maturity_e8s: u64,
    /// The staked maturity to transfer from source to target.
    transfer_staked_maturity_e8s: u64,
    /// The new dissolve state and age of the source neuron.
    source_neuron_dissolve_state_and_age: DissolveStateAndAge,
    /// The new dissolve state and age of the target neuron.
    target_neuron_dissolve_state_and_age: DissolveStateAndAge,
    /// The transaction fee as e8s.
    transaction_fees_e8s: u64,
}

impl MergeNeuronsEffect {
    pub fn source_neuron_id(&self) -> NeuronId {
        self.source_neuron_id
    }

    pub fn target_neuron_id(&self) -> NeuronId {
        self.target_neuron_id
    }

    pub fn source_burn_fees(&self) -> Option<BurnNeuronFeesOperation> {
        self.source_burn_fees_e8s
            .map(|amount_e8s| BurnNeuronFeesOperation {
                neuron_id: self.source_neuron_id,
                amount_e8s,
            })
    }

    pub fn stake_transfer(&self) -> Option<NeuronStakeTransferOperation> {
        self.stake_transfer_to_target_e8s
            .map(|amount_to_target_e8s| NeuronStakeTransferOperation {
                source_neuron_id: self.source_neuron_id,
                target_neuron_id: self.target_neuron_id,
                amount_to_target_e8s,
                transaction_fees_e8s: self.transaction_fees_e8s,
            })
    }

    pub fn source_effect(&self) -> MergeNeuronsSourceEffect {
        MergeNeuronsSourceEffect {
            dissolve_state_and_age: self.source_neuron_dissolve_state_and_age,
            subtract_maturity: self.transfer_maturity_e8s,
            subtract_staked_maturity: self.transfer_staked_maturity_e8s,
        }
    }

    pub fn target_effect(&self) -> MergeNeuronsTargetEffect {
        MergeNeuronsTargetEffect {
            dissolve_state_and_age: self.target_neuron_dissolve_state_and_age,
            add_maturity: self.transfer_maturity_e8s,
            add_staked_maturity: self.transfer_staked_maturity_e8s,
        }
    }
}

/// The effect of merge neurons on the source neuron (other than the ones involving ledger).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MergeNeuronsSourceEffect {
    dissolve_state_and_age: DissolveStateAndAge,
    subtract_maturity: u64,
    subtract_staked_maturity: u64,
}

impl MergeNeuronsSourceEffect {
    pub fn apply(self, source_neuron: &mut Neuron) {
        source_neuron.set_dissolve_state_and_age(self.dissolve_state_and_age);
        source_neuron.maturity_e8s_equivalent = source_neuron
            .maturity_e8s_equivalent
            .saturating_sub(self.subtract_maturity);
        source_neuron.subtract_staked_maturity(self.subtract_staked_maturity);
    }
}

/// The effect of merge neurons on the target neuron (other than the ones involving ledger).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MergeNeuronsTargetEffect {
    dissolve_state_and_age: DissolveStateAndAge,
    add_maturity: u64,
    add_staked_maturity: u64,
}

impl MergeNeuronsTargetEffect {
    pub fn apply(self, target_neuron: &mut Neuron) {
        target_neuron.set_dissolve_state_and_age(self.dissolve_state_and_age);
        target_neuron.maturity_e8s_equivalent = target_neuron
            .maturity_e8s_equivalent
            .saturating_add(self.add_maturity);
        target_neuron.add_staked_maturity(self.add_staked_maturity);
    }
}

/// All possible errors that can occur when merging neurons
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MergeNeuronsError {
    SourceAndTargetSame,
    NoSourceNeuronId,
    SourceNeuronNotFound,
    TargetNeuronNotFound,
    SourceNeuronNotHotKeyOrController,
    TargetNeuronNotHotKeyOrController,
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
    SourceNeuronNotController,
    TargetNeuronNotController,
    SourceOrTargetInvolvedInProposal,
}

impl From<MergeNeuronsError> for GovernanceError {
    fn from(error: MergeNeuronsError) -> Self {
        match error {
            MergeNeuronsError::SourceAndTargetSame => GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Source id and target id cannot be the same",
            ),
            MergeNeuronsError::NoSourceNeuronId => GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "There was no source neuron id",
            ),
            MergeNeuronsError::SourceNeuronNotFound => {
                GovernanceError::new_with_message(ErrorType::NotFound, "Source neuron not found")
            }
            MergeNeuronsError::TargetNeuronNotFound => {
                GovernanceError::new_with_message(ErrorType::NotFound, "Target neuron not found")
            }
            MergeNeuronsError::SourceNeuronNotHotKeyOrController => {
                GovernanceError::new_with_message(
                    ErrorType::NotAuthorized,
                    "Caller must be hotkey or controller of the source neuron",
                )
            }
            MergeNeuronsError::TargetNeuronNotHotKeyOrController => {
                GovernanceError::new_with_message(
                    ErrorType::NotAuthorized,
                    "Caller must be hotkey or controller of the target neuron",
                )
            }
            MergeNeuronsError::SourceNeuronSpawning => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Source neuron is spawning.",
            ),
            MergeNeuronsError::TargetNeuronSpawning => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Target neuron is spawning.",
            ),
            MergeNeuronsError::SourceNeuronDissolving => GovernanceError::new_with_message(
                ErrorType::RequiresNotDissolving,
                "Only two non-dissolving neurons with a dissolve delay greater than 0 \
                can be merged.",
            ),
            MergeNeuronsError::TargetNeuronDissolving => GovernanceError::new_with_message(
                ErrorType::RequiresNotDissolving,
                "Only two non-dissolving neurons with a dissolve delay greater than 0 \
                can be merged.",
            ),
            MergeNeuronsError::SourceNeuronInNeuronsFund => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot merge neurons that have been dedicated to the Neurons' Fund",
            ),
            MergeNeuronsError::TargetNeuronInNeuronsFund => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot merge neurons that have been dedicated to the Neurons' Fund",
            ),
            MergeNeuronsError::NeuronManagersNotSame => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "ManageNeuron following of source and target does not match",
            ),
            MergeNeuronsError::KycVerifiedNotSame => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Source neuron's kyc_verified field does not match target",
            ),
            MergeNeuronsError::NotForProfitNotSame => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Source neuron's not_for_profit field does not match target",
            ),
            MergeNeuronsError::NeuronTypeNotSame => GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Source neuron's neuron_type field does not match target",
            ),
            MergeNeuronsError::SourceNeuronNotController => GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Source neuron must be owned by the caller",
            ),
            MergeNeuronsError::TargetNeuronNotController => GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Target neuron must be owned by the caller",
            ),
            MergeNeuronsError::SourceOrTargetInvolvedInProposal => {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    "Cannot merge neurons that are involved in open proposals",
                )
            }
        }
    }
}

/// Calculates the effects of merging two neurons.
pub fn calculate_merge_neurons_effect(
    id: &NeuronId,
    merge: &Merge,
    caller: &PrincipalId,
    neuron_store: &NeuronStore,
    transaction_fees_e8s: u64,
    now_seconds: u64,
) -> Result<MergeNeuronsEffect, MergeNeuronsError> {
    let (source, target) =
        validate_request_and_neurons(id, merge, caller, neuron_store, now_seconds)?;

    let source_burn_fees_e8s = if source.fees_e8s > transaction_fees_e8s {
        Some(source.fees_e8s)
    } else {
        None
    };

    let amount_to_target_e8s = source.minted_stake_e8s.saturating_sub(transaction_fees_e8s);
    let stake_transfer_to_target_e8s = if amount_to_target_e8s > 0 {
        Some(amount_to_target_e8s)
    } else {
        None
    };

    let (_, new_target_age_seconds) = combine_aged_stakes(
        target.cached_stake_e8s,
        target.age_seconds,
        amount_to_target_e8s,
        source.age_seconds,
    );
    // The combined age is a weighted average of the ages of the two neurons, which should be no
    // more than their maximum.
    debug_assert!(new_target_age_seconds <= std::cmp::max(source.age_seconds, target.age_seconds));

    debug_assert!(source.age_seconds <= now_seconds);
    let source_neuron_dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
        dissolve_delay_seconds: source.dissolve_delay_seconds,
        aging_since_timestamp_seconds: if stake_transfer_to_target_e8s.is_some() {
            now_seconds
        } else {
            now_seconds.saturating_sub(source.age_seconds)
        },
    };

    // Because of the invariant above `new_target_age_seconds <= max(source.age_seconds,
    // target.age_seconds`, and both `source.age_seconds` and `target.age_seconds` are no more than
    // now_seconds, `new_target_age_seconds` should be no more than `now_seconds`.
    debug_assert!(new_target_age_seconds <= now_seconds);
    let target_neuron_dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
        dissolve_delay_seconds: std::cmp::max(
            source.dissolve_delay_seconds,
            target.dissolve_delay_seconds,
        ),
        aging_since_timestamp_seconds: now_seconds.saturating_sub(new_target_age_seconds),
    };

    Ok(MergeNeuronsEffect {
        source_neuron_id: source.id,
        target_neuron_id: target.id,
        source_burn_fees_e8s,
        stake_transfer_to_target_e8s,
        source_neuron_dissolve_state_and_age,
        target_neuron_dissolve_state_and_age,
        transfer_maturity_e8s: source.maturity_e8s_equivalent,
        transfer_staked_maturity_e8s: source.staked_maturity_e8s_equivalent,
        transaction_fees_e8s,
    })
}

/// Additional validation for merge neurons before executing the merge.
pub fn validate_merge_neurons_before_commit(
    source_neuron_id: &NeuronId,
    target_neuron_id: &NeuronId,
    caller: &PrincipalId,
    neuron_store: &NeuronStore,
    proposals: &BTreeMap<u64, ProposalData>,
) -> Result<(), MergeNeuronsError> {
    let (source_is_caller_controller, source_subaccount) = neuron_store
        .with_neuron(source_neuron_id, |source_neuron| {
            (
                source_neuron.is_controlled_by(caller),
                source_neuron.subaccount(),
            )
        })
        .map_err(|_| MergeNeuronsError::SourceNeuronNotFound)?;
    if !source_is_caller_controller {
        return Err(MergeNeuronsError::SourceNeuronNotController);
    }

    let (target_is_caller_controller, target_subaccount) = neuron_store
        .with_neuron(target_neuron_id, |target_neuron| {
            (
                target_neuron.is_controlled_by(caller),
                target_neuron.subaccount(),
            )
        })
        .map_err(|_| MergeNeuronsError::TargetNeuronNotFound)?;
    if !target_is_caller_controller {
        return Err(MergeNeuronsError::TargetNeuronNotController);
    }

    if is_neuron_involved_with_open_proposals(source_neuron_id, &source_subaccount, proposals)
        || is_neuron_involved_with_open_proposals(target_neuron_id, &target_subaccount, proposals)
    {
        return Err(MergeNeuronsError::SourceOrTargetInvolvedInProposal);
    }

    Ok(())
}

/// Builds merge neurons response.
pub fn build_merge_neurons_response(
    source: &Neuron,
    target: &Neuron,
    voting_power_economics: &VotingPowerEconomics,
    now_seconds: u64,
    requester: PrincipalId,
) -> MergeResponse {
    let source_neuron = Some(
        source
            .clone()
            .into_api(now_seconds, voting_power_economics, false),
    );
    let target_neuron = Some(
        target
            .clone()
            .into_api(now_seconds, voting_power_economics, false),
    );

    let source_neuron_info =
        Some(source.get_neuron_info(voting_power_economics, now_seconds, requester, false));
    let target_neuron_info =
        Some(target.get_neuron_info(voting_power_economics, now_seconds, requester, false));

    MergeResponse {
        source_neuron,
        target_neuron,
        source_neuron_info,
        target_neuron_info,
    }
}

// Below are helper methods/structs that are private to this module.

/// A set of properties of the source neuron to be used for merging. Instances of this struct
/// should only be created during the calculation of merge and internal to this module.
struct ValidSourceNeuron {
    id: NeuronId,
    /// The dissolve delay of the neuron
    dissolve_delay_seconds: u64,
    /// The age of the source neuron in seconds.
    age_seconds: u64,
    /// The amount of stake that the neuron has
    minted_stake_e8s: u64,
    /// The neuron fees the source neuron has.
    fees_e8s: u64,
    /// The maturity of the neuron
    maturity_e8s_equivalent: u64,
    /// The staked maturity of the neuron
    staked_maturity_e8s_equivalent: u64,
}

impl ValidSourceNeuron {
    fn try_new(neuron: &Neuron, now_seconds: u64) -> Result<Self, MergeNeuronsError> {
        let dissolve_state_and_age = neuron.dissolve_state_and_age();
        let (dissolve_delay_seconds, aging_since_timestamp_seconds) = match dissolve_state_and_age {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } => (dissolve_delay_seconds, aging_since_timestamp_seconds),
            _ => {
                return Err(MergeNeuronsError::SourceNeuronDissolving);
            }
        };

        let fees_e8s = neuron.neuron_fees_e8s;
        let minted_stake_e8s = neuron.minted_stake_e8s();
        let maturity_e8s_equivalent = neuron.maturity_e8s_equivalent;
        let staked_maturity_e8s_equivalent = neuron
            .staked_maturity_e8s_equivalent
            .as_ref()
            .cloned()
            .unwrap_or(0);

        Ok(Self {
            id: neuron.id(),
            dissolve_delay_seconds,
            age_seconds: now_seconds - aging_since_timestamp_seconds,
            minted_stake_e8s,
            fees_e8s,
            maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
        })
    }
}

/// A set of properties of the target neuron to be used for merging. Instances of this struct
/// should only be created during the calculation of merge and internal to this module.
struct ValidTargetNeuron {
    id: NeuronId,
    /// The dissolve delay of the neuron
    dissolve_delay_seconds: u64,
    /// The age of the target neuron in seconds.
    age_seconds: u64,
    /// The amount of stake that the neuron has
    cached_stake_e8s: u64,
}

impl ValidTargetNeuron {
    fn try_new(neuron: &Neuron, now_seconds: u64) -> Result<Self, MergeNeuronsError> {
        let dissolve_state_and_age = neuron.dissolve_state_and_age();
        let (dissolve_delay_seconds, aging_since_timestamp_seconds) = match dissolve_state_and_age {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } => (dissolve_delay_seconds, aging_since_timestamp_seconds),
            _ => {
                return Err(MergeNeuronsError::TargetNeuronDissolving);
            }
        };

        // Note: we are not considering the fees of the target neuron. The impact is small anyway,
        // since it only matters for the age calculation.
        let cached_stake_e8s = neuron.cached_neuron_stake_e8s;

        Ok(Self {
            id: neuron.id(),
            dissolve_delay_seconds,
            age_seconds: now_seconds - aging_since_timestamp_seconds,
            cached_stake_e8s,
        })
    }
}

fn validate_request_and_neurons(
    target_neuron_id: &NeuronId,
    merge_neuron: &Merge,
    caller: &PrincipalId,
    neuron_store: &NeuronStore,
    now_seconds: u64,
) -> Result<(ValidSourceNeuron, ValidTargetNeuron), MergeNeuronsError> {
    let source_neuron_id = merge_neuron
        .source_neuron_id
        .ok_or(MergeNeuronsError::NoSourceNeuronId)?;

    if source_neuron_id == *target_neuron_id {
        return Err(MergeNeuronsError::SourceAndTargetSame);
    }

    let (
        source_neuron_to_merge,
        source_is_caller_authorized,
        source_is_not_spawning,
        source_is_not_in_neurons_fund,
        source_neuron_managers,
        source_kyc_verified,
        source_not_for_profit,
        source_neuron_type,
    ) = neuron_store
        .with_neuron(&source_neuron_id, |source_neuron| {
            let source_neuron_to_merge = ValidSourceNeuron::try_new(source_neuron, now_seconds);
            let source_is_caller_authorized =
                source_neuron.is_authorized_to_simulate_manage_neuron(caller);
            let source_is_not_spawning = source_neuron.state(now_seconds) != NeuronState::Spawning;
            let source_is_not_in_neurons_fund = !source_neuron.is_a_neurons_fund_member();
            let source_neuron_managers = source_neuron.neuron_managers();
            let source_kyc_verified = source_neuron.kyc_verified;
            let source_not_for_profit = source_neuron.not_for_profit;
            let source_neuron_type = source_neuron.neuron_type;

            (
                source_neuron_to_merge,
                source_is_caller_authorized,
                source_is_not_spawning,
                source_is_not_in_neurons_fund,
                source_neuron_managers,
                source_kyc_verified,
                source_not_for_profit,
                source_neuron_type,
            )
        })
        .map_err(|_| MergeNeuronsError::SourceNeuronNotFound)?;
    if !source_is_caller_authorized {
        return Err(MergeNeuronsError::SourceNeuronNotHotKeyOrController);
    }
    if !source_is_not_spawning {
        return Err(MergeNeuronsError::SourceNeuronSpawning);
    }
    if !source_is_not_in_neurons_fund {
        return Err(MergeNeuronsError::SourceNeuronInNeuronsFund);
    }
    let source_neuron_to_merge = source_neuron_to_merge?;

    let (
        target_neuron_to_merge,
        target_is_caller_authorized,
        target_is_not_spawning,
        target_is_not_in_neurons_fund,
        target_neuron_managers,
        target_kyc_verified,
        target_not_for_profit,
        target_neuron_type,
    ) = neuron_store
        .with_neuron(target_neuron_id, |target_neuron| {
            let target_neuron_to_merge = ValidTargetNeuron::try_new(target_neuron, now_seconds);
            let target_is_caller_authorized =
                target_neuron.is_authorized_to_simulate_manage_neuron(caller);
            let target_is_not_spawning = target_neuron.state(now_seconds) != NeuronState::Spawning;
            let target_is_not_in_neurons_fund = !target_neuron.is_a_neurons_fund_member();
            let target_neuron_managers = target_neuron.neuron_managers();
            let target_kyc_verified = target_neuron.kyc_verified;
            let target_not_for_profit = target_neuron.not_for_profit;
            let target_neuron_type = target_neuron.neuron_type;

            (
                target_neuron_to_merge,
                target_is_caller_authorized,
                target_is_not_spawning,
                target_is_not_in_neurons_fund,
                target_neuron_managers,
                target_kyc_verified,
                target_not_for_profit,
                target_neuron_type,
            )
        })
        .map_err(|_| MergeNeuronsError::TargetNeuronNotFound)?;
    if !target_is_caller_authorized {
        return Err(MergeNeuronsError::TargetNeuronNotHotKeyOrController);
    }
    if !target_is_not_spawning {
        return Err(MergeNeuronsError::TargetNeuronSpawning);
    }
    if !target_is_not_in_neurons_fund {
        return Err(MergeNeuronsError::TargetNeuronInNeuronsFund);
    }
    let target_neuron_to_merge = target_neuron_to_merge?;

    if source_neuron_managers != target_neuron_managers {
        return Err(MergeNeuronsError::NeuronManagersNotSame);
    }
    if source_kyc_verified != target_kyc_verified {
        return Err(MergeNeuronsError::KycVerifiedNotSame);
    }
    if source_not_for_profit != target_not_for_profit {
        return Err(MergeNeuronsError::NotForProfitNotSame);
    }
    if source_neuron_type != target_neuron_type {
        return Err(MergeNeuronsError::NeuronTypeNotSame);
    }

    Ok((source_neuron_to_merge, target_neuron_to_merge))
}

fn is_neuron_involved_with_open_proposal(
    neuron_id: &NeuronId,
    subaccount: &Subaccount,
    proposal_data: &ProposalData,
) -> bool {
    // Only consider proposals that have not been decided yet.
    if proposal_data.status() != ProposalStatus::Open {
        return false;
    }

    // For most proposals, the neuron is "involved" exactly when it is the proposer.
    if proposal_data.proposer.as_ref() == Some(neuron_id) {
        return true;
    }

    // The one exception is ManageNeuron proposals. In this case, then a neuron
    // can be involved if the neuron is the one that the proposal operates on.
    if !proposal_data.is_manage_neuron() {
        return false;
    }

    match proposal_data
        .proposal
        .as_ref()
        .and_then(|proposal| proposal.managed_neuron())
    {
        Some(NeuronIdOrSubaccount::NeuronId(managed_neuron_id)) => managed_neuron_id == *neuron_id,
        Some(NeuronIdOrSubaccount::Subaccount(managed_subaccount)) => {
            managed_subaccount == subaccount.to_vec()
        }
        None => false,
    }
}

fn is_neuron_involved_with_open_proposals(
    neuron_id: &NeuronId,
    subaccount: &Subaccount,
    proposals: &BTreeMap<u64, ProposalData>,
) -> bool {
    proposals.values().any(|proposal_data| {
        is_neuron_involved_with_open_proposal(neuron_id, subaccount, proposal_data)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        neuron::{DissolveStateAndAge, NeuronBuilder},
        pb::v1::{Followees, ManageNeuron, NeuronType, Proposal, Topic, proposal::Action},
        storage::reset_stable_memory,
    };
    use assert_matches::assert_matches;
    use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
    use lazy_static::lazy_static;
    use maplit::{btreemap, hashmap};
    use std::collections::BTreeMap;

    static NOW_SECONDS: u64 = 1_234_567_890;
    static TRANSACTION_FEES_E8S: u64 = 10_000;

    lazy_static! {
        static ref PRINCIPAL_ID: PrincipalId = PrincipalId::new_user_test_id(1);
    }

    fn create_model_neuron_builder(id: u64) -> NeuronBuilder {
        let mut account = vec![0; 32];
        for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
            *destination = *data;
        }
        let subaccount = Subaccount::try_from(account.as_slice()).unwrap();
        NeuronBuilder::new(
            NeuronId { id },
            subaccount,
            *PRINCIPAL_ID,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1,
                aging_since_timestamp_seconds: NOW_SECONDS - 1,
            },
            NOW_SECONDS,
        )
    }

    #[test]
    fn test_validate_merge_neurons_request_invalid_no_source() {
        let neuron_store = NeuronStore::new(BTreeMap::new());

        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 1 },
            &Merge {
                source_neuron_id: None,
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::NoSourceNeuronId);
    }

    #[test]
    fn test_validate_merge_neurons_request_invalid_same_source_target() {
        let neuron_store = NeuronStore::new(BTreeMap::new());

        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 1 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::SourceAndTargetSame);
    }

    #[test]
    fn test_calculate_effect_source_or_target_not_found() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        neuron_store
            .add_neuron(create_model_neuron_builder(2).build())
            .unwrap();

        // Source not found.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();
        assert_matches!(error, MergeNeuronsError::SourceNeuronNotFound);

        // Target not found.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 1 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 2 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();
        assert_matches!(error, MergeNeuronsError::TargetNeuronNotFound);
    }

    #[test]
    fn test_calculate_effect_source_or_target_not_authorized() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron_not_authorized = create_model_neuron_builder(1)
            .with_controller(PrincipalId::new_user_test_id(2))
            .build();
        neuron_store.add_neuron(neuron_not_authorized).unwrap();
        neuron_store
            .add_neuron(create_model_neuron_builder(2).build())
            .unwrap();

        // Source not authorized.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();
        assert_matches!(error, MergeNeuronsError::SourceNeuronNotHotKeyOrController);

        // Target not authorized.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 1 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 2 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();
        assert_matches!(error, MergeNeuronsError::TargetNeuronNotHotKeyOrController);
    }

    #[test]
    fn test_calculate_effect_source_or_target_spawning() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron_spawning = create_model_neuron_builder(1)
            .with_spawn_at_timestamp_seconds(NOW_SECONDS - 1)
            .build();
        neuron_store.add_neuron(neuron_spawning).unwrap();
        neuron_store
            .add_neuron(create_model_neuron_builder(2).build())
            .unwrap();

        // Source spawning.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();
        assert_matches!(error, MergeNeuronsError::SourceNeuronSpawning);

        // Target spawning.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 1 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 2 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();
        assert_matches!(error, MergeNeuronsError::TargetNeuronSpawning);
    }

    #[test]
    fn test_calculate_effect_source_or_target_dissolving_or_dissolved() {
        let dissolve_state_and_age_invalid_for_merge_cases = vec![
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW_SECONDS + 1,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW_SECONDS - 1,
            },
        ];

        for dissolve_state_and_age_invalid_for_merge in
            dissolve_state_and_age_invalid_for_merge_cases
        {
            // Reset stable memory for each case so that neuron store is empty.
            reset_stable_memory();
            let mut neuron_store = NeuronStore::new(BTreeMap::new());
            let neuron_invalid = create_model_neuron_builder(1)
                .with_dissolve_state_and_age(dissolve_state_and_age_invalid_for_merge)
                .build();
            neuron_store.add_neuron(neuron_invalid).unwrap();
            neuron_store
                .add_neuron(create_model_neuron_builder(2).build())
                .unwrap();

            // Source neuron dissolving or dissolved.
            let error = calculate_merge_neurons_effect(
                &NeuronId { id: 2 },
                &Merge {
                    source_neuron_id: Some(NeuronId { id: 1 }),
                },
                &PRINCIPAL_ID,
                &neuron_store,
                TRANSACTION_FEES_E8S,
                NOW_SECONDS,
            )
            .unwrap_err();

            assert_matches!(error, MergeNeuronsError::SourceNeuronDissolving);

            // Target neuron dissolving or dissolved.
            let error = calculate_merge_neurons_effect(
                &NeuronId { id: 1 },
                &Merge {
                    source_neuron_id: Some(NeuronId { id: 2 }),
                },
                &PRINCIPAL_ID,
                &neuron_store,
                TRANSACTION_FEES_E8S,
                NOW_SECONDS,
            )
            .unwrap_err();

            assert_matches!(error, MergeNeuronsError::TargetNeuronDissolving);
        }
    }

    #[test]
    fn test_calculate_effect_source_or_target_in_neurons_fund() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron_in_neurons_fund = create_model_neuron_builder(1)
            .with_joined_community_fund_timestamp_seconds(Some(NOW_SECONDS - 1))
            .build();
        neuron_store.add_neuron(neuron_in_neurons_fund).unwrap();
        neuron_store
            .add_neuron(create_model_neuron_builder(2).build())
            .unwrap();

        // Source neuron in neurons fund.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::SourceNeuronInNeuronsFund);

        // Target neuron in neurons fund.
        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 1 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 2 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::TargetNeuronInNeuronsFund);
    }

    #[test]
    fn test_calculate_effect_neuron_managers_not_same() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron1 = create_model_neuron_builder(1)
            .with_followees(hashmap! {
                Topic::NeuronManagement as i32 => Followees {
                    followees: vec![NeuronId { id: 101 }],
                }
            })
            .build();
        neuron_store.add_neuron(neuron1).unwrap();
        let neuron2 = create_model_neuron_builder(2)
            .with_followees(hashmap! {
                Topic::NeuronManagement as i32 => Followees {
                    followees: vec![NeuronId { id: 102 }],
                }
            })
            .build();
        neuron_store.add_neuron(neuron2).unwrap();

        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::NeuronManagersNotSame);
    }

    #[test]
    fn test_calculate_effect_kyc_verified_not_same() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron1 = create_model_neuron_builder(1)
            .with_kyc_verified(true)
            .build();
        neuron_store.add_neuron(neuron1).unwrap();
        let neuron2 = create_model_neuron_builder(2)
            .with_kyc_verified(false)
            .build();
        neuron_store.add_neuron(neuron2).unwrap();

        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::KycVerifiedNotSame);
    }

    #[test]
    fn test_calculate_effect_not_for_profit_not_same() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron_1 = create_model_neuron_builder(1)
            .with_not_for_profit(true)
            .build();
        neuron_store.add_neuron(neuron_1).unwrap();
        let neuron_2 = create_model_neuron_builder(2)
            .with_not_for_profit(false)
            .build();
        neuron_store.add_neuron(neuron_2).unwrap();

        let error = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::NotForProfitNotSame);
    }

    #[test]
    fn test_calculate_effect_neuron_type_not_same() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let neuron_seed = create_model_neuron_builder(1)
            .with_neuron_type(Some(NeuronType::Seed as i32))
            .build();
        neuron_store.add_neuron(neuron_seed.clone()).unwrap();
        let neuron_ect = create_model_neuron_builder(2)
            .with_neuron_type(Some(NeuronType::Ect as i32))
            .build();
        neuron_store.add_neuron(neuron_ect.clone()).unwrap();
        let neuron_none_type = create_model_neuron_builder(3)
            .with_neuron_type(None)
            .build();
        neuron_store.add_neuron(neuron_none_type.clone()).unwrap();

        let assert_neurons_cannot_be_merged = |source_id, target_id| {
            let error = calculate_merge_neurons_effect(
                &target_id,
                &Merge {
                    source_neuron_id: Some(source_id),
                },
                &PRINCIPAL_ID,
                &neuron_store,
                TRANSACTION_FEES_E8S,
                NOW_SECONDS,
            )
            .unwrap_err();

            assert_matches!(error, MergeNeuronsError::NeuronTypeNotSame);
        };

        assert_neurons_cannot_be_merged(neuron_seed.id(), neuron_ect.id());
        assert_neurons_cannot_be_merged(neuron_seed.id(), neuron_none_type.id());
        assert_neurons_cannot_be_merged(neuron_ect.id(), neuron_seed.id());
        assert_neurons_cannot_be_merged(neuron_ect.id(), neuron_none_type.id());
        assert_neurons_cannot_be_merged(neuron_none_type.id(), neuron_seed.id());
        assert_neurons_cannot_be_merged(neuron_none_type.id(), neuron_ect.id());
    }

    #[test]
    fn test_calculate_effect_typical() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());

        let source_neuron = create_model_neuron_builder(1)
            .with_controller(PrincipalId::new_user_test_id(2))
            .with_hot_keys(vec![*PRINCIPAL_ID])
            .with_cached_neuron_stake_e8s(300 * E8 + 10 * E8 + TRANSACTION_FEES_E8S)
            .with_neuron_fees_e8s(10 * E8)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * ONE_DAY_SECONDS,
            })
            .with_maturity_e8s_equivalent(50 * E8)
            .with_staked_maturity_e8s_equivalent(40 * E8)
            .with_followees(hashmap! {
                Topic::NeuronManagement as i32 => Followees {
                    followees: vec![NeuronId { id: 101 }],
                }
            })
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();

        let target_neuron = create_model_neuron_builder(2)
            .with_controller(PrincipalId::new_user_test_id(2))
            .with_hot_keys(vec![*PRINCIPAL_ID])
            .with_cached_neuron_stake_e8s(100 * E8)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * ONE_DAY_SECONDS,
            })
            .with_followees(hashmap! {
                Topic::NeuronManagement as i32 => Followees {
                    followees: vec![NeuronId { id: 101 }],
                }
            })
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let effect = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap();

        assert_eq!(
            effect,
            MergeNeuronsEffect {
                source_neuron_id: NeuronId { id: 1 },
                target_neuron_id: NeuronId { id: 2 },
                source_burn_fees_e8s: Some(10 * E8),
                stake_transfer_to_target_e8s: Some(300 * E8),
                source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS,
                },
                target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS - 150 * ONE_DAY_SECONDS,
                },
                transfer_maturity_e8s: 50 * E8,
                transfer_staked_maturity_e8s: 40 * E8,
                transaction_fees_e8s: TRANSACTION_FEES_E8S,
            }
        );
    }

    #[test]
    fn test_calculate_effect_no_stake_transfer() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());

        let source_neuron = create_model_neuron_builder(1)
            .with_cached_neuron_stake_e8s(10 * E8 + 9_000) // 9_000 is lesss than TRANSACTION_FEES_E8S
            .with_neuron_fees_e8s(10 * E8)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * ONE_DAY_SECONDS,
            })
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();
        let target_neuron = create_model_neuron_builder(2)
            .with_cached_neuron_stake_e8s(100 * E8)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * ONE_DAY_SECONDS,
            })
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let effect = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap();

        assert_eq!(
            effect,
            MergeNeuronsEffect {
                source_neuron_id: NeuronId { id: 1 },
                target_neuron_id: NeuronId { id: 2 },
                source_burn_fees_e8s: Some(10 * E8,),
                stake_transfer_to_target_e8s: None,
                source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS - 100 * ONE_DAY_SECONDS,
                },
                target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS - 300 * ONE_DAY_SECONDS,
                },
                transfer_maturity_e8s: 0,
                transfer_staked_maturity_e8s: 0,
                transaction_fees_e8s: TRANSACTION_FEES_E8S,
            }
        );
    }

    #[test]
    fn test_calculate_effect_no_burn_fees() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());

        let source_neuron = create_model_neuron_builder(1)
            .with_cached_neuron_stake_e8s(300 * E8 + TRANSACTION_FEES_E8S)
            .with_neuron_fees_e8s(0)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * ONE_DAY_SECONDS,
            })
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();
        let target_neuron = create_model_neuron_builder(2)
            .with_cached_neuron_stake_e8s(100 * E8)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * ONE_DAY_SECONDS,
            })
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let effect = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap();

        assert_eq!(
            effect,
            MergeNeuronsEffect {
                source_neuron_id: NeuronId { id: 1 },
                target_neuron_id: NeuronId { id: 2 },
                source_burn_fees_e8s: None,
                stake_transfer_to_target_e8s: Some(300 * E8),
                source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS,
                },
                target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS - 150 * ONE_DAY_SECONDS,
                },
                transfer_maturity_e8s: 0,
                transfer_staked_maturity_e8s: 0,
                transaction_fees_e8s: TRANSACTION_FEES_E8S,
            }
        );
    }

    /// No stake transfer or burn fees because the minted stake (9_000) and the neuron fees (8_000)
    /// are less than the transaction fees. In this case, maturity and staked maturity are still
    /// moved to the target and the dissolve delay of target is still changed to the larger of the
    /// two neurons. However, since no stake is transferred, the aging since timestamps of neither
    /// of the neurons are changed.
    #[test]
    fn test_calculate_effect_no_stake_transfer_or_burn_fees() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let source_neuron = create_model_neuron_builder(1)
            // Neither the minted stake (9_000) nor the neuron fees (8_000) are larger than the
            // transaction fees.
            .with_cached_neuron_stake_e8s(17_000)
            .with_neuron_fees_e8s(8_000)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * ONE_DAY_SECONDS,
            })
            .with_maturity_e8s_equivalent(50 * E8)
            .with_staked_maturity_e8s_equivalent(40 * E8)
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();
        let target_neuron = create_model_neuron_builder(2)
            .with_cached_neuron_stake_e8s(100 * E8)
            .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100 * ONE_DAY_SECONDS,
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * ONE_DAY_SECONDS,
            })
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let effect = calculate_merge_neurons_effect(
            &NeuronId { id: 2 },
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
            &PRINCIPAL_ID,
            &neuron_store,
            TRANSACTION_FEES_E8S,
            NOW_SECONDS,
        )
        .unwrap();

        assert_eq!(
            effect,
            MergeNeuronsEffect {
                source_neuron_id: NeuronId { id: 1 },
                target_neuron_id: NeuronId { id: 2 },
                source_burn_fees_e8s: None,
                stake_transfer_to_target_e8s: None,
                source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS - 100 * ONE_DAY_SECONDS,
                },
                target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 200 * ONE_DAY_SECONDS,
                    aging_since_timestamp_seconds: NOW_SECONDS - 300 * ONE_DAY_SECONDS,
                },
                transfer_maturity_e8s: 50 * E8,
                transfer_staked_maturity_e8s: 40 * E8,
                transaction_fees_e8s: TRANSACTION_FEES_E8S,
            }
        );
    }

    #[test]
    fn test_validate_merge_neurons_before_commit_valid() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());

        let source_neuron = create_model_neuron_builder(1)
            .with_controller(*PRINCIPAL_ID)
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();
        let target_neuron = create_model_neuron_builder(2)
            .with_controller(*PRINCIPAL_ID)
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let proposals = btreemap! {
            1 => ProposalData {
                proposer: Some(NeuronId { id: 3 }),
                ..Default::default()
            },
        };

        assert_eq!(
            validate_merge_neurons_before_commit(
                &NeuronId { id: 1 },
                &NeuronId { id: 2 },
                &PRINCIPAL_ID,
                &neuron_store,
                &proposals
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_merge_neurons_before_commit_source_neuron_not_controller() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());

        let source_neuron = create_model_neuron_builder(1)
            .with_controller(PrincipalId::new_user_test_id(1001))
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();
        let target_neuron = create_model_neuron_builder(2)
            .with_controller(*PRINCIPAL_ID)
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let proposals = btreemap! {
            1 => ProposalData {
                proposer: Some(NeuronId { id: 3 }),
                ..Default::default()
            },
        };

        let error = validate_merge_neurons_before_commit(
            &NeuronId { id: 1 },
            &NeuronId { id: 2 },
            &PRINCIPAL_ID,
            &neuron_store,
            &proposals,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::SourceNeuronNotController);
    }

    #[test]
    fn test_validate_merge_neurons_before_commit_target_neuron_not_controller() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());

        let source_neuron = create_model_neuron_builder(1)
            .with_controller(*PRINCIPAL_ID)
            .build();
        neuron_store.add_neuron(source_neuron).unwrap();
        let target_neuron = create_model_neuron_builder(2)
            .with_controller(PrincipalId::new_user_test_id(1001))
            .build();
        neuron_store.add_neuron(target_neuron).unwrap();

        let proposals = btreemap! {
            1 => ProposalData {
                proposer: Some(NeuronId { id: 3 }),
                ..Default::default()
            },
        };

        let error = validate_merge_neurons_before_commit(
            &NeuronId { id: 1 },
            &NeuronId { id: 2 },
            &PRINCIPAL_ID,
            &neuron_store,
            &proposals,
        )
        .unwrap_err();

        assert_matches!(error, MergeNeuronsError::TargetNeuronNotController);
    }

    #[test]
    fn test_validate_merge_neurons_before_commit_neurons_involved_with_open_proposal() {
        let neuron_not_involved = create_model_neuron_builder(1).build();
        let neuron_involved_with_proposal = create_model_neuron_builder(2).build();
        let neuron_involved_with_managed_neuron_proposal_by_id =
            create_model_neuron_builder(3).build();
        let neuron_involved_with_managed_neuron_proposal_by_subaccount =
            create_model_neuron_builder(4).build();

        let proposal = ProposalData {
            proposer: Some(neuron_involved_with_proposal.id()),
            ..Default::default()
        };
        let managed_neuron_proposal_by_id = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        neuron_involved_with_managed_neuron_proposal_by_id.id(),
                    )),
                    ..Default::default()
                }))),
                ..Default::default()
            }),
            topic: Some(Topic::NeuronManagement as i32),
            ..Default::default()
        };
        let managed_neuron_proposal_by_subaccount = ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                        neuron_involved_with_managed_neuron_proposal_by_subaccount
                            .subaccount()
                            .to_vec(),
                    )),
                    ..Default::default()
                }))),
                ..Default::default()
            }),
            topic: Some(Topic::NeuronManagement as i32),
            ..Default::default()
        };
        // The proposer is a neuron 'not involved', which is OK because the proposal is decided.
        let decided_proposal = ProposalData {
            proposer: Some(neuron_not_involved.id()),
            proposal: Some(Proposal {
                ..Default::default()
            }),
            decided_timestamp_seconds: NOW_SECONDS - 1,
            ..Default::default()
        };

        let neuron_store = NeuronStore::new(btreemap! {
            1 => neuron_not_involved.clone(),
            2 => neuron_involved_with_proposal.clone(),
            3 => neuron_involved_with_managed_neuron_proposal_by_id.clone(),
            4 => neuron_involved_with_managed_neuron_proposal_by_subaccount.clone(),
        });
        let proposals = btreemap! {
            1001 => proposal.clone(),
            1002 => managed_neuron_proposal_by_id.clone(),
            1003 => managed_neuron_proposal_by_subaccount.clone(),
            1004 => decided_proposal.clone(),
        };

        let test_validate_fails_with_involved_in_proposal =
            |source_neuron_id: NeuronId, target_neuron_id: NeuronId| {
                assert_eq!(
                    validate_merge_neurons_before_commit(
                        &source_neuron_id,
                        &target_neuron_id,
                        &PRINCIPAL_ID,
                        &neuron_store,
                        &proposals,
                    ),
                    Err(MergeNeuronsError::SourceOrTargetInvolvedInProposal)
                );
            };

        test_validate_fails_with_involved_in_proposal(
            neuron_involved_with_proposal.id(),
            neuron_not_involved.id(),
        );
        test_validate_fails_with_involved_in_proposal(
            neuron_not_involved.id(),
            neuron_involved_with_proposal.id(),
        );
        test_validate_fails_with_involved_in_proposal(
            neuron_involved_with_managed_neuron_proposal_by_id.id(),
            neuron_not_involved.id(),
        );
        test_validate_fails_with_involved_in_proposal(
            neuron_not_involved.id(),
            neuron_involved_with_managed_neuron_proposal_by_id.id(),
        );
        test_validate_fails_with_involved_in_proposal(
            neuron_involved_with_managed_neuron_proposal_by_subaccount.id(),
            neuron_not_involved.id(),
        );
        test_validate_fails_with_involved_in_proposal(
            neuron_not_involved.id(),
            neuron_involved_with_managed_neuron_proposal_by_subaccount.id(),
        );
    }

    use proptest::{prelude::*, proptest};

    // In cached stake, maturity and staked maturity are all large enough we might get overflows. We
    // choose a large enough value to be comprehensive but not too large to cause overflows.
    static MAX_E8: u64 = 1_000_000_000_000_000_000;

    proptest! {

        // Test a few invariants for the `calculate_merge_neurons_effect` function, mostly that the
        // function does not panic and some numeric constraints (e.g. transferred stake cannot be
        // larger than what the neuron has).
        #[test]
        fn test_calculate_effect_invariants(
            source_cached_stake in 0..MAX_E8,
            source_fees in 0..MAX_E8,
            source_maturity in 0..MAX_E8,
            source_staked_maturity in 0..MAX_E8,
            source_dissolve_delay_seconds in 0..u64::MAX,
            source_aging_since_timestamp_seconds in 0..=NOW_SECONDS,
            target_cached_stake in 0..MAX_E8,
            target_dissolve_delay_seconds in 0..u64::MAX,
            target_aging_since_timestamp_seconds in 0..=NOW_SECONDS,
            transaction_fees_e8s in 0..u64::MAX,
        ) {
            reset_stable_memory();
            let mut neuron_store = NeuronStore::new(BTreeMap::new());

            let source_neuron = create_model_neuron_builder(1)
                .with_cached_neuron_stake_e8s(source_cached_stake)
                .with_neuron_fees_e8s(source_fees)
                .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: source_dissolve_delay_seconds,
                    aging_since_timestamp_seconds: source_aging_since_timestamp_seconds,
                })
                .with_maturity_e8s_equivalent(source_maturity)
                .with_staked_maturity_e8s_equivalent(source_staked_maturity)
                .build();
            neuron_store.add_neuron(source_neuron).unwrap();
            let target_neuron = create_model_neuron_builder(2)
                .with_cached_neuron_stake_e8s(target_cached_stake)
                .with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: target_dissolve_delay_seconds,
                    aging_since_timestamp_seconds: target_aging_since_timestamp_seconds,
                })
                .build();
            neuron_store.add_neuron(target_neuron).unwrap();

            let result = calculate_merge_neurons_effect(
                &NeuronId { id: 2 },
                &Merge {
                    source_neuron_id: Some(NeuronId { id: 1 }),
                },
                &PRINCIPAL_ID,
                &neuron_store,
                transaction_fees_e8s,
                NOW_SECONDS,
            );

            let effect = match result {
                Ok(effect) => effect,
                Err(error) => {
                    prop_assert!(matches!(
                        error,
                        MergeNeuronsError::SourceNeuronDissolving
                            | MergeNeuronsError::TargetNeuronDissolving
                    ));
                    return Ok(());
                }
            };

            if let Some(source_burn_fees_e8s) = effect.source_burn_fees_e8s {
                prop_assert!(source_burn_fees_e8s <= source_fees);
            }
            if let Some(stake_transfer_to_target_e8s) = effect.stake_transfer_to_target_e8s {
                prop_assert!(
                    stake_transfer_to_target_e8s + source_fees + effect.transaction_fees_e8s
                        <= source_cached_stake
                );
            }
            prop_assert_eq!(effect.transfer_maturity_e8s, source_maturity);
            prop_assert_eq!(
                effect.transfer_staked_maturity_e8s,
                source_staked_maturity
            );
            if let DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } = effect.source_neuron_dissolve_state_and_age
            {
                prop_assert!(dissolve_delay_seconds >= source_dissolve_delay_seconds);
                prop_assert!(aging_since_timestamp_seconds >= source_aging_since_timestamp_seconds);
                prop_assert!(aging_since_timestamp_seconds <= NOW_SECONDS);
            } else {
                panic!("Source neuron should not stop dissolving after merging");
            }
            let target_dissolve_state_and_age = effect.target_neuron_dissolve_state_and_age;
            if let DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } = target_dissolve_state_and_age
            {
                prop_assert!(dissolve_delay_seconds >= target_dissolve_delay_seconds);
                // The resulted age should be between the source and target ages.
                prop_assert!(aging_since_timestamp_seconds >=
                    std::cmp::min(source_aging_since_timestamp_seconds, target_aging_since_timestamp_seconds));
                prop_assert!(aging_since_timestamp_seconds <=
                    std::cmp::max(source_aging_since_timestamp_seconds, target_aging_since_timestamp_seconds));
                prop_assert!(aging_since_timestamp_seconds <= NOW_SECONDS);
            } else {
                panic!("Target neuron should not stop dissolving after merging");
            }
        }

    }
}
