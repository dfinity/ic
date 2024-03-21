#![allow(unused)]
use crate::{
    governance::{
        combine_aged_stakes,
        ledger_helper::{BurnNeuronFees, NeuronStakeTransfer},
    },
    neuron::types::DissolveStateAndAge,
    neuron_store::NeuronStore,
    pb::v1::{
        manage_neuron::Merge, manage_neuron_response::MergeResponse, GovernanceError, Neuron,
        NeuronState,
    },
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use std::collections::BTreeMap;

/// All possible effect of merging 2 neurons.
#[derive(Clone, Debug, PartialEq)]
pub struct MergeNeuronsEffect {
    /// The source neuron id.
    pub source_neuron_id: NeuronId,
    /// The target neuron id.
    pub target_neuron_id: NeuronId,
    /// The burning of neuron fees for the source neuron.
    pub source_burn_fees: Option<BurnNeuronFees>,
    /// The stake transfer between the source and target neuron.
    pub stake_transfer: Option<NeuronStakeTransfer>,
    /// The effect of merge neurons on the source neuron (other than the ones involving ledger).
    pub source_effect: MergeNeuronsSourceEffect,
    /// The effect of merge neurons on the target neuron (other than the ones involving ledger).
    pub target_effect: MergeNeuronsTargetEffect,
}

/// The effect of merge neurons on the source neuron (other than the ones involving ledger).
#[derive(Clone, Debug, PartialEq)]
pub struct MergeNeuronsSourceEffect {
    source_neuron_dissolve_state_and_age: DissolveStateAndAge,
    subtract_maturity: u64,
    subtract_staked_maturity: u64,
}

impl MergeNeuronsSourceEffect {
    pub fn apply(self, source_neuron: &mut Neuron) {
        todo!()
    }
}

/// The effect of merge neurons on the target neuron (other than the ones involving ledger).
#[derive(Clone, Debug, PartialEq)]
pub struct MergeNeuronsTargetEffect {
    target_neuron_dissolve_state_and_age: DissolveStateAndAge,
    add_maturity: u64,
    add_staked_maturity: u64,
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
        todo!()
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

    let source_burn_fees = if source.fees_e8s > transaction_fees_e8s {
        Some(BurnNeuronFees {
            amount_e8s: source.fees_e8s,
        })
    } else {
        None
    };

    let amount_to_target_e8s = source.minted_stake_e8s.saturating_sub(transaction_fees_e8s);
    let stake_transfer = if amount_to_target_e8s > 0 {
        Some(NeuronStakeTransfer {
            amount_to_target_e8s,
            transaction_fee_e8s: transaction_fees_e8s,
        })
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
    let source_neuron_state = DissolveStateAndAge::NotDissolving {
        dissolve_delay_seconds: source.dissolve_delay_seconds,
        aging_since_timestamp_seconds: if stake_transfer.is_some() {
            now_seconds
        } else {
            now_seconds.saturating_sub(source.age_seconds)
        },
    };

    // Because of the invariant above `new_target_age_seconds <= max(source.age_seconds,
    // target.age_seconds`, and both `source.age_seconds` and `target.age_seconds` are no more than
    // now_seconds, `new_target_age_seconds` should be no more than `now_seconds`.
    debug_assert!(new_target_age_seconds <= now_seconds);
    let target_neuron_state = DissolveStateAndAge::NotDissolving {
        dissolve_delay_seconds: std::cmp::max(
            source.dissolve_delay_seconds,
            target.dissolve_delay_seconds,
        ),
        aging_since_timestamp_seconds: now_seconds.saturating_sub(new_target_age_seconds),
    };

    Ok(MergeNeuronsEffect {
        source_neuron_id: source.id,
        target_neuron_id: target.id,
        source_burn_fees,
        stake_transfer,
        source_effect: MergeNeuronsSourceEffect {
            source_neuron_dissolve_state_and_age: source_neuron_state,
            subtract_maturity: source.maturity_e8s_equivalent,
            subtract_staked_maturity: source.staked_maturity_e8s_equivalent,
        },
        target_effect: MergeNeuronsTargetEffect {
            target_neuron_dissolve_state_and_age: target_neuron_state,
            add_maturity: source.maturity_e8s_equivalent,
            add_staked_maturity: source.staked_maturity_e8s_equivalent,
        },
    })
}

/// Builds merge neurons response.
pub fn build_merge_neurons_response(
    source: &Neuron,
    target: &Neuron,
    now_seconds: u64,
) -> MergeResponse {
    todo!()
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
            id: neuron.id.expect("Neuron must have an id"),
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
            id: neuron.id.expect("Neuron must have an id"),
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
        source_account_valid,
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
            let source_account_valid = source_neuron.subaccount().is_ok();
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
                source_account_valid,
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
    check_condition(
        source_account_valid,
        MergeNeuronsError::SourceInvalidAccount,
    )?;
    check_condition(
        source_is_caller_authorized,
        MergeNeuronsError::SourceNeuronNotHotKeyOrController,
    )?;
    check_condition(
        source_is_not_spawning,
        MergeNeuronsError::SourceNeuronSpawning,
    )?;
    check_condition(
        source_is_not_in_neurons_fund,
        MergeNeuronsError::SourceNeuronInNeuronsFund,
    )?;
    let source_neuron_to_merge = source_neuron_to_merge?;

    let (
        target_neuron_to_merge,
        target_account_valid,
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
            let target_account_valid = target_neuron.subaccount().is_ok();
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
                target_account_valid,
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
    check_condition(
        target_account_valid,
        MergeNeuronsError::TargetInvalidAccount,
    )?;
    check_condition(
        target_is_caller_authorized,
        MergeNeuronsError::TargetNeuronNotHotKeyOrController,
    )?;
    check_condition(
        target_is_not_spawning,
        MergeNeuronsError::TargetNeuronSpawning,
    )?;
    check_condition(
        target_is_not_in_neurons_fund,
        MergeNeuronsError::TargetNeuronInNeuronsFund,
    )?;
    let target_neuron_to_merge = target_neuron_to_merge?;

    check_equal(
        source_neuron_managers,
        target_neuron_managers,
        MergeNeuronsError::NeuronManagersNotSame,
    )?;
    check_equal(
        source_kyc_verified,
        target_kyc_verified,
        MergeNeuronsError::KycVerifiedNotSame,
    )?;
    check_equal(
        source_not_for_profit,
        target_not_for_profit,
        MergeNeuronsError::NotForProfitNotSame,
    )?;
    check_equal(
        source_neuron_type,
        target_neuron_type,
        MergeNeuronsError::NeuronTypeNotSame,
    )?;

    Ok((source_neuron_to_merge, target_neuron_to_merge))
}

fn check_condition(condition: bool, error: MergeNeuronsError) -> Result<(), MergeNeuronsError> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}

fn check_equal<T: Eq>(
    neuron_field: T,
    other_neuron_field: T,
    error: MergeNeuronsError,
) -> Result<(), MergeNeuronsError> {
    check_condition(neuron_field == other_neuron_field, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::{
        neuron::{DissolveState, Followees},
        Topic,
    };
    use assert_matches::assert_matches;
    use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
    use lazy_static::lazy_static;
    use maplit::{btreemap, hashmap};

    static NOW_SECONDS: u64 = 1_234_567_890;
    static TRANSACTION_FEES_E8S: u64 = 10_000;

    lazy_static! {
        static ref PRINCIPAL_ID: PrincipalId = PrincipalId::new_user_test_id(1);
    }

    fn model_neuron(id: u64) -> Neuron {
        let mut account = vec![0; 32];
        for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
            *destination = *data;
        }
        Neuron {
            id: Some(NeuronId { id }),
            account,
            controller: Some(*PRINCIPAL_ID),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(1)),
            aging_since_timestamp_seconds: NOW_SECONDS - 1,
            ..Default::default()
        }
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
    fn test_calculate_effect_source_neuron_not_found() {
        let neuron_store = NeuronStore::new(btreemap! {
            2 => model_neuron(2),
        });

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
    }

    #[test]
    fn test_calculate_effect_target_neuron_not_found() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => model_neuron(1),
        });

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

        assert_matches!(error, MergeNeuronsError::TargetNeuronNotFound);
    }

    #[test]
    fn test_calculate_effect_source_invalid_account() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                account: vec![],
                ..model_neuron(1)
            },
            2 => model_neuron(2),
        });

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

        assert_matches!(error, MergeNeuronsError::SourceInvalidAccount);
    }

    #[test]
    fn test_calculate_effect_target_invalid_account() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => model_neuron(1),
            2 => Neuron {
                account: vec![],
                ..model_neuron(2)
            },
        });

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

        assert_matches!(error, MergeNeuronsError::TargetInvalidAccount);
    }

    #[test]
    fn test_calculate_effect_source_not_authorized() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                controller: Some(PrincipalId::new_user_test_id(2)),
                ..model_neuron(1)
            },
            2 => model_neuron(2),
        });

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
    }

    #[test]
    fn test_calculate_effect_target_not_authorized() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => model_neuron(1),
            2 => Neuron {
                controller: Some(PrincipalId::new_user_test_id(2)),
                ..model_neuron(2)
            },
        });

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

        assert_matches!(error, MergeNeuronsError::TargetNeuronNotHotKeyOrController);
    }

    #[test]
    fn test_calculate_effect_source_spawning() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                spawn_at_timestamp_seconds: Some(NOW_SECONDS - 1),
                ..model_neuron(1)
            },
            2 => model_neuron(2),
        });

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
    }

    #[test]
    fn test_calculate_effect_target_spawning() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => model_neuron(1),
            2 => Neuron {
                spawn_at_timestamp_seconds: Some(NOW_SECONDS - 1),
                ..model_neuron(2)
            },
        });

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

        assert_matches!(error, MergeNeuronsError::TargetNeuronSpawning);
    }

    #[test]
    fn test_calculate_effect_source_dissolving() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(NOW_SECONDS + 1)),
                aging_since_timestamp_seconds: u64::MAX,
                ..model_neuron(1)
            },
            2 => model_neuron(2),
        });

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
    }

    #[test]
    fn test_calculate_effect_target_dissolving() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => model_neuron(1),
            2 => Neuron {
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(NOW_SECONDS + 1)),
                aging_since_timestamp_seconds: u64::MAX,
                ..model_neuron(2)
            },
        });

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

        assert_matches!(error, MergeNeuronsError::TargetNeuronDissolving);
    }

    #[test]
    fn test_calculate_effect_source_in_neurons_fund() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                joined_community_fund_timestamp_seconds: Some(NOW_SECONDS - 1),
                ..model_neuron(1)
            },
            2 => model_neuron(2),
        });

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
    }

    #[test]
    fn test_calculate_effect_target_in_neurons_fund() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => model_neuron(1),
            2 => Neuron {
                joined_community_fund_timestamp_seconds: Some(NOW_SECONDS - 1),
                ..model_neuron(2)
            },
        });

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

        assert_matches!(error, MergeNeuronsError::TargetNeuronInNeuronsFund);
    }

    #[test]
    fn test_calculate_effect_neuron_managers_not_same() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                followees: hashmap! {
                    Topic::NeuronManagement as i32 =>
                    Followees {
                        followees: vec![
                            NeuronId { id: 101 },
                        ],
                    },
                },
                ..model_neuron(1)
            },
            2 => Neuron {
                followees: hashmap! {
                    Topic::NeuronManagement as i32 =>
                    Followees {
                        followees: vec![
                            NeuronId { id: 102 },
                        ],
                    },
                },
                ..model_neuron(2)
            },
        });

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
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                kyc_verified: true,
                ..model_neuron(1)
            },
            2 => Neuron {
                kyc_verified: false,
                ..model_neuron(2)
            },
        });

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
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                not_for_profit: true,
                ..model_neuron(1)
            },
            2 => Neuron {
                not_for_profit: false,
                ..model_neuron(2)
            },
        });

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
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                neuron_type: Some(1),
                ..model_neuron(1)
            },
            2 => Neuron {
                neuron_type: None,
                ..model_neuron(2)
            },
        });

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

        assert_matches!(error, MergeNeuronsError::NeuronTypeNotSame);
    }

    #[test]
    fn test_calculate_effect_typical() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                cached_neuron_stake_e8s: 300 * E8 + 10 * E8 + TRANSACTION_FEES_E8S,
                neuron_fees_e8s: 10 * E8,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(200 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * SECONDS_PER_DAY,
                maturity_e8s_equivalent: 50 * E8,
                staked_maturity_e8s_equivalent: Some(40 * E8),
                ..model_neuron(1)
            },
            2 => Neuron {
                cached_neuron_stake_e8s: 100 * E8,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(100 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * SECONDS_PER_DAY,
                ..model_neuron(2)
            },
        });

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
                source_burn_fees: Some(BurnNeuronFees {
                    amount_e8s: 10 * E8,
                }),
                stake_transfer: Some(NeuronStakeTransfer {
                    amount_to_target_e8s: 300 * E8,
                    transaction_fee_e8s: TRANSACTION_FEES_E8S,
                }),
                source_effect: MergeNeuronsSourceEffect {
                    source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS,
                    },
                    subtract_maturity: 50 * E8,
                    subtract_staked_maturity: 40 * E8,
                },
                target_effect: MergeNeuronsTargetEffect {
                    target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS - 150 * SECONDS_PER_DAY,
                    },
                    add_maturity: 50 * E8,
                    add_staked_maturity: 40 * E8,
                },
            }
        );
    }

    #[test]
    fn test_calculate_effect_no_stake_transfer() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                cached_neuron_stake_e8s: 10 * E8 + 9_000, // 9_000 is less than TRANSACTION_FEES_E8S
                neuron_fees_e8s: 10 * E8,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(200 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * SECONDS_PER_DAY,
                ..model_neuron(1)
            },
            2 => Neuron {
                cached_neuron_stake_e8s: 100 * E8,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(100 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * SECONDS_PER_DAY,
                ..model_neuron(2)
            },
        });

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
                source_burn_fees: Some(BurnNeuronFees {
                    amount_e8s: 10 * E8,
                }),
                stake_transfer: None,
                source_effect: MergeNeuronsSourceEffect {
                    source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS - 100 * SECONDS_PER_DAY,
                    },
                    subtract_maturity: 0,
                    subtract_staked_maturity: 0,
                },
                target_effect: MergeNeuronsTargetEffect {
                    target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS - 300 * SECONDS_PER_DAY,
                    },
                    add_maturity: 0,
                    add_staked_maturity: 0,
                },
            }
        );
    }

    #[test]
    fn test_calculate_effect_no_burn_fees() {
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                cached_neuron_stake_e8s: 300 * E8 + TRANSACTION_FEES_E8S,
                neuron_fees_e8s: 0,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(200 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * SECONDS_PER_DAY,
                ..model_neuron(1)
            },
            2 => Neuron {
                cached_neuron_stake_e8s: 100 * E8,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(100 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * SECONDS_PER_DAY,
                ..model_neuron(2)
            },
        });

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
                source_burn_fees: None,
                stake_transfer: Some(NeuronStakeTransfer {
                    amount_to_target_e8s: 300 * E8,
                    transaction_fee_e8s: TRANSACTION_FEES_E8S,
                }),
                source_effect: MergeNeuronsSourceEffect {
                    source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS,
                    },
                    subtract_maturity: 0,
                    subtract_staked_maturity: 0,
                },
                target_effect: MergeNeuronsTargetEffect {
                    target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS - 150 * SECONDS_PER_DAY,
                    },
                    add_maturity: 0,
                    add_staked_maturity: 0,
                },
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
        let neuron_store = NeuronStore::new(btreemap! {
            1 => Neuron {
                // Neither the minted stake (9_000) nor the neuron fees (8_000) are larger than the
                // transaction fees.
                cached_neuron_stake_e8s: 17_000,
                neuron_fees_e8s: 8_000,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(200 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 100 * SECONDS_PER_DAY,
                maturity_e8s_equivalent: 50 * E8,
                staked_maturity_e8s_equivalent: Some(40 * E8),
                ..model_neuron(1)
            },
            2 => Neuron {
                cached_neuron_stake_e8s: 100 * E8,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(100 * SECONDS_PER_DAY)),
                aging_since_timestamp_seconds: NOW_SECONDS - 300 * SECONDS_PER_DAY,
                ..model_neuron(2)
            },
        });

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
                source_burn_fees: None,
                stake_transfer: None,
                source_effect: MergeNeuronsSourceEffect {
                    source_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS - 100 * SECONDS_PER_DAY,
                    },
                    subtract_maturity: 50 * E8,
                    subtract_staked_maturity: 40 * E8,
                },
                target_effect: MergeNeuronsTargetEffect {
                    target_neuron_dissolve_state_and_age: DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 200 * SECONDS_PER_DAY,
                        aging_since_timestamp_seconds: NOW_SECONDS - 300 * SECONDS_PER_DAY,
                    },
                    add_maturity: 50 * E8,
                    add_staked_maturity: 40 * E8,
                },
            }
        );
    }

    use proptest::prelude::*;
    use proptest::proptest;

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
            let neuron_store = NeuronStore::new(btreemap! {
                1 => Neuron {
                    cached_neuron_stake_e8s: source_cached_stake,
                    neuron_fees_e8s: source_fees,
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(source_dissolve_delay_seconds)),
                    aging_since_timestamp_seconds: source_aging_since_timestamp_seconds,
                    maturity_e8s_equivalent: source_maturity,
                    staked_maturity_e8s_equivalent: if source_staked_maturity > 0 {
                        Some(source_staked_maturity)
                    } else {
                        None
                    },
                    ..model_neuron(1)
                },
                2 => Neuron {
                    cached_neuron_stake_e8s: target_cached_stake,
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(target_dissolve_delay_seconds)),
                    aging_since_timestamp_seconds: target_aging_since_timestamp_seconds,
                    ..model_neuron(2)
                },
            });

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

            if let Some(source_burn_fees) = effect.source_burn_fees {
                prop_assert!(source_burn_fees.amount_e8s <= source_fees);
            }
            if let Some(stake_transfer) = effect.stake_transfer {
                prop_assert!(
                    stake_transfer.amount_to_target_e8s + source_fees + transaction_fees_e8s
                        <= source_cached_stake
                );
                prop_assert_eq!(stake_transfer.transaction_fee_e8s, transaction_fees_e8s);
            }
            if let DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } = effect.source_effect.source_neuron_dissolve_state_and_age
            {
                prop_assert!(dissolve_delay_seconds >= source_dissolve_delay_seconds);
                prop_assert!(aging_since_timestamp_seconds >= source_aging_since_timestamp_seconds);
                prop_assert!(aging_since_timestamp_seconds <= NOW_SECONDS);
            } else {
                panic!("Source neuron should not stop dissolving after merging");
            }
            prop_assert_eq!(effect.source_effect.subtract_maturity, source_maturity);
            prop_assert_eq!(
                effect.source_effect.subtract_staked_maturity,
                source_staked_maturity
            );
            let target_state_and_age = effect.target_effect.target_neuron_dissolve_state_and_age;
            if let DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } = target_state_and_age
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
            prop_assert_eq!(effect.target_effect.add_maturity, source_maturity);
            prop_assert_eq!(
                effect.target_effect.add_staked_maturity,
                source_staked_maturity
            );
        }

    }
}
