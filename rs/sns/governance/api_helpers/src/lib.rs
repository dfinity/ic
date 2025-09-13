use ic_nervous_system_common::{
    DEFAULT_TRANSFER_FEE, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS,
};
use ic_sns_governance_api::pb::v1::{
    DefaultFollowees, GovernanceError, NervousSystemParameters, Neuron, NeuronId,
    NeuronPermissionList, NeuronPermissionType, VotingRewardsParameters,
    governance_error::ErrorType,
};
use icrc_ledger_types::icrc1::account::Subaccount;
use maplit::btreemap;

/// The number of e8s per governance token;
pub const E8S_PER_TOKEN: u64 = 100_000_000;

pub const DEFAULT_NEURON_CLAIMER_PERMISSIONS: &[NeuronPermissionType] = &[
    NeuronPermissionType::ManagePrincipals,
    NeuronPermissionType::Vote,
    NeuronPermissionType::SubmitProposal,
];

pub fn default_nervous_system_parameters() -> NervousSystemParameters {
    NervousSystemParameters {
        reject_cost_e8s: Some(E8S_PER_TOKEN), // 1 governance token
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN), // 1 governance token
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        max_proposals_to_keep_per_action: Some(100),
        initial_voting_period_seconds: Some(4 * ONE_DAY_SECONDS), // 4d
        wait_for_quiet_deadline_increase_seconds: Some(ONE_DAY_SECONDS), // 1d
        default_followees: Some(DefaultFollowees {
            followees: btreemap! {},
        }),
        max_number_of_neurons: Some(200_000),
        neuron_minimum_dissolve_delay_to_vote_seconds: Some(6 * ONE_MONTH_SECONDS), // 6m
        max_followees_per_function: Some(15),
        max_dissolve_delay_seconds: Some(8 * ONE_YEAR_SECONDS), // 8y
        max_neuron_age_for_age_bonus: Some(4 * ONE_YEAR_SECONDS), // 4y
        max_number_of_proposals_with_ballots: Some(700),
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: DEFAULT_NEURON_CLAIMER_PERMISSIONS
                .iter()
                .map(|p| *p as i32)
                .collect(),
        }),
        neuron_grantable_permissions: Some(NeuronPermissionList::default()),
        max_number_of_principals_per_neuron: Some(5),
        voting_rewards_parameters: Some(VotingRewardsParameters {
            round_duration_seconds: Some(ONE_DAY_SECONDS),
            reward_rate_transition_duration_seconds: Some(0),
            initial_reward_rate_basis_points: Some(0),
            final_reward_rate_basis_points: Some(0),
        }),
        max_dissolve_delay_bonus_percentage: Some(100),
        max_age_bonus_percentage: Some(25),
        maturity_modulation_disabled: Some(false),
        automatically_advance_target_version: Some(true),
    }
}

pub fn neuron_id_subaccount_or_err(neuron_id: &NeuronId) -> Result<Subaccount, GovernanceError> {
    let subaccount =
        Subaccount::try_from(neuron_id.id.as_slice()).map_err(|err| GovernanceError {
            error_type: i32::from(ErrorType::InvalidNeuronId),
            error_message: format!("Could not convert NeuronId to Subaccount {err}"),
        })?;

    Ok(subaccount)
}

pub fn get_neuron_subaccount_or_err(neuron: &Neuron) -> Result<Subaccount, GovernanceError> {
    let Some(neuron_id) = &neuron.id else {
        return Err(GovernanceError {
            error_type: i32::from(ErrorType::NotFound),
            error_message: "Neuron must have a subaccount".to_string(),
        });
    };

    neuron_id_subaccount_or_err(neuron_id)
}
