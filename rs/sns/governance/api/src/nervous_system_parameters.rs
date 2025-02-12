use crate::pb::v1::{
    DefaultFollowees, NervousSystemParameters, NeuronPermissionList, NeuronPermissionType,
    VotingRewardsParameters,
};
use ic_ledger_core::tokens::TOKEN_SUBDIVIDABLE_BY;
use ic_nervous_system_common::{
    DEFAULT_TRANSFER_FEE, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS,
};

/// The number of e8s per governance token;
const E8S_PER_TOKEN: u64 = TOKEN_SUBDIVIDABLE_BY;

impl NervousSystemParameters {
    /// These are the permissions that must be present in
    /// `neuron_claimer_permissions`.
    /// Permissions not in this list can be added after the SNS is created via a
    /// proposal.
    pub const REQUIRED_NEURON_CLAIMER_PERMISSIONS: &'static [NeuronPermissionType] = &[
        // Without this permission, it would be impossible to transfer control
        // of a neuron to a new principal.
        NeuronPermissionType::ManagePrincipals,
        // Without this permission, it would be impossible to vote.
        NeuronPermissionType::Vote,
        // Without this permission, it would be impossible to submit a proposal.
        NeuronPermissionType::SubmitProposal,
    ];

    /// Returns the default for the nervous system parameter neuron_claimer_permissions.
    fn default_neuron_claimer_permissions() -> NeuronPermissionList {
        NeuronPermissionList {
            permissions: Self::REQUIRED_NEURON_CLAIMER_PERMISSIONS
                .iter()
                .map(|p| *p as i32)
                .collect(),
        }
    }
}

impl Default for NervousSystemParameters {
    fn default() -> Self {
        Self {
            reject_cost_e8s: Some(E8S_PER_TOKEN), // 1 governance token
            neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN), // 1 governance token
            transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
            max_proposals_to_keep_per_action: Some(100),
            initial_voting_period_seconds: Some(4 * ONE_DAY_SECONDS), // 4d
            wait_for_quiet_deadline_increase_seconds: Some(ONE_DAY_SECONDS), // 1d
            default_followees: Some(DefaultFollowees::default()),
            max_number_of_neurons: Some(200_000),
            neuron_minimum_dissolve_delay_to_vote_seconds: Some(6 * ONE_MONTH_SECONDS), // 6m
            max_followees_per_function: Some(15),
            max_dissolve_delay_seconds: Some(8 * ONE_YEAR_SECONDS), // 8y
            max_neuron_age_for_age_bonus: Some(4 * ONE_YEAR_SECONDS), // 4y
            max_number_of_proposals_with_ballots: Some(700),
            neuron_claimer_permissions: Some(Self::default_neuron_claimer_permissions()),
            neuron_grantable_permissions: Some(NeuronPermissionList::default()),
            max_number_of_principals_per_neuron: Some(5),
            voting_rewards_parameters: Some(VotingRewardsParameters::with_default_values()),
            max_dissolve_delay_bonus_percentage: Some(100),
            max_age_bonus_percentage: Some(25),
            maturity_modulation_disabled: Some(false),
            automatically_advance_target_version: Some(false),
        }
    }
}
