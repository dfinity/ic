use crate::pb::v1::{
    create_service_nervous_system,
    create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters,
    CreateServiceNervousSystem,
};
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_proto::pb::v1::{Duration, GlobalTimeOfDay};
use ic_sns_init::pb::v1::{self as sns_init_pb, sns_init_payload, SnsInitPayload};
use ic_sns_swap::pb::v1::{self as sns_swap_pb, NeuronsFundParticipationConstraints};

#[derive(Clone, Debug)]
pub struct ExecutedCreateServiceNervousSystemProposal {
    pub current_timestamp_seconds: u64,
    pub create_service_nervous_system: CreateServiceNervousSystem,
    pub proposal_id: u64,
    pub random_swap_start_time: GlobalTimeOfDay,
    /// Information about the Neurons' Fund participation needed by the Swap canister.
    pub neurons_fund_participation_constraints: Option<NeuronsFundParticipationConstraints>,
}

impl TryFrom<ExecutedCreateServiceNervousSystemProposal> for SnsInitPayload {
    type Error = String;

    fn try_from(src: ExecutedCreateServiceNervousSystemProposal) -> Result<Self, Self::Error> {
        let mut defects = vec![];

        let current_timestamp_seconds = src.current_timestamp_seconds;
        let nns_proposal_id = Some(src.proposal_id);
        let neurons_fund_participation_constraints = src.neurons_fund_participation_constraints;
        let start_time = src
            .create_service_nervous_system
            .swap_parameters
            .as_ref()
            .and_then(|swap_parameters| swap_parameters.start_time);
        let duration = src
            .create_service_nervous_system
            .swap_parameters
            .as_ref()
            .and_then(|swap_parameters| swap_parameters.duration);

        let (swap_start_timestamp_seconds, swap_due_timestamp_seconds) =
            match CreateServiceNervousSystem::swap_start_and_due_timestamps(
                start_time.unwrap_or(src.random_swap_start_time),
                duration.unwrap_or_default(),
                current_timestamp_seconds,
            ) {
                Ok((swap_start_timestamp_seconds, swap_due_timestamp_seconds)) => (
                    Some(swap_start_timestamp_seconds),
                    Some(swap_due_timestamp_seconds),
                ),
                Err(err) => {
                    defects.push(err);
                    (None, None)
                }
            };

        let mut result = SnsInitPayload::try_from(src.create_service_nervous_system)?;

        result.nns_proposal_id = nns_proposal_id;
        result.swap_start_timestamp_seconds = swap_start_timestamp_seconds;
        result.swap_due_timestamp_seconds = swap_due_timestamp_seconds;
        result.neurons_fund_participation_constraints = neurons_fund_participation_constraints;

        result.validate_post_execution()?;

        Ok(result)
    }
}

impl CreateServiceNervousSystem {
    pub fn sns_token_e8s(&self) -> Option<u64> {
        self.initial_token_distribution
            .as_ref()?
            .swap_distribution
            .as_ref()?
            .total
            .as_ref()?
            .e8s
    }

    pub fn transaction_fee_e8s(&self) -> Option<u64> {
        self.ledger_parameters
            .as_ref()?
            .transaction_fee
            .as_ref()?
            .e8s
    }

    pub fn neuron_minimum_stake_e8s(&self) -> Option<u64> {
        self.governance_parameters
            .as_ref()?
            .neuron_minimum_stake
            .as_ref()?
            .e8s
    }

    /// Computes timestamps for when the SNS token swap will start, and will be
    /// due, based on the start and end times.
    ///
    /// The swap will start on the first `start_time_of_day` that is more than
    /// 24h after the swap was approved.
    ///
    /// The end time is calculated by adding `duration` to the computed start time.
    ///
    /// if start_time_of_day is None, then randomly_pick_swap_start is used to
    /// pick a start time.
    pub fn swap_start_and_due_timestamps(
        start_time_of_day: GlobalTimeOfDay,
        duration: Duration,
        swap_approved_timestamp_seconds: u64,
    ) -> Result<(u64, u64), String> {
        let start_time_of_day = start_time_of_day
            .seconds_after_utc_midnight
            .ok_or("`seconds_after_utc_midnight` should not be None")?;
        let duration = duration.seconds.ok_or("`seconds` should not be None")?;

        // TODO(NNS1-2298): we should also add 27 leap seconds to this, to avoid
        // having the swap start half a minute earlier than expected.
        let midnight_after_swap_approved_timestamp_seconds = swap_approved_timestamp_seconds
            .saturating_sub(swap_approved_timestamp_seconds % ONE_DAY_SECONDS) // floor to midnight
            .saturating_add(ONE_DAY_SECONDS); // add one day

        let swap_start_timestamp_seconds = {
            let mut possible_swap_starts = (0..2).map(|i| {
                midnight_after_swap_approved_timestamp_seconds
                    .saturating_add(ONE_DAY_SECONDS * i)
                    .saturating_add(start_time_of_day)
            });
            // Find the earliest time that's at least 24h after the swap was approved.
            possible_swap_starts
                .find(|&timestamp| timestamp > swap_approved_timestamp_seconds + ONE_DAY_SECONDS)
                .ok_or(format!(
                    "Unable to find a swap start time after the swap was approved. \
                     swap_approved_timestamp_seconds = {}, \
                     midnight_after_swap_approved_timestamp_seconds = {}, \
                     start_time_of_day = {}, \
                     duration = {} \
                     This is probably a bug.",
                    swap_approved_timestamp_seconds,
                    midnight_after_swap_approved_timestamp_seconds,
                    start_time_of_day,
                    duration,
                ))?
        };

        let swap_due_timestamp_seconds = duration
            .checked_add(swap_start_timestamp_seconds)
            .ok_or("`duration` should not be None")?;

        Ok((swap_start_timestamp_seconds, swap_due_timestamp_seconds))
    }
}

fn divide_perfectly(field_name: &str, dividend: u64, divisor: u64) -> Result<u64, String> {
    match dividend.checked_rem(divisor) {
        None => Err(format!(
            "Attempted to divide by zero while validating {}. \
                 (This is likely due to an internal bug.)",
            field_name,
        )),

        Some(0) => Ok(dividend.saturating_div(divisor)),

        Some(remainder) => {
            assert_ne!(remainder, 0);
            Err(format!(
                "{} is supposed to contain a value that is evenly divisible by {}, \
                 but it contains {}, which leaves a remainder of {}.",
                field_name, divisor, dividend, remainder,
            ))
        }
    }
}

impl TryFrom<CreateServiceNervousSystem> for SnsInitPayload {
    type Error = String;

    fn try_from(src: CreateServiceNervousSystem) -> Result<Self, String> {
        let CreateServiceNervousSystem {
            name,
            description,
            url,
            logo,
            fallback_controller_principal_ids,
            dapp_canisters,

            initial_token_distribution,

            swap_parameters,
            ledger_parameters,
            governance_parameters,
        } = src;

        let mut defects = vec![];

        let ledger_parameters = ledger_parameters.unwrap_or_default();
        let governance_parameters = governance_parameters.unwrap_or_default();
        let swap_parameters = swap_parameters.unwrap_or_default();

        let create_service_nervous_system::LedgerParameters {
            transaction_fee,
            token_name,
            token_symbol,
            token_logo,
        } = ledger_parameters;

        let transaction_fee_e8s = transaction_fee.and_then(|tokens| tokens.e8s);

        let token_logo = token_logo.and_then(|image| image.base64_encoding);

        let proposal_reject_cost_e8s = governance_parameters
            .proposal_rejection_fee
            .and_then(|tokens| tokens.e8s);

        let neuron_minimum_stake_e8s = governance_parameters
            .neuron_minimum_stake
            .and_then(|tokens| tokens.e8s);

        let initial_token_distribution = match sns_init_payload::InitialTokenDistribution::try_from(
            initial_token_distribution.unwrap_or_default(),
        ) {
            Ok(ok) => Some(ok),
            Err(err) => {
                defects.push(err);
                None
            }
        };

        let fallback_controller_principal_ids = fallback_controller_principal_ids
            .iter()
            .map(|principal_id| principal_id.to_string())
            .collect();

        let logo = logo.and_then(|image| image.base64_encoding);
        // url, name, and description need no conversion.

        let neuron_minimum_dissolve_delay_to_vote_seconds = governance_parameters
            .neuron_minimum_dissolve_delay_to_vote
            .and_then(|duration| duration.seconds);

        let voting_reward_parameters = governance_parameters
            .voting_reward_parameters
            .unwrap_or_default();

        let initial_reward_rate_basis_points = voting_reward_parameters
            .initial_reward_rate
            .and_then(|percentage| percentage.basis_points);
        let final_reward_rate_basis_points = voting_reward_parameters
            .final_reward_rate
            .and_then(|percentage| percentage.basis_points);

        let reward_rate_transition_duration_seconds = voting_reward_parameters
            .reward_rate_transition_duration
            .and_then(|duration| duration.seconds);

        let max_dissolve_delay_seconds = governance_parameters
            .neuron_maximum_dissolve_delay
            .and_then(|duration| duration.seconds);

        let max_neuron_age_seconds_for_age_bonus = governance_parameters
            .neuron_maximum_age_for_age_bonus
            .and_then(|duration| duration.seconds);

        let mut basis_points_to_percentage =
            |field_name, percentage: ic_nervous_system_proto::pb::v1::Percentage| -> u64 {
                let basis_points = percentage.basis_points.unwrap_or_default();
                match divide_perfectly(field_name, basis_points, 100) {
                    Ok(ok) => ok,
                    Err(err) => {
                        defects.push(err);
                        basis_points.saturating_div(100)
                    }
                }
            };

        let max_dissolve_delay_bonus_percentage = governance_parameters
            .neuron_maximum_dissolve_delay_bonus
            .map(|percentage| {
                basis_points_to_percentage(
                    "governance_parameters.neuron_maximum_dissolve_delay_bonus",
                    percentage,
                )
            });

        let max_age_bonus_percentage =
            governance_parameters
                .neuron_maximum_age_bonus
                .map(|percentage| {
                    basis_points_to_percentage(
                        "governance_parameters.neuron_maximum_age_bonus",
                        percentage,
                    )
                });

        let initial_voting_period_seconds = governance_parameters
            .proposal_initial_voting_period
            .and_then(|duration| duration.seconds);

        let wait_for_quiet_deadline_increase_seconds = governance_parameters
            .proposal_wait_for_quiet_deadline_increase
            .and_then(|duration| duration.seconds);

        let dapp_canisters = Some(sns_init_pb::DappCanisters {
            canisters: dapp_canisters,
        });

        let confirmation_text = swap_parameters.confirmation_text;

        let restricted_countries = swap_parameters.restricted_countries;

        let min_participants = swap_parameters.minimum_participants;

        let min_direct_participation_icp_e8s = swap_parameters
            .minimum_direct_participation_icp
            .and_then(|tokens| tokens.e8s);

        let max_direct_participation_icp_e8s = swap_parameters
            .maximum_direct_participation_icp
            .and_then(|tokens| tokens.e8s);

        // Check if the deprecated fields are set.
        if let Some(neurons_fund_investment_icp) = swap_parameters.neurons_fund_investment_icp {
            defects.push(format!(
                "neurons_fund_investment_icp ({:?}) is deprecated; please set \
                    neurons_fund_participation instead.",
                neurons_fund_investment_icp,
            ));
        }
        if let Some(minimum_icp) = swap_parameters.minimum_icp {
            defects.push(format!(
                "minimum_icp ({:?}) is deprecated; please set \
                    min_direct_participation_icp_e8s instead.",
                minimum_icp,
            ));
        };
        if let Some(maximum_icp) = swap_parameters.maximum_icp {
            defects.push(format!(
                "maximum_icp ({:?}) is deprecated; please set \
                    max_direct_participation_icp_e8s instead.",
                maximum_icp,
            ));
        };

        let neurons_fund_participation = swap_parameters.neurons_fund_participation;

        let min_participant_icp_e8s = swap_parameters
            .minimum_participant_icp
            .and_then(|tokens| tokens.e8s);

        let max_participant_icp_e8s = swap_parameters
            .maximum_participant_icp
            .and_then(|tokens| tokens.e8s);

        let neuron_basket_construction_parameters = swap_parameters
            .neuron_basket_construction_parameters
            .map(
                |basket| ic_sns_swap::pb::v1::NeuronBasketConstructionParameters {
                    count: basket.count.unwrap_or_default(),
                    dissolve_delay_interval_seconds: basket
                        .dissolve_delay_interval
                        .map(|duration| duration.seconds.unwrap_or_default())
                        .unwrap_or_default(),
                },
            );

        if !defects.is_empty() {
            return Err(format!(
                "Failed to convert CreateServiceNervousSystem proposal to SnsInitPayload:\n{}",
                defects.join("\n"),
            ));
        }

        let result = Self {
            transaction_fee_e8s,
            token_name,
            token_symbol,
            proposal_reject_cost_e8s,
            neuron_minimum_stake_e8s,
            initial_token_distribution,
            fallback_controller_principal_ids,
            logo,
            url,
            name,
            description,
            neuron_minimum_dissolve_delay_to_vote_seconds,
            initial_reward_rate_basis_points,
            final_reward_rate_basis_points,
            reward_rate_transition_duration_seconds,
            max_dissolve_delay_seconds,
            max_neuron_age_seconds_for_age_bonus,
            max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage,
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            dapp_canisters,
            min_participants,
            min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s,
            min_participant_icp_e8s,
            max_participant_icp_e8s,
            neuron_basket_construction_parameters,
            confirmation_text,
            restricted_countries,
            token_logo,
            neurons_fund_participation,

            // These are not known from only the CreateServiceNervousSystem
            // proposal. See TryFrom<ExecutedCreateServiceNervousSystemProposal>
            nns_proposal_id: None,
            neurons_fund_participants: None,
            swap_start_timestamp_seconds: None,
            swap_due_timestamp_seconds: None,
            neurons_fund_participation_constraints: None,

            // Deprecated fields should be set to `None`.
            min_icp_e8s: None,
            max_icp_e8s: None,
        };

        result.validate_pre_execution()?;

        Ok(result)
    }
}

impl TryFrom<create_service_nervous_system::InitialTokenDistribution>
    for sns_init_payload::InitialTokenDistribution
{
    type Error = String;

    fn try_from(
        src: create_service_nervous_system::InitialTokenDistribution,
    ) -> Result<Self, String> {
        let create_service_nervous_system::InitialTokenDistribution {
            developer_distribution,
            treasury_distribution,
            swap_distribution,
        } = src;

        let mut defects = vec![];

        let developer_distribution = match sns_init_pb::DeveloperDistribution::try_from(
            developer_distribution.unwrap_or_default(),
        ) {
            Ok(ok) => Some(ok),
            Err(err) => {
                defects.push(err);
                None
            }
        };

        let treasury_distribution = match sns_init_pb::TreasuryDistribution::try_from(
            treasury_distribution.unwrap_or_default(),
        ) {
            Ok(ok) => Some(ok),
            Err(err) => {
                defects.push(err);
                None
            }
        };

        let swap_distribution =
            match sns_init_pb::SwapDistribution::try_from(swap_distribution.unwrap_or_default()) {
                Ok(ok) => Some(ok),
                Err(err) => {
                    defects.push(err);
                    None
                }
            };

        let airdrop_distribution = Some(sns_init_pb::AirdropDistribution::default());

        if !defects.is_empty() {
            return Err(format!(
                "Failed to convert to InitialTokenDistribution for the following reasons:\n{}",
                defects.join("\n"),
            ));
        }

        Ok(Self::FractionalDeveloperVotingPower(
            sns_init_pb::FractionalDeveloperVotingPower {
                developer_distribution,
                treasury_distribution,
                swap_distribution,
                airdrop_distribution,
            },
        ))
    }
}

impl TryFrom<create_service_nervous_system::initial_token_distribution::SwapDistribution>
    for sns_init_pb::SwapDistribution
{
    type Error = String;

    fn try_from(
        src: create_service_nervous_system::initial_token_distribution::SwapDistribution,
    ) -> Result<Self, String> {
        let create_service_nervous_system::initial_token_distribution::SwapDistribution { total } =
            src;

        let total_e8s = total.unwrap_or_default().e8s.unwrap_or_default();
        let initial_swap_amount_e8s = total_e8s;

        Ok(Self {
            initial_swap_amount_e8s,
            total_e8s,
        })
    }
}

impl TryFrom<create_service_nervous_system::initial_token_distribution::TreasuryDistribution>
    for sns_init_pb::TreasuryDistribution
{
    type Error = String;

    fn try_from(
        src: create_service_nervous_system::initial_token_distribution::TreasuryDistribution,
    ) -> Result<Self, String> {
        let create_service_nervous_system::initial_token_distribution::TreasuryDistribution {
            total,
        } = src;

        let total_e8s = total.unwrap_or_default().e8s.unwrap_or_default();

        Ok(Self { total_e8s })
    }
}

impl TryFrom<create_service_nervous_system::initial_token_distribution::DeveloperDistribution>
    for sns_init_pb::DeveloperDistribution
{
    type Error = String;

    fn try_from(
        src: create_service_nervous_system::initial_token_distribution::DeveloperDistribution,
    ) -> Result<Self, String> {
        let create_service_nervous_system::initial_token_distribution::DeveloperDistribution {
            developer_neurons,
        } = src;

        let mut defects = vec![];

        let developer_neurons =
            developer_neurons
                .into_iter()
                .enumerate()
                .filter_map(|(i, neuron_distribution)| {
                    match sns_init_pb::NeuronDistribution::try_from(neuron_distribution) {
                        Ok(ok) => Some(ok),
                        Err(err) => {
                            defects.push(format!(
                                "Failed to convert element at index {} in field \
                             `developer_neurons`: {}",
                                i, err,
                            ));
                            None
                        }
                    }
                })
                .collect();

        if !defects.is_empty() {
            return Err(format!(
                "Failed to convert to DeveloperDistribution for SnsInitPayload: {}",
                defects.join("\n"),
            ));
        }

        Ok(Self { developer_neurons })
    }
}

impl TryFrom<create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution>
for sns_init_pb::NeuronDistribution
{
    type Error = String;

    fn try_from(
        src: create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution,
    ) -> Result<Self, String> {
        let create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution {
            controller,
            dissolve_delay,
            memo,
            stake,
            vesting_period,
        } = src;

        // controller needs no conversion
        let stake_e8s = stake.unwrap_or_default().e8s.unwrap_or_default();
        let memo = memo.unwrap_or_default();
        let dissolve_delay_seconds = dissolve_delay
            .unwrap_or_default()
            .seconds
            .unwrap_or_default();
        let vesting_period_seconds = vesting_period.unwrap_or_default().seconds;

        Ok(Self {
            controller,
            stake_e8s,
            memo,
            dissolve_delay_seconds,
            vesting_period_seconds,
        })
    }
}

impl TryFrom<NeuronBasketConstructionParameters>
    for sns_swap_pb::NeuronBasketConstructionParameters
{
    type Error = String;

    fn try_from(
        neuron_basket_construction_parameters: NeuronBasketConstructionParameters,
    ) -> Result<Self, Self::Error> {
        let NeuronBasketConstructionParameters {
            count,
            dissolve_delay_interval,
        } = neuron_basket_construction_parameters;

        let params = sns_swap_pb::NeuronBasketConstructionParameters {
            count: count.ok_or("`count` should not be None")?,
            dissolve_delay_interval_seconds: dissolve_delay_interval
                .ok_or("`dissolve_delay_interval` should not be None")?
                .seconds
                .ok_or("`seconds` should not be None")?,
        };
        Ok(params)
    }
}
