use anyhow::{anyhow, Result};
use ic_base_types::PrincipalId;
use ic_nervous_system_proto::pb::v1 as nervous_system_pb;
use ic_nns_governance_api::{
    pb::v1::{proposal::Action, CreateServiceNervousSystem, Proposal},
    proposal_validation::validate_user_submitted_proposal_fields,
};
use ic_sns_init::pb::v1::SnsInitPayload;
use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    str::FromStr,
};

// Alias CreateServiceNervousSystem-related types, but since we have many
// related types in this module, put these aliases in their own module to avoid
// getting mixed up.
mod nns_governance_pb {
    pub use ic_nns_governance_api::pb::v1::create_service_nervous_system::{
        governance_parameters::VotingRewardParameters,
        initial_token_distribution::{
            developer_distribution::NeuronDistribution, DeveloperDistribution, SwapDistribution,
            TreasuryDistribution,
        },
        swap_parameters::NeuronBasketConstructionParameters,
        GovernanceParameters, InitialTokenDistribution, LedgerParameters, SwapParameters,
    };
}

#[cfg(test)]
mod friendly_tests;

// Implements the format used by test_sns_init_v2.yaml in the root of this
// package. Studying that is a much more ergonomic way of becoming familiar with
// the format that we are trying to implement here.
//
// (Thanks to the magic of serde, all the code here is declarative.)
#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnsConfigurationFile {
    name: String,
    description: String,
    logo: PathBuf,
    url: String,

    #[serde(rename = "Principals", default)]
    principals: Vec<PrincipalAlias>,

    fallback_controller_principals: Vec<String>, // Principal (alias)
    dapp_canisters: Vec<String>,                 // Principal (alias)

    #[serde(rename = "Token")]
    token: Token,

    #[serde(rename = "Proposals")]
    proposals: Proposals,

    #[serde(rename = "Neurons")]
    neurons: Neurons,

    #[serde(rename = "Voting")]
    voting: Voting,

    #[serde(rename = "Distribution")]
    distribution: Distribution,

    #[serde(rename = "Swap")]
    swap: Swap,

    #[serde(rename = "NnsProposal")]
    nns_proposal: NnsProposal,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrincipalAlias {
    id: String, // PrincipalId
    name: Option<String>,
    email: Option<String>,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Token {
    name: String,
    symbol: String,
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    transaction_fee: nervous_system_pb::Tokens,
    logo: PathBuf,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proposals {
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    rejection_fee: nervous_system_pb::Tokens,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    initial_voting_period: nervous_system_pb::Duration,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    maximum_wait_for_quiet_deadline_extension: nervous_system_pb::Duration,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Neurons {
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    minimum_creation_stake: nervous_system_pb::Tokens,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Voting {
    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    minimum_dissolve_delay: nervous_system_pb::Duration,

    #[serde(rename = "MaximumVotingPowerBonuses")]
    maximum_voting_power_bonuses: MaximumVotingPowerBonuses,

    #[serde(rename = "RewardRate")]
    reward_rate: RewardRate,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaximumVotingPowerBonuses {
    #[serde(rename = "DissolveDelay")]
    dissolve_delay: Bonus,

    #[serde(rename = "Age")]
    age: Bonus,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bonus {
    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    duration: nervous_system_pb::Duration,

    #[serde(with = "ic_nervous_system_humanize::serde::percentage")]
    bonus: nervous_system_pb::Percentage,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RewardRate {
    #[serde(with = "ic_nervous_system_humanize::serde::percentage")]
    initial: nervous_system_pb::Percentage,

    #[serde(with = "ic_nervous_system_humanize::serde::percentage")]
    r#final: nervous_system_pb::Percentage,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    transition_duration: nervous_system_pb::Duration,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Swap {
    minimum_participants: u64,

    #[serde(default)]
    #[serde(with = "ic_nervous_system_humanize::serde::optional_tokens")]
    minimum_icp: Option<nervous_system_pb::Tokens>,
    #[serde(default)]
    #[serde(with = "ic_nervous_system_humanize::serde::optional_tokens")]
    maximum_icp: Option<nervous_system_pb::Tokens>,

    #[serde(default)]
    #[serde(with = "ic_nervous_system_humanize::serde::optional_tokens")]
    minimum_direct_participation_icp: Option<nervous_system_pb::Tokens>,
    #[serde(default)]
    #[serde(with = "ic_nervous_system_humanize::serde::optional_tokens")]
    maximum_direct_participation_icp: Option<nervous_system_pb::Tokens>,

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    minimum_participant_icp: nervous_system_pb::Tokens,
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    maximum_participant_icp: nervous_system_pb::Tokens,

    confirmation_text: Option<String>,
    restricted_countries: Option<Vec<String>>,

    #[serde(rename = "VestingSchedule")]
    vesting_schedule: VestingSchedule,

    #[serde(default)]
    #[serde(with = "ic_nervous_system_humanize::serde::optional_time_of_day")]
    start_time: Option<nervous_system_pb::GlobalTimeOfDay>,
    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    duration: nervous_system_pb::Duration,

    #[serde(default)]
    #[serde(with = "ic_nervous_system_humanize::serde::optional_tokens")]
    neurons_fund_investment_icp: Option<nervous_system_pb::Tokens>,

    #[serde(default)]
    neurons_fund_participation: Option<bool>,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VestingSchedule {
    events: u64,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    interval: nervous_system_pb::Duration,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Distribution {
    #[serde(rename = "Neurons")]
    neurons: Vec<Neuron>,

    #[serde(rename = "InitialBalances")]
    initial_balances: InitialBalances,

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    total: nervous_system_pb::Tokens,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Neuron {
    principal: String, // Principal (alias)

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    stake: nervous_system_pb::Tokens,

    #[serde(default)]
    memo: u64,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    dissolve_delay: nervous_system_pb::Duration,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    vesting_period: nervous_system_pb::Duration,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialBalances {
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    governance: nervous_system_pb::Tokens,

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    swap: nervous_system_pb::Tokens,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct NnsProposal {
    title: String,
    summary: String,
    url: Option<String>,
}

struct AliasToPrincipalId<'a> {
    #[allow(unused)]
    source: &'a Vec<PrincipalAlias>,
    /* TODO
    #[derive(Eq, PartialEq, Hash, Debug)]
    enum Key { // TODO: This name is just a placeholder.
        Name(String),
        Email(String),
    }

        alias_to_principal_id: HashMap<Key, PrincipalId>,
        */
}

impl<'a> AliasToPrincipalId<'a> {
    fn new(source: &'a Vec<PrincipalAlias>) -> Self {
        Self { source }
    }

    /// TODO: Currently, this just does PrincipalId::from_str, but real alias
    /// substitution is planned for a future MR.
    fn unalias(
        &self,
        field_name: &str,
        principals: &[String],
    ) -> Result<Vec<PrincipalId>, Vec<String>> {
        let mut defects = vec![];

        let result = principals
            .iter()
            .map(|string| {
                PrincipalId::from_str(string)
                    .map_err(|err| {
                        defects.push(format!(
                            "Unable to parse PrincipalId ({:?}) in {}. Reason: {}",
                            string, field_name, err,
                        ))
                    })
                    .unwrap_or_default()
            })
            .collect();

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(result)
    }
}

/// Parses an image PathBuf and base64 encodes the content
fn parse_image_path(
    image_path: &PathBuf,
    base_path: &Path,
) -> Result<nervous_system_pb::Image, String> {
    // Read the image file contents from the path buf
    let image = Path::new(image_path);
    let image = if image.is_relative() {
        base_path.join(image)
    } else {
        image.to_path_buf()
    };
    let image = image.as_path();
    let image_content = std::fs::read(image).map_err(|err| {
        format!(
            "An error occurred while reading the image file ({:?}): {}",
            image_path, err,
        )
    })?;
    let image_content = base64::encode(image_content);
    let base64_encoding = Some(format!("data:image/png;base64,{}", image_content));
    Ok(nervous_system_pb::Image { base64_encoding })
}

impl SnsConfigurationFile {
    pub fn try_convert_to_nns_proposal(&self, base_path: &Path) -> Result<Proposal> {
        // Extract the proposal action from the config file
        let create_service_nervous_system =
            self.try_convert_to_create_service_nervous_system(base_path)?;

        let SnsConfigurationFile {
            name: _,
            description: _,
            logo: _,
            url: _,
            principals: _,
            fallback_controller_principals: _,
            dapp_canisters: _,
            token: _,
            proposals: _,
            neurons: _,
            voting: _,
            distribution: _,
            swap: _,
            nns_proposal,
        } = self;

        // Extract the Proposal metadata (title, url, description, etc) from the config file
        let title = Some(nns_proposal.title.clone());
        let summary = nns_proposal.summary.clone();
        // Empty strings is a legal NNS Proposal Url.
        let url = nns_proposal.url.clone().unwrap_or_default();

        let proposal = Proposal {
            title,
            summary,
            url,
            action: Some(Action::CreateServiceNervousSystem(
                create_service_nervous_system,
            )),
        };

        validate_user_submitted_proposal_fields(&(proposal.clone()))
            .map_err(|e| anyhow!("{}", e))?;

        Ok(proposal)
    }

    pub fn try_convert_to_create_service_nervous_system(
        &self,
        base_path: &Path,
    ) -> Result<CreateServiceNervousSystem> {
        // Step 1: Unpack.
        let SnsConfigurationFile {
            name,
            description,
            logo,
            url,
            principals,
            fallback_controller_principals,
            dapp_canisters,
            token,
            proposals,
            neurons,
            voting,
            distribution,
            swap,
            nns_proposal: _, // We ignore the NNS Proposal fields
        } = self;

        // Step 2: Convert components.
        //
        // (This is the main section, where the "real" work takes place.)
        let alias_to_principal_id = AliasToPrincipalId::new(principals);
        let mut defects = vec![];

        // 2.1: Convert "primitive" typed fields.

        let name = Some(name.clone());
        let description = Some(description.clone());
        let url = Some(url.clone());

        let logo = parse_image_path(logo, base_path)
            .map(Some)
            .map_err(|err| defects.push(err))
            .unwrap_or_default();

        // 2.2: Convert Vec fields.

        let fallback_controller_principal_ids = alias_to_principal_id
            .unalias(
                "fallback_controller_principals",
                fallback_controller_principals,
            )
            .map_err(|inner_defects| defects.extend(inner_defects))
            .unwrap_or_default();

        let dapp_canisters = alias_to_principal_id
            .unalias("dapp_canisters", dapp_canisters)
            .map_err(|inner_defects| defects.extend(inner_defects))
            .unwrap_or_default();

        // Wrap in Canister.
        let dapp_canisters = dapp_canisters
            .into_iter()
            .map(|principal_id| {
                let id = Some(principal_id);
                nervous_system_pb::Canister { id }
            })
            .collect();

        // 2.3: Convert composite fields.
        let initial_token_distribution = Some(
            distribution
                .try_convert_to_initial_token_distribution()
                .map_err(|inner_defects| defects.extend(inner_defects))
                .unwrap_or_default(),
        );
        let swap_parameters = Some(swap.convert_to_swap_parameters());
        let ledger_parameters = Some(
            token
                .convert_to_ledger_parameters(base_path)
                .map_err(|inner_defects| defects.extend(inner_defects))
                .unwrap_or_default(),
        );
        let governance_parameters =
            Some(convert_to_governance_parameters(proposals, neurons, voting));

        // Step 3: Repackage.
        let result = CreateServiceNervousSystem {
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
        };

        // Step 4: Validate.
        if !defects.is_empty() {
            return Err(anyhow!(
                "Unable to convert configuration file to proposal for the following \
                 reason(s):\n  -{}",
                defects.join("\n  -"),
            ));
        }
        if let Err(err) = SnsInitPayload::try_from(result.clone()) {
            return Err(anyhow!(
                "Unable to convert configuration file to proposal: {}",
                err,
            ));
        }

        // Step 5: Ship it!
        Ok(result)
    }
}

impl Distribution {
    fn try_convert_to_initial_token_distribution(
        &self,
    ) -> Result<nns_governance_pb::InitialTokenDistribution, Vec<String>> {
        let Distribution {
            neurons,
            initial_balances,
            total,
        } = self;

        let mut defects = vec![];
        // IDEALLY: Make Tokens support operators like +, -, and *. Ditto for
        // Duration, Percentage.
        let mut observed_total_e8s = 0;

        let developer_distribution =
            try_convert_from_neuron_vec_to_developer_distribution_and_total_stake(neurons)
                .map_err(|inner_defects| defects.extend(inner_defects))
                .unwrap_or_default();
        observed_total_e8s += developer_distribution
            .developer_neurons
            .iter()
            .map(|developer_neuron| {
                developer_neuron
                    .stake
                    .unwrap_or_default()
                    .e8s
                    .unwrap_or_default()
            })
            .sum::<u64>();
        let developer_distribution = Some(developer_distribution);

        let (treasury_distribution, swap_distribution) = {
            let InitialBalances { governance, swap } = initial_balances;

            observed_total_e8s += governance.e8s.unwrap_or_default();
            observed_total_e8s += swap.e8s.unwrap_or_default();

            (
                Some(nns_governance_pb::TreasuryDistribution {
                    total: Some(*governance),
                }),
                Some(nns_governance_pb::SwapDistribution { total: Some(*swap) }),
            )
        };

        // Validate total SNS tokens.
        if observed_total_e8s != total.e8s.unwrap_or_default() {
            defects.push(format!(
                "The total amount of SNS tokens was expected to be {}, but was instead {}.",
                ic_nervous_system_humanize::format_tokens(total),
                ic_nervous_system_humanize::format_tokens(&nervous_system_pb::Tokens {
                    e8s: Some(observed_total_e8s),
                }),
            ));
        }

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(nns_governance_pb::InitialTokenDistribution {
            developer_distribution,
            treasury_distribution,
            swap_distribution,
        })
    }
}

fn try_convert_from_neuron_vec_to_developer_distribution_and_total_stake(
    original: &[Neuron],
) -> Result<nns_governance_pb::DeveloperDistribution, Vec<String>> {
    let mut defects = vec![];

    let developer_neurons = original
        .iter()
        .map(|neuron| {
            neuron
                .try_convert_to_neuron_distribution()
                .map_err(|inner_defects| defects.extend(inner_defects))
                .unwrap_or_default()
        })
        .collect();

    if !defects.is_empty() {
        return Err(defects);
    }

    Ok(nns_governance_pb::DeveloperDistribution { developer_neurons })
}

impl Neuron {
    fn try_convert_to_neuron_distribution(
        &self,
    ) -> Result<nns_governance_pb::NeuronDistribution, Vec<String>> {
        let Neuron {
            principal,
            stake,
            memo,
            dissolve_delay,
            vesting_period,
        } = self;

        let mut defects = vec![];

        let controller = PrincipalId::from_str(principal)
            .map_err(|err| {
                defects.push(format!(
                    "Unable to parse PrincipalId in distribution.neurons ({:?}). \
                     err: {:#?}",
                    principal, err,
                ))
            })
            .unwrap_or_default();
        let controller = Some(controller);

        let dissolve_delay = Some(*dissolve_delay);
        let memo = Some(*memo);
        let stake = Some(*stake);

        let vesting_period = Some(*vesting_period);

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(nns_governance_pb::NeuronDistribution {
            controller,
            dissolve_delay,
            memo,
            stake,
            vesting_period,
        })
    }
}

impl Token {
    fn convert_to_ledger_parameters(
        &self,
        base_path: &Path,
    ) -> Result<nns_governance_pb::LedgerParameters, Vec<String>> {
        let Token {
            name,
            symbol,
            transaction_fee,
            logo,
        } = self;

        let token_name = Some(name.clone());
        let token_symbol = Some(symbol.clone());
        let transaction_fee = Some(*transaction_fee);

        // Read the token-logo file contents from the path buf
        let token_logo = parse_image_path(logo, base_path)
            .map(Some)
            .map_err(|err| vec![err])?;

        Ok(nns_governance_pb::LedgerParameters {
            token_name,
            token_symbol,
            transaction_fee,
            token_logo,
        })
    }
}

fn convert_to_governance_parameters(
    proposals: &Proposals,
    neurons: &Neurons,
    voting: &Voting,
) -> nns_governance_pb::GovernanceParameters {
    let Proposals {
        rejection_fee,
        initial_voting_period,
        maximum_wait_for_quiet_deadline_extension,
    } = proposals;
    let Neurons {
        minimum_creation_stake,
    } = neurons;
    let Voting {
        minimum_dissolve_delay,
        maximum_voting_power_bonuses,
        reward_rate,
    } = voting;
    let MaximumVotingPowerBonuses {
        dissolve_delay,
        age,
    } = maximum_voting_power_bonuses;

    let proposal_rejection_fee = Some(*rejection_fee);
    let proposal_initial_voting_period = Some(*initial_voting_period);
    let proposal_wait_for_quiet_deadline_increase =
        Some(*maximum_wait_for_quiet_deadline_extension);

    let neuron_minimum_stake = Some(*minimum_creation_stake);
    let neuron_minimum_dissolve_delay_to_vote = Some(*minimum_dissolve_delay);

    let (neuron_maximum_dissolve_delay, neuron_maximum_dissolve_delay_bonus) = {
        let Bonus { duration, bonus } = dissolve_delay;

        (Some(*duration), Some(*bonus))
    };

    let (neuron_maximum_age_for_age_bonus, neuron_maximum_age_bonus) = {
        let Bonus { duration, bonus } = age;

        (Some(*duration), Some(*bonus))
    };

    let voting_reward_parameters = Some(reward_rate.convert_to_voting_reward_parameters());

    nns_governance_pb::GovernanceParameters {
        proposal_rejection_fee,
        proposal_initial_voting_period,
        proposal_wait_for_quiet_deadline_increase,

        neuron_minimum_stake,

        neuron_minimum_dissolve_delay_to_vote,
        neuron_maximum_dissolve_delay,
        neuron_maximum_dissolve_delay_bonus,

        neuron_maximum_age_for_age_bonus,
        neuron_maximum_age_bonus,

        voting_reward_parameters,
    }
}

impl RewardRate {
    fn convert_to_voting_reward_parameters(&self) -> nns_governance_pb::VotingRewardParameters {
        let RewardRate {
            initial,
            r#final,
            transition_duration,
        } = self;

        let initial_reward_rate = Some(*initial);
        let final_reward_rate = Some(*r#final);
        let reward_rate_transition_duration = Some(*transition_duration);

        nns_governance_pb::VotingRewardParameters {
            initial_reward_rate,
            final_reward_rate,
            reward_rate_transition_duration,
        }
    }
}

impl Swap {
    fn convert_to_swap_parameters(&self) -> nns_governance_pb::SwapParameters {
        let Swap {
            minimum_participants,

            minimum_icp,
            maximum_icp,

            minimum_direct_participation_icp,
            maximum_direct_participation_icp,

            maximum_participant_icp,
            minimum_participant_icp,

            confirmation_text,
            restricted_countries,

            vesting_schedule,

            start_time,
            duration,
            neurons_fund_investment_icp,
            neurons_fund_participation,
        } = self;

        let minimum_participants = Some(*minimum_participants);

        let minimum_icp = *minimum_icp;
        let maximum_icp = *maximum_icp;

        let minimum_direct_participation_icp = minimum_direct_participation_icp
            .or_else(|| minimum_icp?.checked_sub(&neurons_fund_investment_icp.unwrap_or_default()));
        let maximum_direct_participation_icp = maximum_direct_participation_icp
            .or_else(|| maximum_icp?.checked_sub(&neurons_fund_investment_icp.unwrap_or_default()));

        let maximum_participant_icp = Some(*maximum_participant_icp);
        let minimum_participant_icp = Some(*minimum_participant_icp);

        let confirmation_text = confirmation_text.clone();
        let restricted_countries = restricted_countries.as_ref().map(|restricted_countries| {
            nervous_system_pb::Countries {
                iso_codes: restricted_countries.clone(),
            }
        });

        let neuron_basket_construction_parameters =
            Some(vesting_schedule.convert_to_neuron_basket_construction_parameters());

        let start_time = *start_time;
        let duration = Some(*duration);

        let neurons_fund_participation = *neurons_fund_participation;

        nns_governance_pb::SwapParameters {
            minimum_participants,

            minimum_icp,
            maximum_icp,

            minimum_direct_participation_icp,
            maximum_direct_participation_icp,

            maximum_participant_icp,
            minimum_participant_icp,

            neuron_basket_construction_parameters,

            confirmation_text,
            restricted_countries,

            start_time,
            duration,

            neurons_fund_investment_icp: *neurons_fund_investment_icp,
            neurons_fund_participation,
        }
    }
}

impl VestingSchedule {
    fn convert_to_neuron_basket_construction_parameters(
        &self,
    ) -> nns_governance_pb::NeuronBasketConstructionParameters {
        let VestingSchedule { events, interval } = self;

        let count = Some(*events);
        let dissolve_delay_interval = Some(*interval);

        nns_governance_pb::NeuronBasketConstructionParameters {
            count,
            dissolve_delay_interval,
        }
    }
}
