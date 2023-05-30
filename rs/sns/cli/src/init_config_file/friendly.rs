use ic_nervous_system_proto::pb::v1 as nervous_system_pb;
use std::path::PathBuf;

// Implements the format used by example_sns_init_v2.yaml in the root of this
// package. Studying that is a much more ergonomic way of becoming familiar with
// the format that we are trying to implement here.
//
// (Thanks to the magic of serde, all the code here is declarative.)
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SnsConfigurationFile {
    name: String,
    description: String,
    logo: PathBuf,
    url: String,

    #[serde(rename = "Principals")]
    principals: Vec<PrincipalAlias>,

    fallback_controller_principals: Vec<String>, // Principal (alias)

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
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrincipalAlias {
    id: String, // PrincipalId
    name: Option<String>,
    email: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Token {
    name: String,
    symbol: String,
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    transaction_fee: nervous_system_pb::Tokens,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Proposals {
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    rejection_fee: nervous_system_pb::Tokens,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    initial_voting_period: nervous_system_pb::Duration,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    maximum_wait_for_quiet_deadline_extension: nervous_system_pb::Duration,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Neurons {
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    minimum_creation_stake: nervous_system_pb::Tokens,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Voting {
    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    minimum_dissolve_delay: nervous_system_pb::Duration,

    #[serde(rename = "MaximumVotingPowerBonuses")]
    maximum_voting_power_bonuses: MaximumVotingPowerBonuses,

    #[serde(rename = "RewardRate")]
    reward_rate: RewardRate,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MaximumVotingPowerBonuses {
    #[serde(rename = "DissolveDelay")]
    dissolve_delay: Bonus,

    #[serde(rename = "Age")]
    age: Bonus,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bonus {
    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    duration: nervous_system_pb::Duration,

    #[serde(with = "ic_nervous_system_humanize::serde::percentage")]
    bonus: nervous_system_pb::Percentage,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RewardRate {
    #[serde(with = "ic_nervous_system_humanize::serde::percentage")]
    initial: nervous_system_pb::Percentage,

    #[serde(with = "ic_nervous_system_humanize::serde::percentage")]
    r#final: nervous_system_pb::Percentage,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    transition_duration: nervous_system_pb::Duration,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Distribution {
    #[serde(rename = "Neurons")]
    neurons: Vec<Neuron>,

    #[serde(rename = "InitialBalances")]
    initial_balances: InitialBalances,

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    total: nervous_system_pb::Tokens,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Neuron {
    principal: String, // Principal (alias)

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    stake: nervous_system_pb::Tokens,

    #[serde(default)]
    memo: u64,

    #[serde(with = "ic_nervous_system_humanize::serde::duration")]
    dissolve_delay: nervous_system_pb::Duration,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InitialBalances {
    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    governance: nervous_system_pb::Tokens,

    #[serde(with = "ic_nervous_system_humanize::serde::tokens")]
    swap: nervous_system_pb::Tokens,
}

#[cfg(test)]
mod friendly_tests;
