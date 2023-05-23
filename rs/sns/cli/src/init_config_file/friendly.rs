use std::path::PathBuf;

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SnsConfigurationFile {
    name: String,
    description: String,
    logo: PathBuf,
    url: String,

    #[serde(rename = "Principals")]
    principals: Vec<PrincipalAlias>,

    fallback_controller_principals: Vec<String>,

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
    id: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Token {
    name: String,
    symbol: String,
    transaction_fee: String, // Tokens
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Proposals {
    rejection_fee: String,                             // Tokens
    initial_voting_period: String,                     // Duration
    maximum_wait_for_quiet_deadline_extension: String, // Duration
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Neurons {
    minimum_creation_stake: String, // Tokens
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Voting {
    minimum_dissolve_delay: String, // Duration

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
    duration: String, // Duration
    boost: String,    // Percentage
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RewardRate {
    initial: String,             // Percentage
    r#final: String,             // Percentage
    transition_duration: String, // Duration
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Distribution {
    #[serde(rename = "Neurons")]
    neurons: Vec<Neuron>,

    #[serde(rename = "Balances")]
    balances: Balances,

    total: String, // Tokens
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Neuron {
    principal: String, // Principal (alias)

    stake: String, // Tokens

    #[serde(default)]
    memo: u64,

    dissolve_delay: String, // Duration
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Balances {
    governance: String, // Tokens
    swap: String,       // Tokens
}

#[cfg(test)]
mod friendly_tests;
