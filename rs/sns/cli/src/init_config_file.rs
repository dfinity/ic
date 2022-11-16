use crate::unit_helpers;
use anyhow::anyhow;
use clap::Parser;
use ic_sns_governance::{
    pb::v1::{governance::SnsMetadata, NervousSystemParameters, VotingRewardsParameters},
    types::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS},
};
use ic_sns_init::{
    pb::v1::{sns_init_payload, SnsInitPayload},
    MAX_TOKEN_NAME_LENGTH, MAX_TOKEN_SYMBOL_LENGTH, MIN_TOKEN_NAME_LENGTH, MIN_TOKEN_SYMBOL_LENGTH,
};
use regex::Regex;
use std::{
    convert::TryFrom,
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
    str::FromStr,
};

const DEFAULT_INIT_CONFIG_PATH: &str = "sns_init.yaml";

#[derive(Debug, Parser)]
pub struct InitConfigFileArgs {
    #[clap(long, parse(from_os_str))]
    init_config_file_path: Option<PathBuf>,

    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Debug, Parser)]
enum SubCommand {
    /// Creates a new init config file template. Fields with default values have the default value
    /// assigned. Fields without default values must be filled by the user.
    New,

    /// Validates that a init_config_file is well formed.
    Validate,
}

#[derive(serde::Deserialize, serde::Serialize, Eq, Clone, PartialEq, Debug)]
pub struct SnsLedgerConfig {
    /// Fee of a transaction.
    pub transaction_fee_e8s: Option<u64>,

    /// The name of the token issued by an SNS Ledger.
    pub token_name: Option<String>,

    /// The symbol of the token issued by an SNS Ledger.
    pub token_symbol: Option<String>,
}
#[derive(serde::Deserialize, serde::Serialize, Clone, PartialEq, Debug)]
pub struct SnsGovernanceConfig {
    /// Cost of making a proposal that is rejected.
    pub proposal_reject_cost_e8s: Option<u64>,

    /// The minimum amount of SNS Token e8s an SNS Ledger account must have to stake a neuron.
    pub neuron_minimum_stake_e8s: Option<u64>,

    /// The minimum dissolve_delay in seconds a neuron must have to be able to cast votes on proposals.
    pub neuron_minimum_dissolve_delay_to_vote_seconds: Option<u64>,

    /// The logo for the SNS project represented as a path to the logo file in the local filesystem.
    pub logo: Option<PathBuf>,

    /// The URL to the dapp that is controlled by the SNS project.
    pub url: Option<String>,

    /// The name of the SNS project. This may differ from the name of the associated token.
    pub name: Option<String>,

    /// A description of the SNS project.
    pub description: Option<String>,

    /// The amount of time that the growth rate changes (presumably, decreases)
    /// from the initial growth rate to the final growth rate. (See the two
    /// *_reward_rate_basis_points fields bellow.) The transition is quadratic, and
    /// levels out at the end of the growth rate transition period.
    pub reward_rate_transition_duration_seconds: Option<u64>,

    /// The amount of rewards is proportional to token_supply * current_rate. In
    /// turn, current_rate is somewhere between `initial_reward_rate_percentage`
    /// and `final_reward_rate_percentage`. In the first reward period, it is the
    /// initial growth rate, and after the growth rate transition period has elapsed,
    /// the growth rate becomes the final growth rate, and remains at that value for
    /// the rest of time. The transition between the initial and final growth rates is
    /// quadratic, and levels out at the end of the growth rate transition period.
    ///
    /// (A basis point is one in ten thousand.)
    ///
    /// Note that in the rest of the codebase, the analogous fields are
    /// initial_reward_rate_basis_points and final_reward_rate_basis_points.
    /// In the config file we use percentages instead of basis points to try to
    /// be a bit more user friendly.
    /// For example, on the ic dashbord
    /// <https://dashboard.internetcomputer.org/circulation> we show the reward
    /// rate in terms of percentages instead of basis points.
    pub initial_reward_rate_percentage: Option<f64>,
    pub final_reward_rate_percentage: Option<f64>,

    // The maximum dissolve delay that a neuron can have. That is, the maximum
    // that a neuron's dissolve delay can be increased to. The maximum is also enforced
    // when saturating the dissolve delay bonus in the voting power computation.
    pub max_dissolve_delay_seconds: Option<u64>,

    // The age of a neuron that saturates the age bonus for the voting power computation.
    pub max_neuron_age_seconds_for_age_bonus: Option<u64>,

    // The voting power multiplier of a neuron with a dissolve delay of
    // `max_dissolve_delay_seconds`.
    // For example, a value of 2.0 means a neuron with the max dissolve delay
    // has 100% more voting power than an otherwise-equivalent neuron with the
    // minimum dissolve delay.
    //
    // For no bonus, this should be set to 1.
    //
    // To achieve functionality equivalent to NNS, this should be set to 2.0.
    ///
    /// Note that in the rest of the codebase, the analogous field is
    /// max_dissolve_delay_bonus_percentage.
    /// In the config file we ask the user to specify a multiplier instead
    /// because that is how this field is normally communicated to the users.
    pub max_dissolve_delay_bonus_multiplier: Option<f64>,

    // The voting power multiplier of a neuron whose age is
    // `max_neuron_age_seconds_for_age_bonus` or older.
    // For example, a value of 1.25 means a neuron with max age has 25% more
    // voting power than an otherwise-equivalent neuron with age 0.
    //
    // Analogous to `max_dissolve_delay_bonus_multiplier`.
    // but this one relates to neuron age instead of dissolve delay.
    //
    // To achieve functionality equivalent to NNS, this should be set to 1.25.
    ///
    /// Note that in the rest of the codebase, the analogous field is
    /// max_age_bonus_percentage.
    /// In the config file we ask the user to specify a multiplier instead
    /// because that is how this field is normally communicated to the users.
    pub max_age_bonus_multiplier: Option<f64>,

    /// If the swap fails, control of the dapp canister(s) will be set to these
    /// principal IDs. In most use-cases, this would be the same as the original
    /// set of controller(s).
    pub fallback_controller_principal_ids: Vec<String>,

    // The initial voting period of a newly created proposal.
    // A proposal's voting period may then be further increased during
    // a proposal's lifecycle due to the wait-for-quiet algorithm.
    //
    // The voting period must be between (inclusive) the defined floor
    // INITIAL_VOTING_PERIOD_SECONDS_FLOOR and ceiling
    // INITIAL_VOTING_PERIOD_SECONDS_CEILING.
    pub initial_voting_period_seconds: Option<u64>,

    // The wait for quiet algorithm extends the voting period of a proposal when
    // there is a flip in the majority vote during the proposal's voting period.
    // This parameter determines the maximum time period that the voting period
    // may be extended after a flip. If there is a flip at the very end of the
    // original proposal deadline, the remaining time will be set to this parameter.
    // If there is a flip before or after the original deadline, the deadline will
    // extended by somewhat less than this parameter.
    // The maximum total voting period extension is 2 * wait_for_quiet_deadline_increase_seconds.
    // For more information, see the wiki page on the wait-for-quiet algorithm:
    // https://wiki.internetcomputer.org/wiki/Network_Nervous_System#Proposal_decision_and_wait-for-quiet
    pub wait_for_quiet_deadline_increase_seconds: Option<u64>,
}

#[derive(serde::Deserialize, serde::Serialize, Eq, Clone, PartialEq, Debug)]
pub struct SnsInitialTokenDistributionConfig {
    /// The initial tokens and neurons available at genesis will be distributed according
    /// to the strategy and configuration picked via the initial_token_distribution
    /// parameter.
    pub initial_token_distribution: Option<sns_init_payload::InitialTokenDistribution>,
}

/// The SnsCliInitConfig allows for a more "human-friendly" way of specifying parameters for
/// the SnsInitPayload that make sense for a CLI tool.
///
/// For instance, the SnsInitPayload requires the logo to be a base64
/// encoded String representation of a image file. If directly mapping the config file to
/// the SnsInitPayload, users of the SNS Cli would need to do the encoding by hand and paste
/// it into the init config file. With SnsCliInitConfig, this struct allows for a PathBuf to be specified
/// and will handle converting to the correct type within the Cli tool.
#[derive(serde::Deserialize, serde::Serialize, Clone, PartialEq, Debug)]
pub struct SnsCliInitConfig {
    #[serde(flatten)]
    pub sns_ledger: SnsLedgerConfig,
    #[serde(flatten)]
    pub sns_governance: SnsGovernanceConfig,
    #[serde(flatten)]
    pub initial_token_distribution: SnsInitialTokenDistributionConfig,
}

impl Default for SnsCliInitConfig {
    fn default() -> Self {
        let nervous_system_parameters_default = NervousSystemParameters::with_default_values();
        let voting_rewards_parameters = nervous_system_parameters_default
            .voting_rewards_parameters
            .as_ref()
            .unwrap();

        SnsCliInitConfig {
            sns_ledger: SnsLedgerConfig {
                transaction_fee_e8s: nervous_system_parameters_default.transaction_fee_e8s,
                token_name: None,
                token_symbol: None,
            },
            sns_governance: SnsGovernanceConfig {
                proposal_reject_cost_e8s: nervous_system_parameters_default.reject_cost_e8s,
                neuron_minimum_stake_e8s: nervous_system_parameters_default
                    .neuron_minimum_stake_e8s,
                neuron_minimum_dissolve_delay_to_vote_seconds: nervous_system_parameters_default
                    .neuron_minimum_dissolve_delay_to_vote_seconds,
                fallback_controller_principal_ids: vec![],
                logo: None,
                url: None,
                name: None,
                description: None,

                reward_rate_transition_duration_seconds: voting_rewards_parameters
                    .reward_rate_transition_duration_seconds,
                initial_reward_rate_percentage: voting_rewards_parameters
                    .initial_reward_rate_basis_points
                    .map(unit_helpers::basis_points_to_percentage),
                final_reward_rate_percentage: voting_rewards_parameters
                    .final_reward_rate_basis_points
                    .map(unit_helpers::basis_points_to_percentage),
                max_dissolve_delay_seconds: nervous_system_parameters_default
                    .max_dissolve_delay_seconds,
                max_neuron_age_seconds_for_age_bonus: nervous_system_parameters_default
                    .max_neuron_age_for_age_bonus,
                max_dissolve_delay_bonus_multiplier: nervous_system_parameters_default
                    .max_dissolve_delay_bonus_percentage
                    .map(unit_helpers::percentage_increase_to_multiplier),
                max_age_bonus_multiplier: nervous_system_parameters_default
                    .max_age_bonus_percentage
                    .map(unit_helpers::percentage_increase_to_multiplier),
                initial_voting_period_seconds: nervous_system_parameters_default
                    .initial_voting_period_seconds,
                wait_for_quiet_deadline_increase_seconds: nervous_system_parameters_default
                    .wait_for_quiet_deadline_increase_seconds,
            },
            initial_token_distribution: SnsInitialTokenDistributionConfig {
                initial_token_distribution: None,
            },
        }
    }
}

impl SnsCliInitConfig {
    fn initial_reward_rate_basis_points(&self) -> anyhow::Result<u64> {
        let initial_reward_rate_percentage = self
            .sns_governance
            .initial_reward_rate_percentage
            .ok_or_else(|| anyhow!("initial_reward_rate_percentage must be specified"))?;

        let initial_reward_rate_basis_points =
            unit_helpers::percentage_to_basis_points(initial_reward_rate_percentage);

        if initial_reward_rate_basis_points
            > VotingRewardsParameters::INITIAL_REWARD_RATE_BASIS_POINTS_CEILING
        {
            return Err(anyhow!(
                "Error: initial_reward_rate_percentage must be less than or equal to {}, but it is {initial_reward_rate_percentage}",
                unit_helpers::basis_points_to_percentage(VotingRewardsParameters::INITIAL_REWARD_RATE_BASIS_POINTS_CEILING)
            ));
        }

        Ok(initial_reward_rate_basis_points)
    }

    fn final_reward_rate_basis_points(&self) -> anyhow::Result<u64> {
        let final_reward_rate_percentage = self
            .sns_governance
            .final_reward_rate_percentage
            .ok_or_else(|| anyhow!("final_reward_rate_percentage must be specified"))?;
        let initial_reward_rate_percentage = self
            .sns_governance
            .initial_reward_rate_percentage
            .ok_or_else(|| anyhow!("initial_reward_rate_percentage must be specified"))?;

        if final_reward_rate_percentage > initial_reward_rate_percentage {
            return Err(anyhow!(
                "Error: final_reward_rate_percentage must be less than or equal to initial_reward_rate_percentage, but they are {final_reward_rate_percentage} and {initial_reward_rate_percentage}.",
            ));
        }

        let final_reward_rate_basis_points =
            unit_helpers::percentage_to_basis_points(final_reward_rate_percentage);

        Ok(final_reward_rate_basis_points)
    }

    fn max_dissolve_delay_bonus_percentage(&self) -> anyhow::Result<u64> {
        let max_dissolve_delay_bonus_multiplier = self
            .sns_governance
            .max_dissolve_delay_bonus_multiplier
            .ok_or_else(|| anyhow!("max_dissolve_delay_bonus_multiplier must be specified"))?;

        let max_dissolve_delay_bonus_percentage =
            unit_helpers::multiplier_to_percentage_increase(
                max_dissolve_delay_bonus_multiplier,
            ).ok_or_else(|| {
                anyhow!(
                    "max_dissolve_delay_bonus_multiplier must be greater than or equal to 1.0, but it is {max_dissolve_delay_bonus_multiplier}"
                )
            })?;

        if max_dissolve_delay_bonus_percentage
            > NervousSystemParameters::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING
        {
            return Err(anyhow!(
                "max_dissolve_delay_bonus_multiplier must be less than or equal to {}, but it is {max_dissolve_delay_bonus_multiplier}", 
                unit_helpers::percentage_increase_to_multiplier(NervousSystemParameters::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING)
            ));
        }

        Ok(max_dissolve_delay_bonus_percentage)
    }

    fn max_age_bonus_percentage(&self) -> anyhow::Result<u64> {
        let max_age_bonus_multiplier = self
            .sns_governance
            .max_age_bonus_multiplier
            .ok_or_else(|| anyhow!("max_age_bonus_multiplier must be specified"))?;

        let max_age_bonus_percentage =
        unit_helpers::multiplier_to_percentage_increase(
            max_age_bonus_multiplier,
        ).ok_or_else(|| {
            anyhow!(
                "max_age_bonus_multiplier must be greater than or equal to 1.0, but it is {max_age_bonus_multiplier}"
            )
        })?;

        if max_age_bonus_percentage > NervousSystemParameters::MAX_AGE_BONUS_PERCENTAGE_CEILING {
            return Err(anyhow!(
                "max_age_bonus_multiplier must be less than or equal to {}, but it is {}",
                max_age_bonus_multiplier,
                unit_helpers::percentage_increase_to_multiplier(
                    NervousSystemParameters::MAX_AGE_BONUS_PERCENTAGE_CEILING
                )
            ));
        }

        Ok(max_age_bonus_percentage)
    }

    /// A SnsCliInitConfig is valid if it can convert to an SnsInitPayload and have the generated
    /// struct pass its validation.
    fn validate(&self) -> anyhow::Result<()> {
        let sns_init_payload = SnsInitPayload::try_from(self.clone())?;
        sns_init_payload.validate()?;
        Ok(())
    }
}

/// Generates a logo data URL from a file.
fn load_logo(logo_path: &PathBuf) -> Result<String, anyhow::Error> {
    // Extensions and their corresponding mime types:
    let supported_formats = [("png", "image/png")];
    // In error messages we provide the list of supported file extensions:
    let supported_extensions = || -> String {
        supported_formats
            .iter()
            .map(|extension| extension.0)
            .collect::<Vec<&str>>()
            .join(", ")
    };
    // Deduce the mime type from the extension:
    let extension = logo_path
        .extension()
        .and_then(|extension| extension.to_str());
    let mime_type = match extension {
        Some(extension) => supported_formats
            .iter()
            .find_map(|(item_extension, suffix)| {
                if *item_extension == extension {
                    Some(suffix)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                anyhow!(
                    "Unsupported logo type ({:?}) not in: {}",
                    extension,
                    supported_extensions()
                )
            }),
        None => Err(anyhow!(
            "Logo file has no extension.  Supported extensions: {}",
            supported_extensions()
        )),
    }?;

    // Data prefix
    let mut buffer: Vec<u8> = format!("data:{};base64,", mime_type).into_bytes();

    // The image is base 64 encoded:
    {
        let mut writer = base64::write::EncoderWriter::new(&mut buffer, base64::STANDARD);
        let file = match File::open(&logo_path) {
            Ok(file) => file,
            Err(err) => {
                return Err(anyhow!(
                    "Couldn't open the logo file ({:?}): {}",
                    logo_path,
                    err
                ))
            }
        };

        let mut reader = BufReader::new(file);

        std::io::copy(&mut reader, &mut writer)?;
    }
    let data_url: String = std::str::from_utf8(&buffer)
        .expect("This should be impossible")
        .to_owned();
    Ok(data_url)
}

impl TryFrom<SnsCliInitConfig> for SnsInitPayload {
    type Error = anyhow::Error;

    fn try_from(sns_cli_init_config: SnsCliInitConfig) -> Result<Self, Self::Error> {
        let optional_logo = match sns_cli_init_config.sns_governance.logo {
            None => None,
            Some(ref logo_path) => Some(load_logo(logo_path)?),
        };

        let max_dissolve_delay_bonus_percentage =
            sns_cli_init_config.max_dissolve_delay_bonus_percentage()?;
        let max_age_bonus_percentage = sns_cli_init_config.max_age_bonus_percentage()?;
        let initial_reward_rate_basis_points =
            sns_cli_init_config.initial_reward_rate_basis_points()?;
        let final_reward_rate_basis_points =
            sns_cli_init_config.final_reward_rate_basis_points()?;

        Ok(SnsInitPayload {
            sns_initialization_parameters: Some(get_config_file_contents(
                sns_cli_init_config.clone(),
            )),
            transaction_fee_e8s: sns_cli_init_config.sns_ledger.transaction_fee_e8s,
            token_name: sns_cli_init_config.sns_ledger.token_name,
            token_symbol: sns_cli_init_config.sns_ledger.token_symbol,
            proposal_reject_cost_e8s: sns_cli_init_config.sns_governance.proposal_reject_cost_e8s,
            neuron_minimum_stake_e8s: sns_cli_init_config.sns_governance.neuron_minimum_stake_e8s,
            neuron_minimum_dissolve_delay_to_vote_seconds: sns_cli_init_config
                .sns_governance
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            fallback_controller_principal_ids: sns_cli_init_config
                .sns_governance
                .fallback_controller_principal_ids,
            logo: optional_logo,
            url: sns_cli_init_config.sns_governance.url,
            name: sns_cli_init_config.sns_governance.name,
            description: sns_cli_init_config.sns_governance.description,
            initial_token_distribution: sns_cli_init_config
                .initial_token_distribution
                .initial_token_distribution,
            initial_reward_rate_basis_points: Some(initial_reward_rate_basis_points),
            final_reward_rate_basis_points: Some(final_reward_rate_basis_points),
            reward_rate_transition_duration_seconds: sns_cli_init_config
                .sns_governance
                .reward_rate_transition_duration_seconds,
            max_dissolve_delay_seconds: sns_cli_init_config
                .sns_governance
                .max_dissolve_delay_seconds,
            max_neuron_age_seconds_for_age_bonus: sns_cli_init_config
                .sns_governance
                .max_neuron_age_seconds_for_age_bonus,
            max_dissolve_delay_bonus_percentage: Some(max_dissolve_delay_bonus_percentage),
            max_age_bonus_percentage: Some(max_age_bonus_percentage),
            initial_voting_period_seconds: sns_cli_init_config
                .sns_governance
                .initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: sns_cli_init_config
                .sns_governance
                .wait_for_quiet_deadline_increase_seconds,
        })
    }
}

pub fn exec(init_config_file_args: InitConfigFileArgs) {
    let init_config_file_path = init_config_file_args
        .init_config_file_path
        .unwrap_or_else(|| PathBuf::from_str(DEFAULT_INIT_CONFIG_PATH).unwrap());
    match init_config_file_args.sub_command {
        SubCommand::New => new(init_config_file_path),
        SubCommand::Validate => validate(init_config_file_path),
    }
}

fn new(init_config_file_path: PathBuf) {
    let default_sns_cli_init_config = SnsCliInitConfig::default();
    let config_file_string = get_config_file_contents(default_sns_cli_init_config);
    let f = File::create(init_config_file_path).expect("Unable to open file");
    let mut f = BufWriter::new(f);
    f.write_all(config_file_string.as_bytes())
        .expect("Unable to write init config file");
}

pub fn get_config_file_contents(sns_cli_init_config: SnsCliInitConfig) -> String {
    let default_config = SnsCliInitConfig::default();
    let yaml_payload = serde_yaml::to_string(&sns_cli_init_config)
        .expect("Error when converting sns_cli_init_config to yaml");

    let mut yaml_file_string = String::new();
    // Comment on top of each field.
    let field_comment: Vec<(Regex, String)> = vec![
        (
            Regex::new(r"transaction_fee_e8s.*").unwrap(),
            format!(
                r##"#
# SNS LEDGER
#
# Fee of a ledger transaction.
# Default value = {}
#"##,
                default_config.sns_ledger.transaction_fee_e8s.unwrap()
            ),
        ),
        (
            Regex::new(r"proposal_reject_cost_e8s.*").unwrap(),
            format!(
                r##"#
#
# SNS GOVERNANCE
#
# The cost of making a proposal that is not adopted in e8s.
# Default value = {}
#"##,
                default_config
                    .sns_governance
                    .proposal_reject_cost_e8s
                    .unwrap()
            ),
        ),
        (
            Regex::new(r"token_name.*").unwrap(),
            format!(
                r##"#
# The name of the token issued by the SNS ledger.
# This field has no default, a value must be provided by the user.
# Must be a string with a length between {} and {} characters.
#
# Example: InternetComputerProtocol
#"##,
                MIN_TOKEN_NAME_LENGTH, MAX_TOKEN_NAME_LENGTH
            ),
        ),
        (
            Regex::new(r"initial_token_distribution.*").unwrap(),
            r##"#
#
# SNS INITIAL TOKEN DISTRIBUTION
#
# This field sets the initial token distribution. Initially, there is only support for
# the FractionalDeveloperVotingPower strategy. This strategy configures how SNS tokens and neurons
# are distributed in four "buckets": developer tokens that are given to the original developers of
# the dapp, airdrop tokens that can be given to any other principals that should have tokens at
# genesis, treasury tokens that are owned by the SNS governance canister, and sale tokens which
# are sold in an initial decentralization sale but parts of which can also be reserved for future
# sales.
# All developer and airdrop tokens are distributed to the defined principals at genesis in a basket
# of neurons called the developer neurons and the airdrop neurons, respectively.
# If only parts of the sale tokens are sold in the initial decentralization sale, the developer
# neurons are restricted by a voting power multiplier. This voting power multiplier is calculated as
# `swap_distribution.initial_swap_amount_e8s / swap_distribution.total_e8s`.

# As more of the swap funds are swapped in future rounds, the voting power
# multiplier will approach 1.0.
# The initial token distribution must satisfy the following preconditions to be valid:
#    - developer_distribution.developer_neurons.stake_e8s.sum <= u64:MAX
#    - developer_neurons.developer_neurons.stake_e8s.sum <= swap_distribution.total_e8s
#    - airdrop_distribution.airdrop_neurons.stake_e8s.sum <= u64:MAX
#    - swap_distribution.initial_swap_amount_e8s > 0
#    - swap_distribution.initial_swap_amount_e8s <= swap_distribution.total_e8s
#    - swap_distribution.total_e8s >= developer_distribution.developer_neurons.stake_e8s.sum
#
# - developer_distribution has one field:
#    - developer_neurons: A list of NeuronDistributions that specify the neuron's stake,
#      controlling principal, a unique memo, and dissolve delay. These neurons will be
#      available at genesis in PreInitializationSwap mode. The voting power multiplier
#      is applied to these neurons.
#
# - treasury_distribution has one field:
#    - total_e8s: The total amount of tokens in the treasury bucket.
#
# - swap_distribution has two fields:
#    - total_e8s: The total amount of tokens in the sale bucket. initial_swap_amount_e8s will be
#      deducted from this total.
#    - initial_swap_amount_e8s: The initial amount of tokens deposited in the sale canister for
#      the initial token sale.
#
# - airdrop_distribution has one field:
#    - airdrop_neurons: A list of NeuronDistributions that specify the neuron's stake and
#      controlling principal. These neurons will be available at genesis in PreInitializationSwap
#      mode. No voting power multiplier is applied to these neurons.
#
# Example:
# initial_token_distribution:
#   FractionalDeveloperVotingPower:
#     developer_distribution:
#       developer_neurons:
#         - controller: x4vjn-rrapj-c2kqe-a6m2b-7pzdl-ntmc4-riutz-5bylw-2q2bh-ds5h2-lae
#           stake_e8s: 1500000000
#           memo: 0
#           dissolve_delay_seconds: 15780000 # 6 months
#         - controller: fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe
#           stake_e8s: 1500000000
#           memo: 1
#           dissolve_delay_seconds: 31560000 # 1 year
#     treasury_distribution:
#       total_e8s: 5000000000
#     swap_distribution:
#       total_e8s: 6000000000
#       initial_swap_amount_e8s: 3000000000
#     airdrop_distribution:
#       airdrop_neurons:
#         - controller: fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe
#           stake_e8s: 500000000
#           memo: 0
#           dissolve_delay_seconds: 15780000 # 6 months
#"##
            .to_string(),
        ),
        (
            Regex::new(r"token_symbol.*").unwrap(),
            format!(
                r##"#
# The symbol of the token issued by the SNS Ledger.
# This field has no default, a value must be provided by the user.
# Must be a string with a length between {} and {} characters.
#
# Example: ICP
#"##,
                MIN_TOKEN_SYMBOL_LENGTH, MAX_TOKEN_SYMBOL_LENGTH
            ),
        ),
        (
            Regex::new(r"neuron_minimum_stake_e8s*").unwrap(),
            format!(
                r##"#
# The minimum amount of SNS Token e8s an SNS Ledger account must have to stake a neuron.
# Default value = {}
#"##,
                default_config
                    .sns_governance
                    .neuron_minimum_stake_e8s
                    .unwrap(),
            ),
        ),
        (
            Regex::new(r"neuron_minimum_dissolve_delay_to_vote_seconds*").unwrap(),
            format!(
                r##"#
# The minimum dissolve_delay in seconds a neuron must have to be able to cast votes on proposals.
# Default value = {}
#"##,
                default_config
                    .sns_governance
                    .neuron_minimum_dissolve_delay_to_vote_seconds
                    .unwrap(),
            ),
        ),
        (
            Regex::new(r"fallback_controller_principal_ids.*").unwrap(),
            r##"#
# If the decentralization sale fails, control of the dapp canister(s) is set to these
# principal IDs. In most use cases, this is set to the original set of controller(s) of the dapp.
# This field has no default, a value must be provided by the user.
#"##
            .to_string(),
        ),
        (
            Regex::new(r"logo.*").unwrap(),
            format!(
                r##"#
# Path to the SNS Project logo on the local filesystem. The path is relative
# to the running sns binary, so an absolute path to the logo file is recommended.
# Must have less than {} characters, roughly 256Kb.
#"##,
                SnsMetadata::MAX_LOGO_LENGTH
            ),
        ),
        (
            Regex::new(r"url.*").unwrap(),
            format!(
                r##"#
# Url to the dapp controlled by the SNS project.
# Must be a string of max length = {}.
#"##,
                SnsMetadata::MAX_URL_LENGTH
            ),
        ),
        (
            Regex::new(r"name.*").unwrap(),
            format!(
                r##"#
# Name of the SNS project. This may differ from the name of the associated token name.
# Must be a string of max length = {}.
#"##,
                SnsMetadata::MAX_NAME_LENGTH
            ),
        ),
        (
            Regex::new(r"description.*").unwrap(),
            format!(
                r##"#
# Description of the SNS project.
# Must be a string of max length = {}.
#"##,
                SnsMetadata::MAX_DESCRIPTION_LENGTH
            ),
        ),
        (
            Regex::new(r"initial_reward_rate_percentage[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# The voting reward rate controls how quickly the supply of the SNS token 
# increases. For example, an initial_reward_rate_percentage of `2.0` will cause 
# the supply to increase by at most 2% each year. A higher voting reward rate 
# incentivizes people to participate in governance, but also results in higher 
# inflation. 
#
# An initial and a final reward rate can be set, to have a higher reward rate at
# the launch of the SNS, and a lower rate farther into the SNS’s lifetime. The 
# reward rate falls quadratically from the initial rate to the final rate over 
# the course of `reward_rate_transition_duration_seconds`.
#
# Setting both `initial_reward_rate_percentage` and `final_reward_rate_percentage`
# to 0 will result in the system not distributing voting rewards at all. 
#
# The default value for initial_reward_rate_percentage is {}. The value used 
# by the NNS is 10%.
# The default value for final_reward_rate_percentage is {}. The value used by 
# the NNS is 5%.
#
# These values correspond to
# `NervousSystemParameters::initial_reward_rate_basis points` and 
# `NervousSystemParameters::final_reward_rate_basis points` in the SNS.
#"##,
                default_config
                    .sns_governance
                    .initial_reward_rate_percentage
                    .unwrap(),
                default_config
                    .sns_governance
                    .final_reward_rate_percentage
                    .unwrap(),
            ),
        ),
        (
            Regex::new(r"reward_rate_transition_duration_seconds[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# The voting reward rate falls quadratically from 
# `initial_reward_rate_basis_points` to `final_reward_rate_basis_points` over 
# the time period defined by `reward_rate_transition_duration_seconds`. 
#
# The default value is {}. Values of 0 result in the reward rate always being
# `final_reward_rate_basis_points`. The value used by the NNS is 8 years, or 
# {} seconds. (The value cannot be set to 0.)
#
#"##,
                default_config
                    .sns_governance
                    .reward_rate_transition_duration_seconds
                    .unwrap(),
                8 * ONE_YEAR_SECONDS
            ),
        ),
        (
            Regex::new(r"max_dissolve_delay_seconds[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# The maximum dissolve delay that a neuron can have. 
#
# The default value is {} seconds ({} months). 
#"##,
                default_config
                    .sns_governance
                    .max_dissolve_delay_seconds
                    .unwrap(),
                default_config
                    .sns_governance
                    .max_dissolve_delay_seconds
                    .unwrap()
                    / ONE_MONTH_SECONDS
            ),
        ),
        (
            Regex::new(r"max_neuron_age_seconds_for_age_bonus[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# It is possible to give a higher voting weight to older neurons by setting 
# `max_age_bonus_multiplier` to a value greater than 1. This parameter, 
# `max_neuron_age_seconds_for_age_bonus`, sets the age at which the maximum bonus will 
# be given. All older neurons will be treated as if they are this age. The unit 
# is seconds. 
#
# The default value is {} seconds ({} months).
#"##,
                default_config
                    .sns_governance
                    .max_neuron_age_seconds_for_age_bonus
                    .unwrap(),
                default_config
                    .sns_governance
                    .max_neuron_age_seconds_for_age_bonus
                    .unwrap()
                    / ONE_MONTH_SECONDS
            ),
        ),
        (
            Regex::new(r"max_dissolve_delay_bonus_multiplier[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# Users with a higher dissolve delay are incentivized to take the long-term 
# interests of the SNS into consideration when voting. To reward this long time 
# commitment, this parameter can be set to a value larger than zero, which will 
# result in neurons having their voting weight increased in proportion to their 
# dissolve delay. 
#
# If neurons’ dissolve delay is set to `max_dissolve_delay_seconds`, their 
# voting weight will be multiplied by `max_dissolve_delay_bonus_multiplier`. 
#
# The default value is {}. The value the NNS uses is 2. A value of 1 results in
# no change in voting weight for neurons with higher dissolve delays. 
# Values below 1 are prohibited.
#
# This value corresponds to
# `NervousSystemParameters::max_dissolve_delay_bonus_percentage` in the SNS.
#"##,
                default_config
                    .sns_governance
                    .max_dissolve_delay_bonus_multiplier
                    .unwrap(),
            ),
        ),
        (
            Regex::new(r"max_age_bonus_multiplier[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# This is analogous to `max_dissolve_delay_bonus_multiplier`, but controls the 
# additional voting weight given to neurons with more age.
#
# If neurons' age is `max_neuron_age_seconds_for_age_bonus` or older, their 
# voting weight will be multiplied by `max_age_bonus_multiplier`. 
#
# The default value is {}. The value the NNS uses is 1.25. A value of 1 results 
# in no change in voting weight for neurons with higher age. 
# Values below 1 are prohibited.
#
# This value corresponds to
# `NervousSystemParameters::max_age_bonus_percentage` in the SNS.
#"##,
                default_config
                    .sns_governance
                    .max_age_bonus_multiplier
                    .unwrap(),
            ),
        ),
        (
            Regex::new(r"initial_voting_period_seconds[^A-Za-z]*").unwrap(),
            format!(
                r##"#
# The initial voting period in seconds of a newly created proposal.
# (A proposal's voting period may be increased during a proposal's lifecycle due
# to the wait-for-quiet algorithm.)
# 
# The default value is {} seconds ({} days).
#"##,
                default_config
                    .sns_governance
                    .initial_voting_period_seconds
                    .unwrap(),
                default_config
                    .sns_governance
                    .initial_voting_period_seconds
                    .unwrap()
                    / ONE_DAY_SECONDS,
            ),
        ),
        (
            Regex::new(r"wait_for_quiet_deadline_increase_seconds[^A-Za-z]*").unwrap(),
            {
                let wait_for_quiet_deadline_increase_seconds = default_config
                    .sns_governance
                    .wait_for_quiet_deadline_increase_seconds
                    .unwrap();
                format!(
                    r##"#
# The wait for quiet algorithm extends the voting period of a proposal when
# there is a flip in the majority vote during the proposal's voting period.
#
# Without this, there could be an incentive to vote right at the end of a 
# proposal's voting period, in order to reduce the chance that people will see 
# the result and vote against. 
# 
# If this value is set to 86400 seconds (1 day), a change in the majority vote 
# during at the end of a proposal's original voting period the voting period 
# being extended by an additional day. Another change at the end of the extended
# period will cause the voting period to be extended by half a day, and so on.
#
# The total extension to the voting period will never be more than twice this 
# value.
#
# For more information, see the wiki page on the wait-for-quiet algorithm: 
# https://wiki.internetcomputer.org/wiki/Network_Nervous_System#Proposal_decision_and_wait-for-quiet
#
# The default value is {} seconds ({} day{}).
#"##,
                    wait_for_quiet_deadline_increase_seconds,
                    wait_for_quiet_deadline_increase_seconds / ONE_DAY_SECONDS,
                    if wait_for_quiet_deadline_increase_seconds / ONE_DAY_SECONDS == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            },
        ),
    ];

    for (i, line) in yaml_payload.lines().enumerate() {
        if i == 1 {
            yaml_file_string.push_str("# It holds that 100000000 e8s = 1 SNS token.\n#\n")
        }
        for (re, comment) in field_comment.iter() {
            if re.is_match(line) {
                yaml_file_string.push_str(format!("{}\n", comment).as_str());
                break;
            }
        }
        yaml_file_string.push_str(format!("{}\n", line).as_str());
    }
    yaml_file_string
}

fn validate(init_config_file: PathBuf) {
    let file = File::open(&init_config_file).unwrap_or_else(|_| {
        eprintln!(
            "Couldn't open {} for validation",
            init_config_file.to_str().unwrap()
        );
        std::process::exit(1);
    });
    let sns_cli_init_config: SnsCliInitConfig = serde_yaml::from_reader(file).unwrap_or_else(|e| {
        eprintln!(
            "Couldn't parse {} for validation: {}",
            init_config_file.to_str().unwrap(),
            e
        );
        std::process::exit(1);
    });
    match sns_cli_init_config.validate() {
        Ok(_) => println!("No errors found {}", init_config_file.to_str().unwrap()),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_sns_governance::types::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS};
    use ic_sns_init::pb::v1::sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower as FDVP;
    use ic_sns_init::pb::v1::{FractionalDeveloperVotingPower, SnsInitPayload};
    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::{BufReader, Read};

    impl SnsLedgerConfig {
        pub fn with_test_values() -> Self {
            let mut logo_path =
                std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
            logo_path.push("test.png");

            Self {
                transaction_fee_e8s: Some(1),
                token_name: Some("ServiceNervousSystem".to_string()),
                token_symbol: Some("SNS".to_string()),
            }
        }
    }

    impl SnsGovernanceConfig {
        pub fn with_test_values() -> Self {
            let mut logo_path =
                std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
            logo_path.push("test.png");

            Self {
                proposal_reject_cost_e8s: Some(2),
                neuron_minimum_stake_e8s: Some(3),
                neuron_minimum_dissolve_delay_to_vote_seconds: Some(6 * ONE_MONTH_SECONDS),
                fallback_controller_principal_ids: vec![
                    "fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe".to_string(),
                ],
                logo: Some(logo_path.clone()),
                url: Some("https://internetcomputer.org".to_string()),
                name: Some("Name".to_string()),
                description: Some("Description".to_string()),
                initial_reward_rate_percentage: Some(31.0),
                final_reward_rate_percentage: Some(27.0),
                reward_rate_transition_duration_seconds: Some(100_000),
                max_dissolve_delay_seconds: Some(8 * ONE_MONTH_SECONDS),
                max_neuron_age_seconds_for_age_bonus: Some(11 * ONE_MONTH_SECONDS),
                max_dissolve_delay_bonus_multiplier: Some(
                    unit_helpers::percentage_increase_to_multiplier(
                        NervousSystemParameters::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING,
                    ),
                ),
                max_age_bonus_multiplier: Some(unit_helpers::percentage_increase_to_multiplier(
                    NervousSystemParameters::MAX_AGE_BONUS_PERCENTAGE_CEILING,
                )),
                initial_voting_period_seconds: Some(ONE_MONTH_SECONDS),
                wait_for_quiet_deadline_increase_seconds: Some(ONE_DAY_SECONDS),
            }
        }
    }

    impl SnsInitialTokenDistributionConfig {
        pub fn with_test_values() -> Self {
            let mut logo_path =
                std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
            logo_path.push("test.png");

            Self {
                initial_token_distribution: Some(FDVP(FractionalDeveloperVotingPower {
                    ..Default::default()
                })),
            }
        }
    }

    impl SnsCliInitConfig {
        pub fn with_test_values() -> Self {
            let mut logo_path =
                std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
            logo_path.push("test.png");

            Self {
                sns_ledger: SnsLedgerConfig::with_test_values(),
                sns_governance: SnsGovernanceConfig::with_test_values(),
                initial_token_distribution: SnsInitialTokenDistributionConfig::with_test_values(),
            }
        }
    }

    /// Tests that the text produced by the "new" command can be read into the default SnsCliInitConfig
    #[test]
    fn test_default_init_config_file() {
        assert_eq!(
            SnsCliInitConfig::default(),
            serde_yaml::from_str(&get_config_file_contents(SnsCliInitConfig::default())).unwrap()
        )
    }

    /// Test reading a valid and an invalid yaml file.
    #[test]
    fn test_read_yaml_file() {
        let mut logo_path = std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        logo_path.push("test.png");
        let file_contents = format!(
            r#"
---
transaction_fee_e8s: 10000
token_name: Bitcoin
token_symbol: BTC
proposal_reject_cost_e8s: 100000000
neuron_minimum_stake_e8s: 100000000
neuron_minimum_dissolve_delay_to_vote_seconds: 15780000
initial_token_distribution:
  FractionalDeveloperVotingPower:
    developer_distribution:
      developer_neurons:
        - controller: x4vjn-rrapj-c2kqe-a6m2b-7pzdl-ntmc4-riutz-5bylw-2q2bh-ds5h2-lae
          stake_e8s: 1500000000
          memo: 0
          dissolve_delay_seconds: 15780000
    treasury_distribution:
      total_e8s: 5000000000
    swap_distribution:
      total_e8s: 6000000000
      initial_swap_amount_e8s: 3000000000
    airdrop_distribution:
      airdrop_neurons:
        - controller: fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe
          stake_e8s: 500000000
          memo: 0
          dissolve_delay_seconds: 15780000

fallback_controller_principal_ids: [fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe]
logo: {}
description: Launching an SNS
name: ServiceNervousSystemTest
url: https://internetcomputer.org/
initial_reward_rate_percentage: 100
final_reward_rate_percentage: 100
reward_rate_transition_duration_seconds: 100
max_dissolve_delay_seconds: 100000000
max_neuron_age_seconds_for_age_bonus: 18
max_dissolve_delay_bonus_multiplier: 1.9
max_age_bonus_multiplier: 1.3
initial_voting_period_seconds: 86400
wait_for_quiet_deadline_increase_seconds: 1000
        "#,
            logo_path.clone().into_os_string().into_string().unwrap()
        );
        let resulting_payload: SnsCliInitConfig = serde_yaml::from_str(&file_contents).unwrap();
        resulting_payload.validate().unwrap();

        let sns_init_payload = SnsInitPayload::try_from(resulting_payload.clone())
            .expect("Expected to be able to convert");
        assert_eq!(
            serde_yaml::from_str::<SnsCliInitConfig>(
                &sns_init_payload.sns_initialization_parameters.unwrap()
            )
            .unwrap(),
            resulting_payload
        );

        // We add a string repeating the field "name", this should fail
        let mut file_contents = file_contents;
        file_contents.push_str("\nname: ServiceNervousSystemTest");
        assert!(serde_yaml::from_str::<SnsCliInitConfig>(&file_contents).is_err());
    }

    #[test]
    fn test_try_from_sns_cli_init_config() {
        let sns_cli_init_config = SnsCliInitConfig::with_test_values();
        let try_from_result = SnsInitPayload::try_from(sns_cli_init_config.clone());

        let sns_init_payload = match try_from_result {
            Ok(sns_init_payload) => sns_init_payload,
            Err(reason) => panic!(
                "Could not convert SnsCliInitConfig to SnsInitPayload: {}",
                reason
            ),
        };

        let SnsInitPayload {
            transaction_fee_e8s,
            token_name,
            token_symbol,
            proposal_reject_cost_e8s,
            neuron_minimum_stake_e8s,
            fallback_controller_principal_ids,
            logo,
            url,
            name,
            description,
            neuron_minimum_dissolve_delay_to_vote_seconds,
            sns_initialization_parameters,
            initial_reward_rate_basis_points,
            final_reward_rate_basis_points,
            reward_rate_transition_duration_seconds,
            max_dissolve_delay_seconds,
            max_neuron_age_seconds_for_age_bonus,
            max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage,
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            initial_token_distribution,
        } = sns_init_payload;

        assert_eq!(
            get_config_file_contents(sns_cli_init_config.clone()),
            sns_initialization_parameters.unwrap()
        );
        assert_eq!(
            sns_cli_init_config.sns_ledger.transaction_fee_e8s,
            transaction_fee_e8s
        );
        assert_eq!(sns_cli_init_config.sns_ledger.token_name, token_name);
        assert_eq!(sns_cli_init_config.sns_ledger.token_symbol, token_symbol);
        assert_eq!(
            sns_cli_init_config.sns_governance.proposal_reject_cost_e8s,
            proposal_reject_cost_e8s
        );
        assert_eq!(
            sns_cli_init_config.sns_governance.neuron_minimum_stake_e8s,
            neuron_minimum_stake_e8s
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            neuron_minimum_dissolve_delay_to_vote_seconds
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .fallback_controller_principal_ids,
            fallback_controller_principal_ids
        );
        assert_eq!(sns_cli_init_config.sns_governance.url, url);
        assert_eq!(sns_cli_init_config.sns_governance.description, description);
        assert_eq!(
            sns_cli_init_config
                .initial_token_distribution
                .initial_token_distribution,
            initial_token_distribution
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .initial_reward_rate_percentage
                .map(|v| (v * 100.0) as u64),
            initial_reward_rate_basis_points
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .final_reward_rate_percentage
                .map(|v| (v * 100.0) as u64),
            final_reward_rate_basis_points
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .reward_rate_transition_duration_seconds,
            reward_rate_transition_duration_seconds
        );
        assert_eq!(sns_cli_init_config.sns_governance.name, name);
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .max_dissolve_delay_seconds,
            max_dissolve_delay_seconds
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .max_neuron_age_seconds_for_age_bonus,
            max_neuron_age_seconds_for_age_bonus
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .max_dissolve_delay_bonus_multiplier
                .map(|v| ((v - 1.0) * 100.0) as u64),
            max_dissolve_delay_bonus_percentage
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .max_age_bonus_multiplier
                .map(|v| ((v - 1.0) * 100.0) as u64),
            max_age_bonus_percentage
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .initial_voting_period_seconds,
            initial_voting_period_seconds
        );
        assert_eq!(
            sns_cli_init_config
                .sns_governance
                .wait_for_quiet_deadline_increase_seconds,
            wait_for_quiet_deadline_increase_seconds
        );

        // Read the test.png file into memory
        let logo_path = sns_cli_init_config.sns_governance.logo.unwrap();

        let file = File::open(&logo_path).unwrap();
        let mut reader = BufReader::new(file);
        let mut buffer: Vec<u8> = vec![];
        reader.read_to_end(&mut buffer).unwrap();
        let encoded_logo = "data:image/png;base64,".to_owned() + &base64::encode(&buffer);

        assert_eq!(Some(encoded_logo), logo);
    }

    #[test]
    fn test_try_from_sns_cli_init_without_logo() {
        let mut sns_cli_init_config = SnsCliInitConfig::with_test_values();

        // Set the logo to None to indicate the developer hasn't provided it
        sns_cli_init_config.sns_governance.logo = None;

        let try_from_result = SnsInitPayload::try_from(sns_cli_init_config);

        let sns_init_payload = match try_from_result {
            Ok(sns_init_payload) => sns_init_payload,
            Err(reason) => panic!(
                "Could not convert SnsCliInitConfig to SnsInitPayload: {}",
                reason
            ),
        };

        assert!(sns_init_payload.logo.is_none(), "Expected logo to be None");
    }

    #[test]
    fn test_initial_reward_rate_percentage_validation() {
        let sns_cli_init_config = SnsCliInitConfig {
            sns_governance: SnsGovernanceConfig {
                initial_reward_rate_percentage: Some(
                    unit_helpers::basis_points_to_percentage(
                        VotingRewardsParameters::INITIAL_REWARD_RATE_BASIS_POINTS_CEILING,
                    ) + 1.0,
                ),
                ..SnsGovernanceConfig::with_test_values()
            },
            ..SnsCliInitConfig::with_test_values()
        };

        assert!(sns_cli_init_config
            .initial_reward_rate_basis_points()
            .is_err());
        assert!(SnsInitPayload::try_from(sns_cli_init_config).is_err());
    }

    #[test]
    fn final_initial_reward_rate_percentage_validation() {
        let sns_cli_init_config = SnsCliInitConfig {
            sns_governance: SnsGovernanceConfig {
                // Final must be <= initial, so this should cause a panic
                initial_reward_rate_percentage: Some(0.0),
                final_reward_rate_percentage: Some(1.0),
                ..SnsGovernanceConfig::with_test_values()
            },
            ..SnsCliInitConfig::with_test_values()
        };

        assert!(sns_cli_init_config
            .final_reward_rate_basis_points()
            .is_err());
        assert!(SnsInitPayload::try_from(sns_cli_init_config).is_err());
    }

    #[test]
    fn max_dissolve_delay_bonus_multiplier_validation() {
        let sns_cli_init_config = SnsCliInitConfig {
            sns_governance: SnsGovernanceConfig {
                max_dissolve_delay_bonus_multiplier: Some(
                    unit_helpers::percentage_increase_to_multiplier(
                        NervousSystemParameters::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING,
                    ) + 1.0,
                ),
                ..SnsGovernanceConfig::with_test_values()
            },
            ..SnsCliInitConfig::with_test_values()
        };

        assert!(sns_cli_init_config
            .max_dissolve_delay_bonus_percentage()
            .is_err());
        assert!(SnsInitPayload::try_from(sns_cli_init_config).is_err());
    }

    #[test]
    fn max_age_bonus_multiplier_validation() {
        let sns_cli_init_config = SnsCliInitConfig {
            sns_governance: SnsGovernanceConfig {
                max_age_bonus_multiplier: Some(
                    unit_helpers::percentage_increase_to_multiplier(
                        NervousSystemParameters::MAX_AGE_BONUS_PERCENTAGE_CEILING,
                    ) + 1.0,
                ),
                ..SnsGovernanceConfig::with_test_values()
            },
            ..SnsCliInitConfig::with_test_values()
        };

        assert!(sns_cli_init_config.max_age_bonus_percentage().is_err());
        assert!(SnsInitPayload::try_from(sns_cli_init_config).is_err());
    }
}
