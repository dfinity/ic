use crate::unit_helpers;
use anyhow::anyhow;
use clap::Parser;
use ic_sns_governance::pb::v1::{governance::SnsMetadata, NervousSystemParameters};
use ic_sns_init::{
    pb::v1::{sns_init_payload::InitialTokenDistribution, SnsInitPayload},
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
    /// Fee of a transaction.
    pub transaction_fee_e8s: Option<u64>,

    /// The name of the token issued by an SNS Ledger.
    pub token_name: Option<String>,

    /// The symbol of the token issued by an SNS Ledger.
    pub token_symbol: Option<String>,

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

    /// The amount of rewards is proportional to token_supply * current_rate. In
    /// turn, current_rate is somewhere between `initial_reward_rate_percentage`
    /// and `final_reward_rate_percentage`. In the first reward period, it is the
    /// initial growth rate, and after the growth rate transition period has elapsed,
    /// the growth rate becomes the final growth rate, and remains at that value for
    /// the rest of time. The transition between the initial and final growth rates is
    /// quadratic, and levels out at the end of the growth rate transition period.
    ///
    /// (A basis point is one in ten thousand.)
    pub initial_reward_rate_percentage: Option<f64>,
    pub final_reward_rate_percentage: Option<f64>,

    /// If the swap fails, control of the dapp canister(s) will be set to these
    /// principal IDs. In most use-cases, this would be the same as the original
    /// set of controller(s).
    pub fallback_controller_principal_ids: Vec<String>,

    /// The initial tokens and neurons available at genesis will be distributed according
    /// to the strategy and configuration picked via the initial_token_distribution
    /// parameter.
    pub initial_token_distribution: Option<InitialTokenDistribution>,
}

impl Default for SnsCliInitConfig {
    fn default() -> Self {
        let nervous_system_parameters_default = NervousSystemParameters::with_default_values();
        let voting_rewards_parameters = nervous_system_parameters_default
            .voting_rewards_parameters
            .as_ref()
            .unwrap();

        SnsCliInitConfig {
            transaction_fee_e8s: nervous_system_parameters_default.transaction_fee_e8s,
            token_name: None,
            token_symbol: None,
            proposal_reject_cost_e8s: nervous_system_parameters_default.reject_cost_e8s,
            neuron_minimum_stake_e8s: nervous_system_parameters_default.neuron_minimum_stake_e8s,
            neuron_minimum_dissolve_delay_to_vote_seconds: nervous_system_parameters_default
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            fallback_controller_principal_ids: vec![],
            logo: None,
            url: None,
            name: None,
            description: None,
            initial_token_distribution: None,
            initial_reward_rate_percentage: voting_rewards_parameters
                .initial_reward_rate_basis_points
                .map(unit_helpers::basis_points_to_percentage),
            final_reward_rate_percentage: voting_rewards_parameters
                .final_reward_rate_basis_points
                .map(unit_helpers::basis_points_to_percentage),
        }
    }
}

impl SnsCliInitConfig {
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
    let supported_formats = [("svg", "image/svg+xml"), ("png", "image/png")];
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

    // SVG data URL prefix:
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
        let optional_logo = match sns_cli_init_config.logo {
            None => None,
            Some(ref logo_path) => Some(load_logo(logo_path)?),
        };

        Ok(SnsInitPayload {
            sns_initialization_parameters: Some(get_config_file_contents(
                sns_cli_init_config.clone(),
            )),
            transaction_fee_e8s: sns_cli_init_config.transaction_fee_e8s,
            token_name: sns_cli_init_config.token_name,
            token_symbol: sns_cli_init_config.token_symbol,
            proposal_reject_cost_e8s: sns_cli_init_config.proposal_reject_cost_e8s,
            neuron_minimum_stake_e8s: sns_cli_init_config.neuron_minimum_stake_e8s,
            neuron_minimum_dissolve_delay_to_vote_seconds: sns_cli_init_config
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            fallback_controller_principal_ids: sns_cli_init_config
                .fallback_controller_principal_ids,
            logo: optional_logo,
            url: sns_cli_init_config.url,
            name: sns_cli_init_config.name,
            description: sns_cli_init_config.description,
            initial_token_distribution: sns_cli_init_config.initial_token_distribution,
            initial_reward_rate_basis_points: sns_cli_init_config
                .initial_reward_rate_percentage
                .map(unit_helpers::percentage_to_basis_points),
            final_reward_rate_basis_points: sns_cli_init_config
                .final_reward_rate_percentage
                .map(unit_helpers::percentage_to_basis_points),
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
                default_config.transaction_fee_e8s.unwrap()
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
                default_config.proposal_reject_cost_e8s.unwrap()
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
#           memo: 0,
#           dissolve_delay_seconds: 15780000 # 6 months
#         - controller: fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe
#           stake_e8s: 1500000000
#           memo: 1,
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
#           memo: 0,
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
                default_config.neuron_minimum_stake_e8s.unwrap(),
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
# increases. For example, a reward rate of 2% will cause the supply to increase 
# by at most 2% each year. A higher voting reward rate incentivizes people to 
# participate in governance, but also results in higher inflation. 
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
#"##,
                default_config.initial_reward_rate_percentage.unwrap(),
                default_config.final_reward_rate_percentage.unwrap(),
            ),
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
    use crate::init_config_file::{get_config_file_contents, SnsCliInitConfig};
    use ic_sns_governance::types::ONE_MONTH_SECONDS;
    use ic_sns_init::pb::v1::sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower as FDVP;
    use ic_sns_init::pb::v1::{FractionalDeveloperVotingPower, SnsInitPayload};
    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::{BufReader, Read};

    impl SnsCliInitConfig {
        pub fn with_test_values() -> Self {
            let mut logo_path =
                std::path::PathBuf::from(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
            logo_path.push("test.png");

            Self {
                transaction_fee_e8s: Some(1),
                token_name: Some("ServiceNervousSystem".to_string()),
                token_symbol: Some("SNS".to_string()),
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
                initial_token_distribution: Some(FDVP(FractionalDeveloperVotingPower {
                    ..Default::default()
                })),
                initial_reward_rate_percentage: Some(31.0),
                final_reward_rate_percentage: Some(27.0),
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
        "#,
            logo_path.clone().into_os_string().into_string().unwrap()
        );
        let resulting_payload: SnsCliInitConfig = serde_yaml::from_str(&file_contents).unwrap();
        assert!(resulting_payload.validate().is_ok());

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

        assert_eq!(
            get_config_file_contents(sns_cli_init_config.clone()),
            sns_init_payload.sns_initialization_parameters.unwrap()
        );
        assert_eq!(
            sns_cli_init_config.transaction_fee_e8s,
            sns_init_payload.transaction_fee_e8s
        );
        assert_eq!(sns_cli_init_config.token_name, sns_init_payload.token_name);
        assert_eq!(
            sns_cli_init_config.token_symbol,
            sns_init_payload.token_symbol
        );
        assert_eq!(
            sns_cli_init_config.proposal_reject_cost_e8s,
            sns_init_payload.proposal_reject_cost_e8s
        );
        assert_eq!(
            sns_cli_init_config.neuron_minimum_stake_e8s,
            sns_init_payload.neuron_minimum_stake_e8s
        );
        assert_eq!(
            sns_cli_init_config.neuron_minimum_dissolve_delay_to_vote_seconds,
            sns_init_payload.neuron_minimum_dissolve_delay_to_vote_seconds
        );
        assert_eq!(
            sns_cli_init_config.fallback_controller_principal_ids,
            sns_init_payload.fallback_controller_principal_ids
        );
        assert_eq!(sns_cli_init_config.url, sns_init_payload.url);
        assert_eq!(
            sns_cli_init_config.description,
            sns_init_payload.description
        );
        assert_eq!(
            sns_cli_init_config.initial_token_distribution,
            sns_init_payload.initial_token_distribution
        );
        assert_eq!(
            sns_cli_init_config
                .initial_reward_rate_percentage
                .map(|v| (v * 100.0) as u64),
            sns_init_payload.initial_reward_rate_basis_points
        );
        assert_eq!(
            sns_cli_init_config
                .final_reward_rate_percentage
                .map(|v| (v * 100.0) as u64),
            sns_init_payload.final_reward_rate_basis_points
        );

        // Read the test.png file into memory
        let logo_path = sns_cli_init_config.logo.unwrap();

        let file = File::open(&logo_path).unwrap();
        let mut reader = BufReader::new(file);
        let mut buffer: Vec<u8> = vec![];
        reader.read_to_end(&mut buffer).unwrap();
        let encoded_logo = "data:image/png;base64,".to_owned() + &base64::encode(&buffer);

        assert_eq!(Some(encoded_logo), sns_init_payload.logo);
    }

    #[test]
    fn test_try_from_sns_cli_init_without_logo() {
        let mut sns_cli_init_config = SnsCliInitConfig::with_test_values();

        // Set the logo to None to indicate the developer hasn't provided it
        sns_cli_init_config.logo = None;

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
}
