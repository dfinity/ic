use clap::Parser;
use ic_sns_governance::pb::v1::NervousSystemParameters;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_init::{
    MAX_TOKEN_NAME_LENGTH, MAX_TOKEN_SYMBOL_LENGTH, MIN_PARTICIPANT_ICP_E8S_DEFAULT,
    MIN_TOKEN_NAME_LENGTH, MIN_TOKEN_SYMBOL_LENGTH,
};
use regex::Regex;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::str::FromStr;

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
    let default_sns_init_payload = SnsInitPayload::with_default_values();
    let config_file_string = get_config_file_contents(default_sns_init_payload);
    let f = File::create(init_config_file_path).expect("Unable to open file");
    let mut f = BufWriter::new(f);
    f.write_all(config_file_string.as_bytes())
        .expect("Unable to write init config file");
}

fn get_config_file_contents(sns_init_payload: SnsInitPayload) -> String {
    let nervous_system_parameters_default = NervousSystemParameters::with_default_values();
    let yaml_payload = serde_yaml::to_string(&sns_init_payload)
        .expect("Error when converting sns_init_payload to yaml");

    let mut yaml_file_string = String::new();
    // Comment on top of each field.
    let field_comment: Vec<(Regex, String)> = vec![
        (
            Regex::new(r"transaction_fee_e8s.*").unwrap(),
            format!(
                r##"#
# Fee of a transaction.
# Default value = {}
#"##,
                nervous_system_parameters_default
                    .transaction_fee_e8s
                    .unwrap()
            ),
        ),
        (
            Regex::new(r"proposal_reject_cost_e8s.*").unwrap(),
            format!(
                r##"#
# Cost of making a proposal that is not adopted.
# Default value = {}
#"##,
                nervous_system_parameters_default.reject_cost_e8s.unwrap()
            ),
        ),
        (
            Regex::new(r"token_name.*").unwrap(),
            format!(
                r##"#
# The name of the token issued by an SNS Ledger.
# This field has no default, a value must be provided by the user.
# Must be a string length between {} and {} characters
#
# Example: InternetComputerProtocol
#"##,
                MIN_TOKEN_NAME_LENGTH, MAX_TOKEN_NAME_LENGTH
            ),
        ),
        (
            Regex::new(r"initial_token_distribution.*").unwrap(),
            r##"#
# This field sets the initial token distribution. Initially, there is only support for
# the FractionalDeveloperVotingPower strategy. The FractionalDeveloperVotingPower token
# distribution strategy configures how tokens and neurons are distributed via four
# "buckets": developers, treasury, swap, and airdrops. This strategy will distribute
# all developer tokens at genesis in restricted neurons with an additional voting power
# multiplier applied. This voting power multiplier is calculated as
# `swap_distribution.initial_swap_amount_e8s / swap_distribution.total_e8s`.
# As more of the swap funds are swapped in future rounds, the voting power
# multiplier will approach 1.0. The following preconditions must be met for
# it to be a valid distribution:
#    - developer_distribution.developer_neurons.stake_e8s.sum <= u64:MAX
#    - developer_neurons.developer_neurons.stake_e8s.sum <= swap_distribution.total_e8s
#    - airdrop_distribution.airdrop_neurons.stake_e8s.sum <= u64:MAX
#    - swap_distribution.initial_swap_amount_e8s > 0
#    - swap_distribution.initial_swap_amount_e8s <= swap_distribution.total_e8s
#    - swap_distribution.total_e8s >= developer_distribution.developer_neurons.stake_e8s.sum
#
# - developer_distribution has one field:
#    - developer_neurons: A list of NeuronDistributions that specifiy the neuron's stake and
#      controlling principal. These neurons will be available at genesis in PreInitializationSwap
#      mode. The voting power mutlipler will be applied to these neurons.
#
# - treasury_distribution has one field:
#    - total_e8s: The total amount of tokens in the treasury bucket.
#
# - swap_distribution has two fields:
#    - total_e8s: The total amount of tokens in the swap bucket. initial_swap_amount_e8s will be
#      deducted from this total.
#    - initial_swap_amount_e8s: The initial amount of tokens deposited in the swap canister for
#      the initial token swap.
#
# - aidrop_distribution has one field:
#    - airdrop_neurons: A list of NeuronDistributions that specifiy the neuron's stake and
#      controlling principal. These neurons will be available at genesis in PreInitializationSwap
#      mode. No voting power mutlipler will be applied to these neurons.
#
# Example:
# initial_token_distribution:
#   FractionalDeveloperVotingPower:
#     developer_distribution:
#       developer_neurons:
#         - controller: x4vjn-rrapj-c2kqe-a6m2b-7pzdl-ntmc4-riutz-5bylw-2q2bh-ds5h2-lae
#           stake_e8s: 1500000000
#         - controller: fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe
#           stake_e8s: 1500000000
#     treasury_distribution:
#       total_e8s: 5000000000
#     swap_distribution:
#       total_e8s: 6000000000
#       initial_swap_amount_e8s: 3000000000
#     airdrop_distribution:
#       airdrop_neurons:
#         - controller: fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe
#           stake_e8s: 500000000
#"##
            .to_string(),
        ),
        (
            Regex::new(r"token_symbol.*").unwrap(),
            format!(
                r##"#
# The symbol of the token issued by an SNS Ledger.
# This field has no default, a value must be provided by the user.
# Must be a string length between {} and {} characters
#
# Example: ICP
#
#"##,
                MIN_TOKEN_SYMBOL_LENGTH, MAX_TOKEN_SYMBOL_LENGTH
            ),
        ),
        (
            Regex::new(r"neuron_minimum_stake_e8s*").unwrap(),
            format!(
                r##"#
# The minimum amount a neuron needs to have staked.
# Default value = {}
#"##,
                nervous_system_parameters_default
                    .neuron_minimum_stake_e8s
                    .unwrap(),
            ),
        ),
        (
            Regex::new(r"min_icp_e8s*").unwrap(),
            r##"#
# This field has no default, a value must be provided by the user.
# The minimum amount of ICP that is required for this token swap to take
# place. This amount divided by the amount of SNS tokens for swap gives the
# seller's reserve price for the swap, i.e., the minimum number of ICP per SNS
# tokens that the seller of SNS tokens is willing to accept. If this amount is
# not achieved, the swap will be aborted (instead of committed) when the due
# date/time occurs. Must be smaller than or equal to `max_icp_e8s`.
#"##
            .to_string(),
        ),
        (
            Regex::new(r"max_icp_e8s*").unwrap(),
            r##"#
# This field has no default, a value must be provided by the user.
# Amount targeted by the swap, if the amount is reached the swap is triggered.
# Must be at least min_participants * min_participant_icp_e8.
#"##
            .to_string(),
        ),
        (
            Regex::new(r"min_participant_icp_e8s*").unwrap(),
            format!(
                r##"#
# The minimum amount of ICP that each buyer must contribute to participate in the swap.
# Default value = {}
#"##,
                MIN_PARTICIPANT_ICP_E8S_DEFAULT
            ),
        ),
        (
            Regex::new(r"min_participants*").unwrap(),
            r##"#
# This field has no default, a value must be provided by the user.
# The minimum number of participants for the swap to take place. Must be greater than zero.
#"##
            .to_string(),
        ),
        (
            Regex::new(r"max_participant_icp_e8s*").unwrap(),
            r##"#
# This field has no default, a value must be provided by the user.
# The maximum amount of ICP that each buyer can contribute. Must be greater than
# or equal to `min_participant_icp_e8s` and less than or equal to
# `max_icp_e8s`. Can effectively be disabled by setting it to `max_icp_e8s`.
#"##
            .to_string(),
        ),
        (
            Regex::new(r"fallback_controller_principal_ids.*").unwrap(),
            r##"#
# If the swap fails, control of the dapp canister(s) will be set to these
# principal IDs. In most use-cases, this would be the same as the original set
# of controller(s). Must not be empty.
#"##
            .to_string(),
        ),
    ];

    for (i, line) in yaml_payload.lines().enumerate() {
        if i == 1 {
            yaml_file_string.push_str("# 100_000_000 e8s = 1 token.\n")
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
    let sns_init_payload: SnsInitPayload = serde_yaml::from_reader(file).unwrap_or_else(|e| {
        eprintln!(
            "Couldn't parse {} for validation: {}",
            init_config_file.to_str().unwrap(),
            e
        );
        std::process::exit(1);
    });
    match sns_init_payload.validate() {
        Ok(_) => println!("No errors found {}", init_config_file.to_str().unwrap()),
        Err(e) => println!("{}", e),
    }
}

#[cfg(test)]
mod test {
    use crate::init_config_file::get_config_file_contents;
    use ic_sns_init::pb::v1::SnsInitPayload;

    /// Tests that the text produced by the "new" command can be read into the default sns_init_payload
    #[test]
    fn test_default_init_config_file() {
        assert_eq!(
            SnsInitPayload::with_default_values(),
            serde_yaml::from_str(&get_config_file_contents(
                SnsInitPayload::with_default_values()
            ))
            .unwrap()
        )
    }
}
