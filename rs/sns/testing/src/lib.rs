use std::{path::PathBuf, str::FromStr};

use clap::{ArgAction, ArgGroup, Parser, Subcommand};
use ic_base_types::{CanisterId, PrincipalId};
use ic_sns_cli::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use icp_ledger::Tokens;
use rust_decimal::Decimal;
use url::Url;

pub mod bootstrap;
pub mod sns;
pub mod utils;

#[derive(Debug, Parser)]
#[clap(name = "sns-testing-cli", about = "A CLI for testing SNS", version)]
pub struct SnsTestingArgs {
    /// The network to run the basic scenario on. This can be either dfx-compatible named network
    /// identifier or the URL of a IC HTTP endpoint.
    #[arg(long)]
    pub network: String,
    #[clap(subcommand)]
    pub subcommand: SnsTestingSubCommand,
}
#[derive(Debug, Parser)]
pub enum SnsTestingSubCommand {
    /// Check that the provided IC network has initialized NNS.
    ValidateNetwork(ValidateNetworkArgs),
    /// Run the SNS lifecycle scenario.
    /// The scenario will create the new SNS, and perform an upgrade for the SNS-controlled canister.
    RunBasicScenario(RunBasicScenarioArgs),
    /// Complete the SNS swap by providing sufficient direct participations.
    SwapComplete(SwapCompleteArgs),
    /// Upvote the proposal in the specified SNS.
    SnsProposalUpvote(SnsProposalUpvoteArgs),
    /// Transfer ICP tokens from the treasury to the specified account.
    TransferICP(TransferICPArgs),
}

#[derive(Debug, Parser)]
pub struct ValidateNetworkArgs {}

#[derive(Debug, Parser)]
pub struct RunBasicScenarioArgs {
    /// The name of the 'dfx' identity to use for the scenario. The principal of this identity
    /// is used to submit NNS proposal to create the new SNS and is added as an initial neuron in the new SNS.
    #[arg(long)]
    pub dev_identity: Option<String>,
    /// The ID of the canister to be controlled by the SNS created in the scenario.
    #[arg(long)]
    pub canister_id: CanisterId,
    /// Path to a canister WASM module file.
    #[arg(long)]
    pub upgrade_wasm_path: PathBuf,
    /// Upgrade argument for the canister.
    /// The argument must be a valid Candid value.
    #[arg(long)]
    pub upgrade_candid_arg: Option<String>,
    /// The NNS Neuron ID that will be used to submit the proposal to create the new SNS.
    /// Defaults to '1'.
    #[arg(long)]
    pub nns_neuron_id: Option<u64>,
}

#[derive(Debug, Parser)]
#[clap(group(ArgGroup::new("neuron-follow-selection").multiple(false).required(false)))]
pub struct SwapCompleteArgs {
    /// The name of the SNS to complete the swap for.
    #[arg(long)]
    pub sns_name: String,
    /// The name of the 'dfx' identity. The principal of this identity is supposed to have
    /// an account in the ICP ledger with sufficient balance to provide direct participations
    /// for the SNS swap.
    /// If not provided, the ephemeral identity with hardcoded principal will be used.
    #[arg(long)]
    pub icp_treasury_identity: Option<String>,
    /// The neuron that swap participants will follow.
    #[clap(long, group = "neuron-follow-selection")]
    pub follow_neuron: Option<ParsedSnsNeuron>,
    /// Principal ID whose neurons swap participants will follow.
    #[clap(long, group = "neuron-follow-selection")]
    pub follow_principal_neurons: Option<PrincipalId>,
}

#[derive(Debug, Parser)]
pub struct SnsProposalUpvoteArgs {
    /// The ID of the proposal to upvote.
    #[arg(long)]
    pub proposal_id: u64,
    /// The name of the SNS to upvote the proposal in.
    #[arg(long)]
    pub sns_name: String,
    /// Wait for proposal execution.
    #[arg(
        long,
        action = ArgAction::Set,
        default_value_t = false,
        default_missing_value = "true",
        num_args = 0..=1,
        require_equals = false,
    )]
    pub wait: bool,
}

// A wrapper to parse 32-byte hex-encoded string.
// Used to parse ICP account and subaccount.
#[derive(Clone, Debug)]
pub struct ParsedAccount(pub [u8; 32]);

impl FromStr for ParsedAccount {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_decoded = hex::decode(s).map_err(|e| e.to_string())?;
        let bytes: [u8; 32] = hex_decoded
            .try_into()
            .map_err(|_| "Invalid length, must be 32 bytes")?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Subcommand)]
pub enum TransferRecipientArg {
    /// Transfer ICP to the specified account.
    #[command(name = "--to")]
    Account {
        /// Recepient account, 32-byte hex-encoded.
        account: ParsedAccount,
    },
    /// Transfer ICP to the specified principal's subaccount.
    #[command(name = "--to-principal")]
    Principal {
        /// The recipient principal ID.
        principal_id: PrincipalId,
        /// The subaccount, 32-byte hex-encoded.
        subaccount: Option<ParsedAccount>,
    },
}

#[derive(Debug, Parser)]
#[command(subcommand_value_name = "RECIPIENT")]
pub struct TransferICPArgs {
    /// The recipient of the transfer.
    #[command(subcommand, name = "recipient")]
    pub recipient: TransferRecipientArg,
    /// The amount of e8s to transfer.
    #[arg(long)]
    pub amount: ParsedTokens,
    /// The name of the 'dfx' identity. The principal of this identity is supposed to
    /// have an account in the ICP ledger with sufficient balance to perform the transfer.
    /// If not provided, the ephemeral identity with hardcoded principal will be used.
    #[arg(long)]
    pub icp_treasury_identity: Option<String>,
}

/// A wrapper to parse ICP tokens from a decimal number.
/// This is required because the internal representation of Tokens is u64 rather than decimal.
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedTokens(pub Tokens);

impl FromStr for ParsedTokens {
    // For now, the errors aren't used for anything other than reporting them to the user in stderr.
    // So the bare 'String' type is used.
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decimal_tokens = Decimal::from_str(s).map_err(|e| e.to_string())?;
        if decimal_tokens.scale() > 8 {
            return Err(
                "The number of decimal places for ICP token must be less than or equal to 8"
                    .to_string(),
            );
        }
        if decimal_tokens.is_sign_negative() {
            return Err("The amount of ICP tokens must be positive".to_string());
        }
        // Tokens are supposed to have at most 8 decimal places.
        // The mantissa is multiplied by 10^(8 - scale) to get the amount in e8s.
        let e8s: i128 = decimal_tokens.mantissa() * 10i128.pow(8 - decimal_tokens.scale());
        if e8s > i128::from(u64::MAX) {
            return Err(
                "The amount of e8s tokens must be less than or equal to 2^64 - 1".to_string(),
            );
        }
        Ok(Self(Tokens::from(e8s as u64)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_successfully_parsed_tokens() {
        let parsed = ParsedTokens::from_str("1.234567");
        assert_eq!(parsed, Ok(ParsedTokens(Tokens::from(123456700))));
    }
    #[test]
    fn test_scale_overflow() {
        let parsed = ParsedTokens::from_str("1.000000001");
        assert_eq!(
            parsed,
            Err(
                "The number of decimal places for ICP token must be less than or equal to 8"
                    .to_string()
            )
        );
    }
    #[test]
    fn test_negative_amount() {
        let parsed = ParsedTokens::from_str("-1.234567");
        assert_eq!(
            parsed,
            Err("The amount of ICP tokens must be positive".to_string())
        );
    }
    #[test]
    fn test_tokens_overflow() {
        // 4503599627370496.0 = 2^52
        let parsed = ParsedTokens::from_str("4503599627370496.0");
        assert_eq!(
            parsed,
            Err("The amount of e8s tokens must be less than or equal to 2^64 - 1".to_string())
        );
    }
}

#[derive(Debug, Parser)]
#[clap(
    name = "sns-testing-init",
    about = "Start the new PocketIC-based network with NNS canisters.
This command exposes the newly created network on 'http://127.0.0.1:8080'",
    version
)]
pub struct NnsInitArgs {
    /// The URL of an existing 'pocket-ic-server' instance where the NNS will be installed.
    #[arg(long)]
    pub server_url: Url,
    /// The path to the state PocketIC instance state directory.
    /// If not specified, a new temporary directory will be created.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// The localhost port on which the HTTP endpoint for the IC network will be exposed.
    /// Defaults to 8080.
    #[arg(long, default_value_t = 8080)]
    pub ic_network_port: u16,
    /// The name of the 'dfx' identity. The principal of this identity will be used as the
    /// hotkey for the NNS neuron with the majority voting power.
    #[arg(long)]
    pub dev_identity: String,
    /// The name of the 'dfx' identity. The principal of this identity will be added to the
    /// ICP ledger with 10_000_000 ICP. This identity will be used to transfer ICP
    /// to provide sufficient direct participations for the SNS swap or to transfer ICP
    /// to the user provided account.
    /// If not provided, the ephemeral identity with hardcoded principal will be used.
    #[arg(long)]
    pub icp_treasury_identity: Option<String>,
}
