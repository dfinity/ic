//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

mod deploy;

use crate::deploy::SnsDeployer;
use candid::{CandidType, Encode, IDLArgs};
use clap::Parser;
use ic_base_types::PrincipalId;
use ledger_canister::{AccountIdentifier, BinaryAccountBalanceArgs, Tokens};
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::FromStr;

#[derive(Debug, Parser)]
#[clap(
    name = "sns-cli",
    about = "Initialize, deploy and interact with an SNS.",
    version
)]
struct CliArgs {
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Debug, Parser)]
enum SubCommand {
    Deploy(DeployArgs),
    AccountBalance(AccountBalanceArgs),
}

/// The arguments used to configure a SNS deployment
#[derive(Debug, Parser)]
pub struct DeployArgs {
    /// Print all error and info messages.
    #[structopt(long)]
    verbose: bool,

    /// The network to deploy to. This can be "local", "ic", or the URL of an IC network.
    #[structopt(default_value = "local", long)]
    network: String,

    /// The amount of cycles to initialize each SNS canister with.
    #[structopt(long)]
    initial_cycles_per_canister: Option<u64>,

    /// The transaction fee that must be paid for ledger transactions (except
    /// minting and burning governance tokens), denominated in e8s (1 token = 100,000,000 e8s).
    #[clap(long)]
    transaction_fee_e8s: Option<u64>,

    /// The name of the governance token controlled by this SNS, for example "Bitcoin".
    #[clap(long)]
    pub token_name: String,

    /// The symbol of the governance token controlled by this SNS, for example "BTC".
    #[clap(long)]
    pub token_symbol: String,

    /// The initial Ledger accounts that the SNS will be initialized with. This is a JSON file
    /// containing a JSON map from principal ID to the number of e8s to initialize the corresponding
    /// principal's account with. Note that sub-accounts are not yet supported.
    ///
    /// For example, this file can contain:
    /// { "fpyvw-ycywu-lzoho-vmluf-zivfl-534ds-uccto-ovwu6-xxpnj-j2hzq-dqe": 1000000000,
    ///   "fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe": 2000000000 }
    #[clap(long, parse(from_os_str))]
    pub initial_ledger_accounts: Option<PathBuf>,

    /// The number of e8s (10E-8 of a token) that a rejected proposal costs the proposer.
    #[clap(long)]
    pub proposal_reject_cost_e8s: Option<u64>,

    /// The minimum number of e8s (10E-8 of a token) that can be staked in a neuron.
    ///
    /// To ensure that staking and disbursing of the neuron work, the chosen value
    /// must be larger than the transaction_fee_e8s.
    #[clap(long)]
    pub neuron_minimum_stake_e8s: Option<u64>,
}

/// The arguments used to display the account balance of a user
#[derive(Debug, Parser)]
struct AccountBalanceArgs {
    /// The principal ID of the account owner to display their main account balance (note that
    /// subaccounts are not yet supported). If not specified, the principal of the current dfx
    /// identity is used.
    #[clap(long)]
    pub principal_id: Option<String>,

    /// The network to deploy to. This can be "local", "ic", or the URL of an IC network.
    #[structopt(default_value = "local", long)]
    network: String,
}

impl DeployArgs {
    const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;
    const MAX_TOKEN_NAME_LENGTH: usize = 255;

    /// panic! if any args are invalid
    pub fn validate(&self) {
        if self.token_symbol.len() > Self::MAX_TOKEN_SYMBOL_LENGTH {
            panic!(
                "Error: token-symbol must be fewer than {} characters, given character count: {}",
                Self::MAX_TOKEN_SYMBOL_LENGTH,
                self.token_symbol.len()
            );
        }

        if self.token_name.len() > Self::MAX_TOKEN_NAME_LENGTH {
            panic!(
                "Error: token-name must be fewer than {} characters, given character count: {}",
                Self::MAX_TOKEN_NAME_LENGTH,
                self.token_name.len()
            );
        }

        if self.network == "ic" {
            assert!(
                self.initial_cycles_per_canister.is_some(),
                "When deploying to the ic network, initial_cycles_per_canister must be set"
            );
        }
    }

    /// Parse the supplied `initial_ledger_accounts` JSON file into a map of account identifiers
    /// to `Tokens`
    pub fn get_initial_accounts(&self) -> HashMap<AccountIdentifier, Tokens> {
        // Read and parse the accounts JSON file.
        let accounts: HashMap<String, u64> = self
            .initial_ledger_accounts
            .clone()
            .map(|file_name| {
                let file =
                    File::open(file_name).expect("Couldn't open initial ledger accounts file");
                let accounts: HashMap<String, u64> = serde_json::from_reader(file)
                    .expect("Could not parse the initial ledger accounts file");
                accounts
            })
            .unwrap_or_default();

        // Validate principal IDs and convert from raw (String, u64) pairs
        // to (AccountIdentifier, Tokens) pairs.
        accounts
            .iter()
            .map(|(principal_str, e8s)| {
                let principal_id = PrincipalId::from_str(principal_str).unwrap_or_else(|_| {
                    panic!("Could not parse {} as a principal ID", principal_str)
                });
                (principal_id.into(), Tokens::from_e8s(*e8s))
            })
            .collect()
    }
}

fn main() {
    let args = CliArgs::try_parse_from(std::env::args())
        .unwrap_or_else(|e| panic!("Illegal arguments: {}", e));

    match args.sub_command {
        SubCommand::Deploy(args) => SnsDeployer::new(args).deploy(),
        SubCommand::AccountBalance(args) => print_account_balance(args),
    }
}

/// Print the Ledger account balance of the principal in `AccountBalanceArgs` if given, else
/// print the account balance of the principal of the current dfx identity.
fn print_account_balance(args: AccountBalanceArgs) {
    let principal_id = if let Some(principal_str) = args.principal_id {
        PrincipalId::from_str(&principal_str)
            .unwrap_or_else(|_| panic!("Could not parse {} as a PrincipalId", principal_str))
    } else {
        get_identity("get-principal", &args.network)
    };

    let account: AccountIdentifier = principal_id.into();
    let account_balance_args = BinaryAccountBalanceArgs {
        account: account.to_address(),
    };

    let idl = IDLArgs::from_bytes(&Encode!(&account_balance_args).unwrap()).unwrap();

    call_dfx(&[
        "canister",
        "--network",
        &args.network,
        "call",
        "sns_ledger",
        "account_balance",
        &format!("{}", idl),
    ]);
}

/// Return the `PrincipalId` of the given dfx identity
pub fn get_identity(identity: &str, network: &str) -> PrincipalId {
    println!("dfx identity {}", identity);
    let output = call_dfx(&["identity", "--network", network, identity]);

    let canister_id = String::from_utf8(output.stdout).unwrap_or_else(|_| {
        panic!(
            "Could not parse the output of 'dfx identity {}' as a string",
            identity
        )
    });

    PrincipalId::from_str(canister_id.trim()).unwrap_or_else(|_| {
        panic!(
            "Could not parse the output of 'dfx identity {}' as a PrincipalId",
            identity
        )
    })
}

/// Calls `dfx` with the given args
fn call_dfx(args: &[&str]) -> Output {
    let output = Command::new("dfx")
        .args(args)
        .output()
        .unwrap_or_else(|_| panic!("dfx failed when called with args: {:?}", args));

    // Some dfx commands output stderr instead of stdout, so we assign it for use in both
    // success and error cases below.
    let std_err = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
        print!("{}", std_err);
    } else {
        println!(
            "dfx failed when called with args: {:?}, error: {}",
            args, std_err
        );
    }

    output
}

/// Given a `CandidType`, return the hex encoding of this object.
pub fn hex_encode_candid(candid: impl CandidType) -> String {
    let bytes = Encode!(&candid).unwrap();
    hex::encode(&bytes)
}
