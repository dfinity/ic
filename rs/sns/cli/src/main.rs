//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

mod deploy;

use crate::deploy::SnsDeployer;
use candid::{CandidType, Encode, IDLArgs};
use clap::Parser;
use ic_base_types::PrincipalId;
use ic_sns_init::{
    distributions::{InitialTokenDistribution, TokenDistribution},
    SnsInitPayload, SnsInitPayloadBuilder,
};
use ledger_canister::{AccountIdentifier, BinaryAccountBalanceArgs};
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

    /// The amount of cycles to initialize each SNS canister with. This can be omitted when
    /// deploying locally.
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
    /// panic! if any args are invalid
    pub fn validate(&self) {
        if self.network == "ic" {
            assert!(
                self.initial_cycles_per_canister.is_some(),
                "When deploying to the ic network, initial_cycles_per_canister must be set"
            );
        }
    }

    pub fn generate_sns_init_payload(&self) -> SnsInitPayload {
        let mut builder = SnsInitPayloadBuilder::new();
        builder
            .with_token_name(self.token_name.clone())
            .with_token_symbol(self.token_symbol.clone())
            // TODO NNS1-1463: Include the InitialTokenDistribution as input
            .with_initial_token_distribution(InitialTokenDistribution {
                developers: TokenDistribution {
                    total_e8s: 100,
                    distributions: Default::default(),
                },

                treasury: TokenDistribution {
                    total_e8s: 100,
                    distributions: Default::default(),
                },
                swap: 100,
            });

        if let Some(transaction_fee_e8s) = self.transaction_fee_e8s {
            builder.with_transaction_fee_e8s(transaction_fee_e8s);
        }

        if let Some(proposal_reject_cost_e8s) = self.proposal_reject_cost_e8s {
            builder.with_proposal_reject_cost_e8s(proposal_reject_cost_e8s);
        }

        if let Some(neuron_minimum_stake_e8s) = self.neuron_minimum_stake_e8s {
            builder.with_neuron_minimum_stake_e8s(neuron_minimum_stake_e8s);
        }

        builder
            .build()
            .unwrap_or_else(|e| panic!("Error creating the SnsInitPayload: {}", e))
    }
}

fn main() {
    let args = match CliArgs::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    match args.sub_command {
        SubCommand::Deploy(args) => deploy(args),
        SubCommand::AccountBalance(args) => print_account_balance(args),
    }
}

/// Deploy an SNS with the given DeployArgs.
fn deploy(args: DeployArgs) {
    args.validate();
    let sns_init_payload = args.generate_sns_init_payload();
    SnsDeployer::new(args, sns_init_payload).deploy()
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
