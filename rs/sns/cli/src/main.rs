//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

mod deploy;

use crate::deploy::SnsDeployer;
use candid::{CandidType, Encode, IDLArgs};
use clap::Parser;
use ic_base_types::PrincipalId;
use ic_crypto_sha::Sha256;
use ic_sns_governance::pb::v1::neuron::DissolveState;
use ic_sns_governance::pb::v1::{NervousSystemParameters, Neuron, NeuronPermission};
use ledger_canister::{AccountIdentifier, BinaryAccountBalanceArgs, Subaccount, Tokens};
use maplit::btreemap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::FromStr;
use std::time::SystemTime;

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

    /// The initial Ledger accounts that the SNS will be initialized with. This is a JSON file
    /// containing a JSON map from principal ID to the number of e8s to initialize the corresponding
    /// principal's account with. Note that sub-accounts are not yet supported.
    ///
    /// For example, this file can contain:
    ///
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

    /// The initial neurons that the SNS will be initialized with. This is a JSON file
    /// containing a JSON list of neuron objects. The possible fields of these neuron
    /// objects are:
    ///
    /// * controller: the Principal ID of the controller of the neuron
    ///
    /// * stake_e8s: the stake of the neuron, in e8s
    ///
    /// * dissolve_delay_seconds: the number of seconds it will take for this neuron to dissolve
    ///
    /// * nonce (optional): An ID to differentiate neurons with the same controller
    ///
    /// * age_seconds (optional): The initial age of the neuron, in seconds
    ///
    /// For example, this file might contain:
    ///
    /// [
    ///     { "controller": "x4vjn-rrapj-c2kqe-a6m2b-7pzdl-ntmc4-riutz-5bylw-2q2bh-ds5h2-lae",
    ///       "stake_e8s": 100000000,
    ///       "dissolve_delay_seconds": 86400,
    ///       "nonce": 12,
    ///       "age_seconds": 55
    ///     },
    ///     { "controller": "fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe",
    ///       "stake_e8s": 800000000,
    ///       "dissolve_delay_seconds": 200000
    ///     }
    /// ]
    #[clap(long, parse(from_os_str))]
    pub initial_neurons: Option<PathBuf>,
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
    /// to `Tokens`. Also add the ledger accounts of the specified initial neurons.
    pub fn get_initial_accounts(
        &self,
        governance_id: PrincipalId,
    ) -> HashMap<AccountIdentifier, Tokens> {
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

        // The ledger accounts of the initial neurons
        let neuron_accounts = self
            .get_initial_neuron_blueprints()
            .into_iter()
            .map(|neuron_blueprint| neuron_blueprint.as_ledger_account(governance_id));

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
            .chain(neuron_accounts)
            .collect()
    }

    /// Return the "blueprints" of the neurons that the user sets to exist on initialization
    /// of the SNS.
    pub fn get_initial_neuron_blueprints(&self) -> Vec<NeuronBlueprint> {
        let neurons: Vec<NeuronBlueprint> = self
            .initial_neurons
            .clone()
            .map(|file_name| {
                let file = File::open(file_name).expect("Couldn't open initial neurons file");
                let neurons: Vec<NeuronBlueprint> = serde_json::from_reader(file)
                    .expect("Could not parse the initial neurons file");
                neurons
            })
            .unwrap_or_default();

        neurons
    }

    /// Return the initial neurons that the user specified. These neurons will exist in
    /// Governance at genesis, with the correct balance in their corresponding ledger
    /// accounts in the Ledger. A map from neuron ID to Neuron is returned.
    pub fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> BTreeMap<String, Neuron> {
        self.get_initial_neuron_blueprints()
            .iter()
            .map(|neuron_blueprint| {
                let neuron = neuron_blueprint.as_neuron(parameters);
                (neuron.id.as_ref().unwrap().to_string(), neuron)
            })
            .collect()
    }
}

/// Specifies the necessary info from which to create a Neuron
#[derive(Serialize, Deserialize, Debug)]
pub struct NeuronBlueprint {
    controller: String,
    nonce: Option<u64>,
    stake_e8s: u64,
    age_seconds: Option<u64>,
    dissolve_delay_seconds: u64,
}

impl NeuronBlueprint {
    /// Build a `Neuron` from the blueprint
    pub fn as_neuron(&self, parameters: &NervousSystemParameters) -> Neuron {
        if let Some(neuron_minimum_stake_e8s) = parameters.neuron_minimum_stake_e8s {
            if self.stake_e8s < neuron_minimum_stake_e8s {
                panic!(
                    "An initial neuron has stake {}, which is less than the configured \
                    neuron_minimum_stake_e8s of {}",
                    self.stake_e8s, neuron_minimum_stake_e8s
                );
            }
        }

        if let Some(max_dissolve_delay_seconds) = parameters.max_dissolve_delay_seconds {
            if self.dissolve_delay_seconds > max_dissolve_delay_seconds {
                panic!(
                    "An initial neuron has dissolve_delay_seconds {}, which is more than the \
                    configured max_dissolve_delay_seconds of {}",
                    self.dissolve_delay_seconds, max_dissolve_delay_seconds
                );
            }
        }

        let permission = NeuronPermission {
            principal: Some(self.controller()),
            permission_type: parameters
                .neuron_claimer_permissions
                .as_ref()
                .unwrap()
                .permissions
                .clone(),
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Neuron {
            id: Some(self.subaccount().into()),
            permissions: vec![permission],
            cached_neuron_stake_e8s: self.stake_e8s,
            neuron_fees_e8s: 0,
            created_timestamp_seconds: now,
            aging_since_timestamp_seconds: now.saturating_sub(self.age_seconds.unwrap_or_default()),
            followees: btreemap! {},
            maturity_e8s_equivalent: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                self.dissolve_delay_seconds,
            )),
        }
    }

    /// Get the ledger account that corresponds with this neuron
    pub fn as_ledger_account(&self, governance_id: PrincipalId) -> (AccountIdentifier, Tokens) {
        let account = AccountIdentifier::new(governance_id, Some(self.subaccount()));
        let tokens = Tokens::from_e8s(self.stake_e8s);

        (account, tokens)
    }

    fn subaccount(&self) -> Subaccount {
        Subaccount({
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(self.controller().as_slice());
            state.write(&self.nonce.unwrap_or_default().to_be_bytes());
            state.finish()
        })
    }

    fn controller(&self) -> PrincipalId {
        PrincipalId::from_str(&self.controller).unwrap_or_else(|_| {
            panic!(
                "Could not parse neuron controller {} as a PrincipalId",
                &self.controller
            )
        })
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
