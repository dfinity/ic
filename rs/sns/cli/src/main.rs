//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

use candid::{CandidType, Encode, IDLArgs};
use clap::Parser;
use ic_base_types::{CanisterId, PrincipalId};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::{Governance, NeuronPermissionList, NeuronPermissionType};
use ic_sns_root::pb::v1::SnsRootCanister;
use ledger_canister::{
    AccountIdentifier, ArchiveOptions, BinaryAccountBalanceArgs, LedgerCanisterInitPayload, Tokens,
};
use maplit::hashset;
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
    LocalDeploy(LocalDeployArgs),
    AccountBalance(AccountBalanceArgs),
}

/// The arguments used to configure a SNS deployment
#[derive(Debug, Parser)]
struct LocalDeployArgs {
    /// The transaction fee that must be paid for ledger transactions (except
    /// minting and burning governance tokens), denominated in e8s (1 token = 100,000,000 e8s).
    #[clap(long)]
    transaction_fee_e8s: Option<u64>,

    /// The name of the governance token controlled by this SNS, for example "Bitcoin"
    #[clap(long)]
    pub token_name: String,

    /// The symbol of the governance token controlled by this SNS, for example "BTC"
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
}

impl LocalDeployArgs {
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

/// The canister IDs of all SNS canisters
struct SnsCanisterIds {
    pub governance: PrincipalId,
    pub ledger: PrincipalId,
    pub root: PrincipalId,
}

fn main() {
    let args = CliArgs::try_parse_from(std::env::args())
        .unwrap_or_else(|e| panic!("Illegal arguments: {}", e));

    match args.sub_command {
        SubCommand::LocalDeploy(args) => local_deploy(args),
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
        get_identity("get-principal")
    };

    let account: AccountIdentifier = principal_id.into();
    let account_balance_args = BinaryAccountBalanceArgs {
        account: account.to_address(),
    };

    let idl = IDLArgs::from_bytes(&Encode!(&account_balance_args).unwrap()).unwrap();

    call_dfx(&[
        "canister",
        "call",
        "sns_ledger",
        "account_balance",
        &format!("{}", idl),
    ]);
}

/// Deploy SNS canisters to the local network (e.g. a local network brought up using `dfx start`)
fn local_deploy(args: LocalDeployArgs) {
    args.validate();
    create_all_canisters();
    let sns_canister_ids = get_sns_canister_ids();
    install_sns_canisters(&sns_canister_ids, &args);
    set_sns_canister_controllers(&sns_canister_ids);
    validate_local_deployment();
    println!("\n***** Successfully deployed! *****");
}

/// Validate that the local SNS deployment executed successfully
fn validate_local_deployment() {
    println!("Validating local deployment...");
    print_nervous_system_parameters();
    print_ledger_transfer_fee();
    print_token_symbol();
    print_token_name();
}

/// Call Governance's `get_nervous_system_parameters` method and print the result
fn print_nervous_system_parameters() {
    println!("Governance Nervous System Parameters:");
    call_dfx(&[
        "canister",
        "call",
        "sns_governance",
        "get_nervous_system_parameters",
        "(null)",
    ]);
}

/// Call the Ledger's `transfer_fee` method and print the result
fn print_ledger_transfer_fee() {
    println!("Ledger transfer_fee:");
    call_dfx(&[
        "canister",
        "call",
        "sns_ledger",
        "transfer_fee",
        "(record {})",
    ]);
}

/// Call the Ledger's `symbol` method and print the result
fn print_token_symbol() {
    println!("Ledger token symbol:");
    call_dfx(&["canister", "call", "sns_ledger", "symbol", "()"]);
}

/// Call the Ledger's `name` method and print the result
fn print_token_name() {
    println!("Ledger token name:");
    call_dfx(&["canister", "call", "sns_ledger", "name", "()"]);
}

/// Set the SNS canister controllers appropriately.
///
/// Governance and Ledger must be controlled only by Root, and Root must be controlled
/// only by Governance.
fn set_sns_canister_controllers(sns_canister_ids: &SnsCanisterIds) {
    println!("Setting SNS canister controllers...");
    let wallet_canister = get_identity("get-wallet");
    let dfx_identity = get_identity("get-principal");

    // Governance must be controlled by only Root
    add_controller(sns_canister_ids.root, "sns_governance");
    remove_controller(wallet_canister, "sns_governance");
    remove_controller(dfx_identity, "sns_governance");

    // Root must be controlled by only Governance
    add_controller(sns_canister_ids.governance, "sns_root");
    remove_controller(wallet_canister, "sns_root");
    remove_controller(dfx_identity, "sns_root");

    // Ledger must be controlled by only Root
    add_controller(sns_canister_ids.root, "sns_ledger");
    remove_controller(wallet_canister, "sns_ledger");
    remove_controller(dfx_identity, "sns_ledger");
}

/// Return the `PrincipalId` of the given dfx identity
fn get_identity(identity: &str) -> PrincipalId {
    println!("dfx identity {}", identity);
    let output = call_dfx(&["identity", identity]);

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

/// Add `controller` as a new controller of the canister given by `canister_name`
fn add_controller(controller: PrincipalId, canister_name: &str) {
    call_dfx(&[
        "canister",
        "update-settings",
        "--add-controller",
        &controller.to_string(),
        canister_name,
    ]);
}

/// Remove `controller` as a controller of the canister given by `canister_name`
fn remove_controller(controller: PrincipalId, canister_name: &str) {
    call_dfx(&[
        "canister",
        "update-settings",
        "--remove-controller",
        &controller.to_string(),
        canister_name,
    ]);
}

/// Install the SNS canisters
fn install_sns_canisters(sns_canister_ids: &SnsCanisterIds, args: &LocalDeployArgs) {
    install_governance(sns_canister_ids, args);
    install_ledger(sns_canister_ids, args);
    install_root(sns_canister_ids);
}

/// Install and initialize Governance
fn install_governance(sns_canister_ids: &SnsCanisterIds, args: &LocalDeployArgs) {
    let init_args = hex_encode_candid(governance_init_args(sns_canister_ids, args));
    install_canister("sns_governance", &init_args);
}

/// Install and initialize Ledger
fn install_ledger(sns_canister_ids: &SnsCanisterIds, args: &LocalDeployArgs) {
    let init_args = hex_encode_candid(ledger_init_args(sns_canister_ids, args));
    install_canister("sns_ledger", &init_args);
}

/// Install and initialize Root
fn install_root(sns_canister_ids: &SnsCanisterIds) {
    let init_args = hex_encode_candid(root_init_args(sns_canister_ids));
    install_canister("sns_root", &init_args);
}

/// Install the given canister
fn install_canister(sns_canister_name: &str, init_args: &str) {
    call_dfx(&[
        "canister",
        "install",
        "--argument-type=raw",
        "--argument",
        init_args,
        sns_canister_name,
    ]);
}

/// Allocate canister IDs for all SNS canisters
fn create_all_canisters() {
    println!("Creating canisters...");
    call_dfx(&["canister", "create", "--all"]);
}

/// Return the canister IDs of all SNS canisters
fn get_sns_canister_ids() -> SnsCanisterIds {
    SnsCanisterIds {
        governance: get_canister_id("sns_governance"),
        ledger: get_canister_id("sns_ledger"),
        root: get_canister_id("sns_root"),
    }
}

/// Return the canister ID of the canister given by `canister_name`
fn get_canister_id(canister_name: &str) -> PrincipalId {
    println!("dfx canister id {}", canister_name);
    let output = call_dfx(&["canister", "id", canister_name]);

    let canister_id = String::from_utf8(output.stdout).unwrap_or_else(|_| {
        panic!(
            "Could not parse the output of 'dfx canister id {}' as a string",
            canister_name
        )
    });

    PrincipalId::from_str(canister_id.trim()).unwrap_or_else(|_| {
        panic!(
            "Could not parse the output of 'dfx canister id {}' as a PrincipalId",
            canister_name
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
        panic!(
            "dfx failed when called with args: {:?}, error: {}",
            args, std_err
        );
    }

    output
}

/// Given a `CandidType`, return the hex encoding of this object.
fn hex_encode_candid(candid: impl CandidType) -> String {
    let bytes = Encode!(&candid).unwrap();
    hex::encode(&bytes)
}

/// Constuct the params used to initialize a SNS Governance canister.
fn governance_init_args(sns_canister_ids: &SnsCanisterIds, args: &LocalDeployArgs) -> Governance {
    let mut governance = GovernanceCanisterInitPayloadBuilder::new().build();
    governance.ledger_canister_id = Some(sns_canister_ids.ledger);
    governance.root_canister_id = Some(sns_canister_ids.root);

    for parameters in governance.parameters.iter_mut() {
        let all_permissions = NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        };
        parameters.neuron_claimer_permissions = Some(all_permissions.clone());
        parameters.neuron_grantable_permissions = Some(all_permissions.clone());

        if let Some(neuron_minimum_stake_e8s) = args.neuron_minimum_stake_e8s {
            parameters.neuron_minimum_stake_e8s = Some(neuron_minimum_stake_e8s);
        }

        if let Some(proposal_reject_cost_e8s) = args.proposal_reject_cost_e8s {
            parameters.reject_cost_e8s = Some(proposal_reject_cost_e8s);
        }
    }

    governance
}

/// Constuct the params used to initialize a SNS Ledger canister.
fn ledger_init_args(
    sns_canister_ids: &SnsCanisterIds,
    args: &LocalDeployArgs,
) -> LedgerCanisterInitPayload {
    let root_canister_id = CanisterId::new(sns_canister_ids.root).unwrap();

    let mut payload = LedgerCanisterInitPayload::builder()
        .minting_account(sns_canister_ids.governance.into())
        .token_symbol_and_name(&args.token_symbol, &args.token_name)
        .archive_options(ArchiveOptions {
            trigger_threshold: 2000,
            num_blocks_to_archive: 1000,
            // 1 GB, which gives us 3 GB space when upgrading
            node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
            // 128kb
            max_message_size_bytes: Some(128 * 1024),
            controller_id: root_canister_id,
            // TODO: allow users to set this value
            // 10 Trillion cycles
            cycles_for_archive_creation: Some(10_000_000_000_000),
        })
        .build()
        .unwrap();

    payload.transfer_fee = args.transaction_fee_e8s.map(Tokens::from_e8s);
    payload.initial_values = args.get_initial_accounts();

    let governance_canister_id = CanisterId::new(sns_canister_ids.governance).unwrap();
    let ledger_canister_id = CanisterId::new(sns_canister_ids.ledger).unwrap();
    payload.send_whitelist = hashset! { governance_canister_id, ledger_canister_id };

    payload
}

/// Constuct the params used to initialize a SNS Root canister.
fn root_init_args(sns_canister_ids: &SnsCanisterIds) -> SnsRootCanister {
    SnsRootCanister {
        governance_canister_id: Some(sns_canister_ids.governance),
    }
}
