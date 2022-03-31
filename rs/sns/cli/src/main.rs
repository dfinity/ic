//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

use candid::{CandidType, Encode};
use ic_base_types::PrincipalId;
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::Governance;
use ic_sns_root::pb::v1::SnsRootCanister;
use ledger_canister::LedgerCanisterInitPayload;
use std::process::{Command, Output};
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "sns-cli",
    about = "Initialize, deploy and interact with an SNS."
)]
struct CliArgs {
    #[structopt(subcommand)]
    sub_command: SubCommand,
}

#[derive(Debug, StructOpt)]
enum SubCommand {
    LocalDeploy(LocalDeployArgs),
}

/// The arguments used to configure a SNS deployment
#[derive(Debug, StructOpt)]
struct LocalDeployArgs {}

/// The canister IDs of all SNS canisters
struct SnsCanisterIds {
    pub governance: PrincipalId,
    pub ledger: PrincipalId,
    pub root: PrincipalId,
}

fn main() {
    let args = CliArgs::from_iter_safe(std::env::args())
        .unwrap_or_else(|e| panic!("Illegal arguments: {}", e));

    match args.sub_command {
        SubCommand::LocalDeploy(args) => local_deploy(args),
    }
}

/// Deploy SNS canisters to the local network (e.g. a local network brought up using `dfx start`)
fn local_deploy(args: LocalDeployArgs) {
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
fn install_sns_canisters(sns_canister_ids: &SnsCanisterIds, _args: &LocalDeployArgs) {
    install_governance(sns_canister_ids);
    install_ledger(sns_canister_ids);
    install_root(sns_canister_ids);
}

/// Install and initialize Governance
fn install_governance(sns_canister_ids: &SnsCanisterIds) {
    let init_args = hex_encode_candid(governance_init_args(sns_canister_ids));
    install_canister("sns_governance", &init_args);
}

/// Install and initialize Ledger
fn install_ledger(sns_canister_ids: &SnsCanisterIds) {
    let init_args = hex_encode_candid(ledger_init_args(sns_canister_ids));
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
fn governance_init_args(sns_canister_ids: &SnsCanisterIds) -> Governance {
    let mut governance = GovernanceCanisterInitPayloadBuilder::new().build();
    governance.ledger_canister_id = Some(sns_canister_ids.ledger);
    // TODO(NNS1-923): Set root canister ID
    governance
}

/// Constuct the params used to initialize a SNS Ledger canister.
fn ledger_init_args(sns_canister_ids: &SnsCanisterIds) -> LedgerCanisterInitPayload {
    LedgerCanisterInitPayload::builder()
        .minting_account(sns_canister_ids.governance.into())
        .build()
        .unwrap()
}

/// Constuct the params used to initialize a SNS Root canister.
fn root_init_args(sns_canister_ids: &SnsCanisterIds) -> SnsRootCanister {
    SnsRootCanister {
        governance_canister_id: Some(sns_canister_ids.governance),
    }
}
