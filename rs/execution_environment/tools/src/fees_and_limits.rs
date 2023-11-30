use candid::{Decode, Encode};
use clap::{Arg, ArgMatches};
use eyre::{bail, Result};
use ic_agent::{export::Principal, identity::Secp256k1Identity, Agent};
use ic_config::{
    embedders, execution_environment,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig},
};
use serde_json::json;

// bazel run //rs/execution_environment:fees_and_limits -- --replica-version=<version> --canister-id=<canister-id> --pem-file=<path>
#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    let replica_version = args.value_of("replica-version").unwrap();
    let canister_id = args.value_of("canister-id");
    let pem_file = args.value_of("pem-file");

    let json = serde_json::to_string_pretty(&get_fees_and_limits())?;
    match (canister_id, pem_file) {
        (None, None) => {
            println!("No canister is specified, dumping JSON to stdout.");
            println!("{}", json);
            Ok(())
        }
        (Some(canister_id), Some(pem_file)) => {
            upload_to_canister(canister_id, pem_file, replica_version, json).await
        }
        (None, Some(_)) => {
            bail!("Please specify the canister for uploading: --canister=<canister-id>")
        }
        (Some(_), None) => {
            bail!("Please specify the private key for uploading: --pem-file=<path>")
        }
    }
}

fn parse_args() -> ArgMatches {
    clap::Command::new("fees_and_limits")
        .about("A tool that extracts developer visible config parameters of the IC")
        .arg(
            Arg::new("canister-id")
                .long("canister-id")
                .takes_value(true)
                .help("The canister to which the data will be uploaded, for example: kbncd-2yaaa-aaaag-qctkq-cai"),
        )
        .arg(
            Arg::new("pem-file")
                .long("pem-file")
                .takes_value(true)
                .help("The file that contains the private key of the principal that will be used for uploading the data."),
        )
        .arg(
            Arg::new("replica-version")
                .long("replica-version")
                .required(true)
                .takes_value(true)
                .help("The replica version corresponding to the current build. It should be a full hash of a git commit, for example: 77a9c33164a923a73d9297445115d8142f5094d1"),
        )
        .get_matches()
}

async fn upload_to_canister(
    canister_id: &str,
    pem_file: &str,
    replica_version: &str,
    json: String,
) -> Result<()> {
    let canister_id = Principal::from_text(canister_id)?;
    let identity = Secp256k1Identity::from_pem_file(pem_file)?;
    let agent = Agent::builder()
        .with_url("https://icp0.io")
        .with_identity(identity)
        .build()?;
    agent.fetch_root_key().await?;

    let result = agent
        .update(&canister_id, "add")
        .with_arg(Encode!(&replica_version.to_string(), &json).unwrap())
        .call_and_wait()
        .await?;
    let result = Decode!(&result, String)?;
    println!("Response: {}", result);
    Ok(())
}

fn get_fees_and_limits() -> serde_json::Value {
    let embedder = embedders::Config::default();
    let execution = execution_environment::Config::default();

    let application = json_config(
        &CyclesAccountManagerConfig::application_subnet(),
        &SchedulerConfig::application_subnet(),
        &embedder,
        &execution,
    );

    let verified_application = json_config(
        &CyclesAccountManagerConfig::verified_application_subnet(),
        &SchedulerConfig::verified_application_subnet(),
        &embedder,
        &execution,
    );

    let system = json_config(
        &CyclesAccountManagerConfig::system_subnet(),
        &SchedulerConfig::system_subnet(),
        &embedder,
        &execution,
    );

    json!({
        "application:": application,
        "verified_application:": verified_application,
        "system:": system,
    })
}

fn json_config(
    cycles_account_manager: &CyclesAccountManagerConfig,
    scheduler: &ic_config::subnet_config::SchedulerConfig,
    embedder: &ic_config::embedders::Config,
    execution: &ic_config::execution_environment::Config,
) -> serde_json::Value {
    use ic_replicated_state::canister_state::DEFAULT_QUEUE_CAPACITY;
    use ic_system_api::MULTIPLIER_MAX_SIZE_LOCAL_SUBNET;
    use ic_types::messages::MAX_XNET_PAYLOAD_IN_BYTES;
    json!({
        "fees": serde_json::to_value(*cycles_account_manager).unwrap(),
        "embedder": serde_json::to_value(embedder.clone()).unwrap(),
        "execution": serde_json::to_value(execution.clone()).unwrap(),
        "scheduler": serde_json::to_value(scheduler.clone()).unwrap(),
        "messages": json!({
            "canister_queue_capacity": DEFAULT_QUEUE_CAPACITY,
            "max_ingress_payload_bytes": MAX_XNET_PAYLOAD_IN_BYTES.get(),
            "max_cross_subnet_call_payload_bytes": MAX_XNET_PAYLOAD_IN_BYTES.get(),
            "max_same_subnet_call_payload_bytes": MAX_XNET_PAYLOAD_IN_BYTES.get() * MULTIPLIER_MAX_SIZE_LOCAL_SUBNET,
        }),
    })
}
