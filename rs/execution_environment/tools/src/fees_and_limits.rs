use candid::{Decode, Encode};
use clap::{Arg, ArgMatches};
use eyre::{bail, Result};
use ic_agent::{export::Principal, identity::Secp256k1Identity, Agent};
use ic_config::subnet_config::CyclesAccountManagerConfig;
use serde_json::json;

// bazel run //rs/execution_environment:fees_and_limits -- --replica=<version> --canister=<canister-id> --pem-file=<path>
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
    let embedder_config = ic_config::embedders::Config::default();
    let subnet_config = ic_config::execution_environment::Config::default();
    json!({
        "fees": {
            "application": CyclesAccountManagerConfig::application_subnet(),
            "verified_application": CyclesAccountManagerConfig::verified_application_subnet(),
            "system": CyclesAccountManagerConfig::system_subnet(),
        },
        "limits": {
            "application:": get_limits(&ic_config::subnet_config::SchedulerConfig::application_subnet(), &embedder_config, &subnet_config),
            "verified_application:": get_limits(&ic_config::subnet_config::SchedulerConfig::verified_application_subnet(), &embedder_config, &subnet_config),
            "system:": get_limits(&ic_config::subnet_config::SchedulerConfig::system_subnet(), &embedder_config, &subnet_config),
        }
    })
}

fn get_limits(
    scheduler_config: &ic_config::subnet_config::SchedulerConfig,
    embedder_config: &ic_config::embedders::Config,
    subnet_config: &ic_config::execution_environment::Config,
) -> serde_json::Value {
    use ic_embedders::wasm_utils::validation::MAX_CODE_SECTION_SIZE_IN_BYTES;
    use ic_replicated_state::canister_state::DEFAULT_QUEUE_CAPACITY;
    use ic_system_api::MULTIPLIER_MAX_SIZE_LOCAL_SUBNET;
    use ic_types::messages::MAX_XNET_PAYLOAD_IN_BYTES;
    use ic_types::{MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES};
    json!({
        "CANISTER_QUEUE_LIMIT": DEFAULT_QUEUE_CAPACITY,
        "MAX_INGRESS_PAYLOAD_BYTES": MAX_XNET_PAYLOAD_IN_BYTES.get(),
        "MAX_SAME_SUBNET_CALL_BYTES": MAX_XNET_PAYLOAD_IN_BYTES.get() * MULTIPLIER_MAX_SIZE_LOCAL_SUBNET,
        "MAX_RESPONSE_SIZE_BYTES": MAX_XNET_PAYLOAD_IN_BYTES.get(), // The same as for ingress payload size?
        "MAX_INSTRUCTIONS_PER_UPDATE_TIMER_HEARTBEAT": (scheduler_config.max_instructions_per_message.get()),
        "MAX_INSTRUCTIONS_PER_QUERY": scheduler_config.max_instructions_per_message_without_dts.get(), // See setup_execution in execution_environment/src/lib.rs,
        "MAX_INSTRUCTIONS_CANISTER_INSTALL": scheduler_config.max_instructions_per_install_code.get(),
        "SUBNET_MEMORY_CAPACITY": subnet_config.subnet_memory_capacity.get(),
        "MAX_STABLE_MEMORY_IN_BYTES": MAX_STABLE_MEMORY_IN_BYTES,
        "MAX_WASM_MEMORY_IN_BYTES": MAX_WASM_MEMORY_IN_BYTES,
        // custom section: global, per canister, sections per canister
        "WASM_CUSTOM_SECTIONS": (
            subnet_config.subnet_wasm_custom_sections_memory_capacity.get(),
            embedder_config.max_custom_sections_size.get(),
            embedder_config.max_custom_sections
        ),
        "WASM_CODE_SECTION_BYTES": MAX_CODE_SECTION_SIZE_IN_BYTES,
        "NUMBER_QUERY_EXECUTION_THREADS": (scheduler_config.scheduler_cores, embedder_config.query_execution_threads_per_canister),
        "NUMBER_UPDATE_EXECUTION_THREADS": scheduler_config.scheduler_cores,
        // Other limits
        "MAX_FUNCTIONS": embedder_config.max_functions,
        "MAX_GLOBALS": embedder_config.max_globals,
        "MAX_EXPORTED_FUNCTIONS": embedder_config.max_number_exported_functions,
        "MAX_SUM_EXPORTED_FUNCTION_NAME_LENGTHS": embedder_config.max_sum_exported_function_name_lengths,
        "MAX_CUSTOM_SECTIONS_SIZE": embedder_config.max_custom_sections_size.get(),
    })
}
