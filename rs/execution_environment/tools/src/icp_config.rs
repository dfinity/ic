use clap::{Arg, ArgMatches};
use eyre::Result;
use ic_config::{
    embedders, execution_environment,
    subnet_config::{CyclesAccountManagerConfig, SchedulerConfig},
};
use serde_json::json;

// bazel run //rs/execution_environment/tools:icp_config -- --replica-version=<version> --output=<file-name>
fn main() -> Result<()> {
    let args = parse_args();
    let replica_version = args.get_one::<String>("replica-version").unwrap();
    let output = args.get_one::<String>("output");

    let json = serde_json::to_string_pretty(&icp_config_as_json(replica_version))?;
    match output {
        None => {
            println!("{json}");
        }
        Some(filename) => {
            let path = std::fs::canonicalize(filename)?;
            std::fs::write(path.clone(), json)?;
            println!("Wrote ICP config to {path:?}");
        }
    }
    Ok(())
}

fn parse_args() -> ArgMatches {
    clap::Command::new("icp_config")
        .about("A tool that extracts developer visible config parameters of ICP")
        .arg(
            Arg::new("replica-version")
                .long("replica-version")
                .required(true)
                .num_args(1)
                .help("The replica version corresponding to the current build. For example: rc--2024-07-25_01-30"),
        ).arg(
            Arg::new("output")
                .long("output")
                .required(false)
                .num_args(1)
                .help("The name of the output file. Use absolute path to avoid bazel working directory."),
        )
        .get_matches()
}

fn icp_config_as_json(version: &str) -> serde_json::Value {
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
        "version": version,
        "application": application,
        "verified_application": verified_application,
        "system": system,
    })
}

fn json_config(
    cycles_account_manager: &CyclesAccountManagerConfig,
    scheduler: &ic_config::subnet_config::SchedulerConfig,
    embedder: &ic_config::embedders::Config,
    execution: &ic_config::execution_environment::Config,
) -> serde_json::Value {
    use ic_embedders::wasmtime_embedder::system_api::MULTIPLIER_MAX_SIZE_LOCAL_SUBNET;
    use ic_replicated_state::canister_state::DEFAULT_QUEUE_CAPACITY;
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
