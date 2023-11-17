use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_embedders::wasm_utils::validation::MAX_CODE_SECTION_SIZE_IN_BYTES;
use ic_replicated_state::canister_state::DEFAULT_QUEUE_CAPACITY;
use ic_system_api::MULTIPLIER_MAX_SIZE_LOCAL_SUBNET;
use ic_types::messages::MAX_XNET_PAYLOAD_IN_BYTES;
use ic_types::{MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES};
use serde_json::json;

use std::process::Command;

fn get_limits(
    scheduler_config: &ic_config::subnet_config::SchedulerConfig,
    embedder_config: &ic_config::embedders::Config,
    subnet_config: &ic_config::execution_environment::Config,
) -> serde_json::Value {
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

// bazel run //rs/execution_environment:fees_and_limits
fn main() {
    let embedder_config = ic_config::embedders::Config::default();
    let subnet_config = ic_config::execution_environment::Config::default();

    let replica_version = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .expect("Failed to get git revision of current HEAD");

    let json = json!({
        "replica": String::from_utf8(replica_version.stdout).expect("Commandd output is not utf-8"),
        "costs": {
            "application": CyclesAccountManagerConfig::application_subnet(),
            "verified_application": CyclesAccountManagerConfig::verified_application_subnet(),
            "system": CyclesAccountManagerConfig::system_subnet(),
        },
        "limits": {
            "application:": get_limits(&ic_config::subnet_config::SchedulerConfig::application_subnet(), &embedder_config, &subnet_config),
            "verified_application:": get_limits(&ic_config::subnet_config::SchedulerConfig::verified_application_subnet(), &embedder_config, &subnet_config),
            "system:": get_limits(&ic_config::subnet_config::SchedulerConfig::system_subnet(), &embedder_config, &subnet_config),
        }
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
