use clap::{Arg, ArgMatches, Command};
use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use ic_config::{flag_status::FlagStatus, Config, ConfigSource};
use ic_drun::{run_drun, DrunOptions};
use ic_registry_subnet_type::SubnetType;
use ic_types::NumBytes;
use std::path::PathBuf;

const DEFAULT_CONFIG_FILE: &str = "ic.json5";
const DEFAULT_EXTRA_BATCHES: u64 = 0;
const ARG_CONF: &str = "config";
const ARG_LOG_FILE: &str = "log-file";
const ARG_MESSAGES: &str = "messages";
const ARG_EXTRA_BATCHES: &str = "extra-batches";
const ARG_INSTRUCTION_LIMIT: &str = "instruction-limit";
const ARG_SUBNET_TYPE: &str = "subnet-type";

const GB: u64 = 1024 * 1024 * 1024;
const MAIN_MEMORY_CAPACITY: NumBytes = NumBytes::new(16 * GB);

fn main() -> Result<(), String> {
    // Check if `drun` is running in the canister sandbox mode where it waits
    // for commands from the parent process. This check has to be performed
    // before the arguments are parsed because the parent process does not pass
    // all the normally required arguments of `drun`.
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
        Ok(())
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        sandbox_launcher_main();
        Ok(())
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        compiler_sandbox_main();
        Ok(())
    } else {
        drun_main()
    }
}

#[tokio::main]
async fn drun_main() -> Result<(), String> {
    let matches = get_arg_matches();
    Config::run_with_temp_config(|mut default_config| async {
        let source = matches
            .value_of(ARG_CONF)
            .map(|arg| ConfigSource::File(PathBuf::from(arg)))
            .unwrap_or(ConfigSource::Default);
        let hypervisor_config = &mut default_config.hypervisor;

        // Enable composite queries in drun by default to allow local
        // development and testing.
        hypervisor_config.composite_queries = FlagStatus::Enabled;
        hypervisor_config
            .embedders_config
            .feature_flags
            .rate_limiting_of_debug_prints = FlagStatus::Disabled;
        hypervisor_config.rate_limiting_of_heap_delta = FlagStatus::Disabled;
        hypervisor_config.rate_limiting_of_instructions = FlagStatus::Disabled;
        hypervisor_config.canister_snapshots = FlagStatus::Enabled;
        // For testing enhanced orthogonal persistence in Motoko,
        // enable Wasm Memory64 and re-configure the main memory capacity.
        hypervisor_config.embedders_config.feature_flags.wasm64 = FlagStatus::Enabled;
        hypervisor_config.embedders_config.max_wasm_memory_size = MAIN_MEMORY_CAPACITY;
        hypervisor_config.max_canister_memory_size =
            hypervisor_config.embedders_config.max_wasm_memory_size
                + hypervisor_config.embedders_config.max_stable_memory_size;

        let cfg = Config::load_with_default(&source, default_config).unwrap_or_else(|err| {
            eprintln!("Failed to load config:\n  {}", err);
            std::process::exit(1);
        });

        let log_file = matches.value_of(ARG_LOG_FILE).map(PathBuf::from);

        let extra_batches = matches
            .value_of(ARG_EXTRA_BATCHES)
            .map(|arg| {
                arg.parse().unwrap_or_else(|err| {
                    eprintln!("Failed to parse {}\n  {}", ARG_EXTRA_BATCHES, err);
                    std::process::exit(1);
                })
            })
            .unwrap_or(DEFAULT_EXTRA_BATCHES);

        let instruction_limit = matches.value_of(ARG_INSTRUCTION_LIMIT).map(|arg| {
            arg.parse().unwrap_or_else(|err| {
                eprintln!("Failed to parse {}\n  {}", ARG_INSTRUCTION_LIMIT, err);
                std::process::exit(1);
            })
        });

        let subnet_type = matches
            .value_of(ARG_SUBNET_TYPE)
            .map(|arg| {
                arg.parse().unwrap_or_else(|err| {
                    eprintln!("Failed to parse {}\n  {}", ARG_SUBNET_TYPE, err);
                    std::process::exit(1);
                })
            })
            .unwrap_or(SubnetType::System);

        let uo = DrunOptions {
            msg_filename: matches.value_of(ARG_MESSAGES).unwrap().to_string(),
            cfg,
            extra_batches,
            log_file,
            instruction_limit,
            subnet_type,
        };
        run_drun(uo).await
    })
    .await
}

fn get_arg_matches() -> ArgMatches {
    Command::new("ic standalone interface")
        .about("Standalone interface for testing application canisters.")
        .arg(
            Arg::new(ARG_EXTRA_BATCHES)
                .long("extra-batches")
                .value_name("INT")
                .help(
                    format!(
                    "Extra batches to execute after each response has been received (default: {}).",
                    DEFAULT_EXTRA_BATCHES
                )
                    .as_str(),
                )
                .takes_value(true),
        )
        .arg(
            Arg::new(ARG_CONF)
                .short('c')
                .long("config")
                .value_name("config")
                .help(
                    format!(
                        "Main configuration of the node (default: {}).",
                        DEFAULT_CONFIG_FILE
                    )
                    .as_str(),
                )
                .takes_value(true),
        )
        .arg(
            Arg::new(ARG_MESSAGES)
                .required(true)
                .value_name("Query/Ingress Messages")
                .help("Text file containing one message per line."),
        )
        .arg(
            Arg::new(ARG_LOG_FILE)
                .long(ARG_LOG_FILE)
                .value_name("log_file")
                .help("Log file for the run (default: None).")
                .takes_value(true),
        )
        .arg(
            Arg::new(ARG_INSTRUCTION_LIMIT)
                .long(ARG_INSTRUCTION_LIMIT)
                .value_name("Instruction Limit")
                .help("Limit on the number of instructions a message is allowed to execute.")
                .takes_value(true),
        )
        .arg(
            Arg::new(ARG_SUBNET_TYPE)
                .long(ARG_SUBNET_TYPE)
                .help("Use specified subnet type.")
                .value_name("Subnet Type")
                .takes_value(true),
        )
        .get_matches()
}
