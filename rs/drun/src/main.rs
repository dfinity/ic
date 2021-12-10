use clap::{App, Arg, ArgMatches};
use ic_canister_sandbox_backend_lib::{canister_sandbox_main, RUN_AS_CANISTER_SANDBOX_FLAG};
use ic_config::{Config, ConfigSource};
use ic_drun::{run_drun, DrunOptions};
use std::path::PathBuf;

const DEFAULT_CONFIG_FILE: &str = "ic.toml";
const DEFAULT_EXTRA_BATCHES: u64 = 0;
const ARG_CONF: &str = "config";
const ARG_LOG_FILE: &str = "log-file";
const ARG_MESSAGES: &str = "messages";
const ARG_EXTRA_BATCHES: &str = "extra-batches";

fn main() -> Result<(), String> {
    // Check if `drun` is running in the canister sandbox mode where it waits
    // for commands from the parent process. This check has to be performed
    // before the arguments are parsed because the parent process does not pass
    // all the normally required arguments of `drun`.
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        canister_sandbox_main();
        Ok(())
    } else {
        drun_main()
    }
}

#[tokio::main]
async fn drun_main() -> Result<(), String> {
    let matches = get_arg_matches();
    Config::run_with_temp_config(|default_config| {
        let source = matches
            .value_of(ARG_CONF)
            .map(|arg| ConfigSource::File(PathBuf::from(arg)))
            .unwrap_or(ConfigSource::Default);
        let cfg = Config::load_with_default(&source, default_config).unwrap_or_else(|err| {
            eprintln!("Failed to load config:\n  {}", err);
            std::process::exit(1);
        });

        let log_file = matches.value_of(ARG_LOG_FILE).map(PathBuf::from);

        let extra_batches = matches
            .value_of(ARG_EXTRA_BATCHES)
            .map(|arg| {
                arg.parse().unwrap_or_else(|err| {
                    eprintln!("Failed to parse ARG_EXTRA_BATCHES\n  {}", err);
                    std::process::exit(1);
                })
            })
            .unwrap_or(DEFAULT_EXTRA_BATCHES);

        let uo = DrunOptions {
            msg_filename: matches.value_of(ARG_MESSAGES).unwrap().to_string(),
            cfg,
            extra_batches,
            log_file,
        };
        run_drun(uo)
    })
}

fn get_arg_matches() -> ArgMatches<'static> {
    App::new("ic standalone interface")
        .about("Standalone interface for testing application canisters.")
        .arg(
            Arg::with_name(ARG_EXTRA_BATCHES)
                .long("extra-batches")
                .value_name("INT")
                .help(&format!(
                    "Extra batches to execute after each response has been received (default: {}).",
                    DEFAULT_EXTRA_BATCHES
                ))
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_CONF)
                .short("c")
                .long("config")
                .value_name("config")
                .help(&format!(
                    "Main configuration of the node (default: {}).",
                    DEFAULT_CONFIG_FILE
                ))
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_MESSAGES)
                .required(true)
                .value_name("Query/Ingress Messages")
                .help("Text file containing one message per line."),
        )
        .arg(
            Arg::with_name(ARG_LOG_FILE)
                .long(ARG_LOG_FILE)
                .value_name("log_file")
                .help("Log file for the run (default: None).")
                .takes_value(true),
        )
        .get_matches()
}
