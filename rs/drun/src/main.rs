use clap::{Arg, ArgMatches, Command};
use ic_drun::{run_drun, DrunOptions, SubnetType};
use std::path::PathBuf;

const ARG_MESSAGES: &str = "messages";
const ARG_LOG_FILE: &str = "log-file";
const ARG_CYCLES_USED_FILE: &str = "cycles-used-file";
const ARG_SUBNET_TYPE: &str = "subnet-type";

fn main() {
    let matches = get_arg_matches();

    let log_file = matches.value_of(ARG_LOG_FILE).map(PathBuf::from);
    let cycles_used_file = matches.value_of(ARG_CYCLES_USED_FILE).map(PathBuf::from);

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
        log_file,
        cycles_used_file,
        subnet_type,
    };
    run_drun(uo).unwrap()
}

fn get_arg_matches() -> ArgMatches {
    Command::new("ic standalone interface")
        .about("Standalone interface for testing application canisters.")
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
            Arg::new(ARG_CYCLES_USED_FILE)
                .long(ARG_CYCLES_USED_FILE)
                .value_name("cycles_used_file")
                .help(
                    "File containing cycles used by the canisters during the run (default: None).",
                )
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
