//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

use clap::Parser;

use ic_sns_cli::{
    add_sns_wasm_for_tests, deploy_testflight, init_config_file, prepare_canisters, propose,
    CliArgs, SubCommand,
};

fn main() {
    let args = match CliArgs::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    match args.sub_command {
        SubCommand::DeployTestflight(args) => deploy_testflight(args),
        SubCommand::AddSnsWasmForTests(args) => add_sns_wasm_for_tests(args),
        SubCommand::InitConfigFile(args) => init_config_file::exec(args),
        SubCommand::PrepareCanisters(args) => prepare_canisters::exec(args),
        SubCommand::Propose(args) => propose::exec(args),
    }
}
