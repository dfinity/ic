//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

use anyhow::{bail, Result};
use clap::Parser;

use ic_sns_cli::{
    add_sns_wasm_for_tests, deploy_testflight, init_config_file, list,
    neuron_id_to_candid_subaccount, prepare_canisters, propose, CliArgs, SubCommand,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = match CliArgs::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            bail!("{}", e);
        }
    };

    let agent = args.agent()?;

    match args.sub_command {
        SubCommand::DeployTestflight(args) => deploy_testflight(args),
        SubCommand::AddSnsWasmForTests(args) => add_sns_wasm_for_tests(args),
        SubCommand::InitConfigFile(args) => init_config_file::exec(args),
        SubCommand::PrepareCanisters(args) => prepare_canisters::exec(args),
        SubCommand::Propose(args) => propose::exec(args),
        SubCommand::NeuronIdToCandidSubaccount(args) => neuron_id_to_candid_subaccount::exec(args),
        SubCommand::List(args) => list::exec(args, &agent).await,
    }
}
