//! A command-line tool to initialize, deploy and interact with a SNS (Service Nervous System)

use anyhow::{Result, bail};
use clap::Parser;

use ic_sns_cli::{
    CliArgs, SubCommand, add_sns_wasm_for_tests, deploy_testflight, health, init_config_file, list,
    neuron_id_to_candid_subaccount, prepare_canisters, propose, register_extension,
    upgrade_sns_controlled_canister,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = match CliArgs::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            bail!("{}", e);
        }
    };

    let agent = args.agent().await?;

    match args.sub_command {
        SubCommand::DeployTestflight(args) => deploy_testflight(args),
        SubCommand::AddSnsWasmForTests(args) => add_sns_wasm_for_tests(args),
        SubCommand::InitConfigFile(args) => init_config_file::exec(args),
        SubCommand::PrepareCanisters(args) => prepare_canisters::exec(args),
        SubCommand::Propose(args) => propose::exec(args),
        SubCommand::NeuronIdToCandidSubaccount(args) => neuron_id_to_candid_subaccount::exec(args),
        SubCommand::List(args) => list::exec(args, &agent).await,
        SubCommand::Health(args) => health::exec(args, &agent).await,
        SubCommand::UpgradeSnsControlledCanister(args) => {
            match upgrade_sns_controlled_canister::exec(args, &agent).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    bail!("{}", err);
                }
            }
        }
        SubCommand::RegisterExtension(args) => match register_extension::exec(args, &agent).await {
            Ok(_) => Ok(()),
            Err(err) => {
                bail!("{}", err);
            }
        },
        SubCommand::RefundAfterSnsControlledCanisterUpgrade(args) => {
            match upgrade_sns_controlled_canister::refund(args, &agent).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    bail!("{}", err);
                }
            }
        }
    }
}
