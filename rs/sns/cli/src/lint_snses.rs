use anyhow::Result;
use clap::Parser;
use ic_agent::Agent;
use ic_nervous_system_agent::nns::sns_wasm;

/// The arguments used to configure the lint-snses command
#[derive(Debug, Parser)]
pub struct LintSnsesArgs {}

pub async fn exec(_args: LintSnsesArgs, agent: &Agent) -> Result<()> {
    println!("Checking SNSes...");
    let snses = sns_wasm::list_deployed_snses(agent).await?;
    for sns in snses {
        println!("==================");
        println!("{:?}", sns);
    }
    Ok(())
}
