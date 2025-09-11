use crate::table::{TableRow, as_table};
use crate::utils::{SnsWithMetadata, get_snses_with_metadata};
use anyhow::Result;
use clap::Parser;
use ic_agent::Agent;
use ic_nervous_system_agent::nns::sns_wasm;

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Output the SNS information as JSON (instead of a human-friendly table).
    #[clap(long)]
    json: bool,
}

impl TableRow for SnsWithMetadata {
    fn column_names() -> Vec<&'static str> {
        vec!["name", "ledger", "governance", "index", "swap", "root"]
    }

    fn column_values(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.sns.ledger.canister_id.to_string(),
            self.sns.governance.canister_id.to_string(),
            self.sns.index.canister_id.to_string(),
            self.sns.swap.canister_id.to_string(),
            self.sns.root.canister_id.to_string(),
        ]
    }
}

pub async fn exec(args: ListArgs, agent: &Agent) -> Result<()> {
    eprintln!("Listing SNSes...");

    let snses = sns_wasm::list_deployed_snses(agent).await?;
    let snses_with_metadata = get_snses_with_metadata(agent, snses).await;

    let output = if args.json {
        serde_json::to_string(&snses_with_metadata).unwrap()
    } else {
        as_table(snses_with_metadata.as_ref())
    };

    println!("{output}");

    Ok(())
}
