use crate::table::{as_table, TableRow};
use anyhow::Result;
use clap::Parser;
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_nervous_system_agent::{nns::sns_wasm, sns::Sns};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Output the SNS information as JSON (instead of a human-friendly table).
    #[clap(long)]
    json: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnsWithMetadata {
    name: String,
    sns: Sns,
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
    let snses = sns_wasm::list_deployed_snses(agent).await?;
    let snses_with_metadata = stream::iter(snses)
        .map(|sns| async move {
            let metadata = sns.governance.metadata(agent).await?;
            Ok((sns, metadata))
        })
        .buffer_unordered(10) // Do up to 10 requests at a time in parallel
        .collect::<Vec<anyhow::Result<_>>>()
        .await;
    let snses_with_metadata = snses_with_metadata
        .into_iter()
        .filter_map(Result::ok)
        .map(|(sns, metadata)| {
            let name = metadata.name.unwrap_or_else(|| "Unknown".to_string());
            SnsWithMetadata { name, sns }
        })
        .sorted_by(|a, b| a.name.cmp(&b.name))
        .collect::<Vec<_>>();

    let output = if args.json {
        serde_json::to_string(&snses_with_metadata).unwrap()
    } else {
        as_table(snses_with_metadata.as_ref())
    };

    println!("{}", output);

    Ok(())
}
