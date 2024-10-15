use anyhow::{anyhow, Result};
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_nervous_system_agent::sns::Sns;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

fn get_agent(ic_url: &str) -> Result<Agent> {
    Agent::builder()
        .with_url(ic_url)
        .with_verify_query_signatures(false)
        .build()
        .map_err(|e| anyhow!(e))
}

pub fn get_mainnet_agent() -> Result<Agent> {
    let ic_url = "https://ic0.app/";
    get_agent(ic_url)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SnsWithMetadata {
    pub(crate) name: String,
    pub(crate) sns: Sns,
}

pub(crate) async fn get_snses_with_metadata(
    agent: &Agent,
    snses: Vec<Sns>,
) -> Vec<SnsWithMetadata> {
    let snses_with_metadata = stream::iter(snses)
        .map(|sns| async move {
            let metadata = sns.governance.metadata(agent).await?;
            Ok((sns, metadata))
        })
        .buffer_unordered(10) // Do up to 10 requests at a time in parallel
        .collect::<Vec<anyhow::Result<_>>>()
        .await;
    snses_with_metadata
        .into_iter()
        .filter_map(Result::ok)
        .map(|(sns, metadata)| {
            let name = metadata.name.unwrap_or_else(|| "Unknown".to_string());
            SnsWithMetadata { name, sns }
        })
        .sorted_by(|a, b| a.name.cmp(&b.name))
        .collect::<Vec<_>>()
}
