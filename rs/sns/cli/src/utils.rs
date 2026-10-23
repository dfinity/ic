use anyhow::Context;
use anyhow::Result;
use futures::{StreamExt, stream};
use ic_agent::Agent;
use ic_nervous_system_agent::sns::Sns;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// Gets an agent for a given network and identity. This is similar to the code DFX uses internally to get an agent.
/// If no identity is provided, it will use the identity currently selected in the DFX CLI.
pub async fn get_agent(network_name: &str, identity: Option<String>) -> Result<Agent> {
    dfx_core_vendored::get_agent(network_name, identity.clone())
        .await
        .with_context(|| {
            format!(
                "Failed to build agent for network `{network_name}` and identity `{identity:?}`"
            )
        })
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
