use anyhow::Context;
use anyhow::Result;
use dfx_core::interface::{builder::IdentityPicker, dfx::DfxInterface};
use futures::{StreamExt, stream};
use ic_agent::Agent;
use ic_nervous_system_agent::sns::Sns;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// Gets an agent for a given network and identity. This is similar to the code DFX uses internally to get an agent.
/// If no identity is provided, it will use the identity currently selected in the DFX CLI.
pub async fn get_agent(network_name: &str, identity: Option<String>) -> Result<Agent> {
    let interface = dfx_interface(network_name, identity)
        .await
        .context("Failed to get dfx interface")?;
    Ok(interface.agent().clone())
}

/// Gets a dfx interface for a given network and identity. This is similar to the code DFX uses internally to build the interface.
/// So this function allows the DFX SNS Extension to use the same interface as DFX itself.
/// If no identity is provided, it will use the identity currently selected in the DFX CLI.
pub async fn dfx_interface(network_name: &str, identity: Option<String>) -> Result<DfxInterface> {
    let interface_builder = {
        let identity = identity
            .clone()
            .map(IdentityPicker::Named)
            .unwrap_or(IdentityPicker::Selected);
        DfxInterface::builder()
            .with_identity(identity)
            .with_network_named(network_name)
    };
    let interface = interface_builder.build().await.context(format!(
        "Failed to build dfx interface with network `{network_name}` and identity `{identity:?}`"
    ))?;
    if !interface.network_descriptor().is_ic {
        interface.agent().fetch_root_key().await.context(format!(
            "Failed to fetch root key from network `{network_name}`."
        ))?;
    }
    Ok(interface)
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
