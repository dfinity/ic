use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use dfx_core::config::model::network_descriptor::NetworkDescriptor;
use dfx_core::identity::identity_manager::InitializeIdentity;
use dfx_core::identity::IdentityManager;
use ic_agent::{
    agent::route_provider::RoundRobinRouteProvider, identity::Secp256k1Identity, Agent,
};
use ic_base_types::PrincipalId;
use ic_nervous_system_agent::nns::governance::list_neurons;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_ID;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::pb::v1::{ListNeurons, Neuron};
use k256::SecretKey;
use reqwest::Client;

pub const NNS_NEURON_ID: NeuronId = NeuronId {
    id: TEST_NEURON_1_ID,
};

pub async fn build_ephemeral_agent(
    secret_key: SecretKey,
    network_descriptor: &NetworkDescriptor,
) -> Result<Agent> {
    let identity = Secp256k1Identity::from_private_key(secret_key);
    let route_provider = RoundRobinRouteProvider::new(network_descriptor.providers.clone())?;
    let client = Client::builder().use_rustls_tls().build()?;

    let agent = Agent::builder()
        .with_http_client(client)
        .with_route_provider(route_provider)
        .with_identity(identity)
        .build()?;
    if !network_descriptor.is_ic {
        let name = network_descriptor.name.clone();
        agent
            .fetch_root_key()
            .await
            .context(format!("Failed to fetch root key from network `{name}`."))?;
    }
    Ok(agent)
}

pub async fn get_nns_neuron_hotkeys<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
) -> Result<Vec<PrincipalId>> {
    let request = ListNeurons {
        neuron_ids: vec![neuron_id.id],
        ..Default::default()
    };
    let response = list_neurons(agent, request).await.unwrap();
    let neuron: Vec<Neuron> = response
        .full_neurons
        .into_iter()
        .filter(|n| n.id == Some(neuron_id))
        .collect();
    neuron
        .first()
        .map(|n| n.hot_keys.clone())
        .ok_or_else(|| anyhow!("Neuron {:?} not found", neuron_id))
}

pub fn get_identity_principal(identity_name: &str) -> Result<PrincipalId> {
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let mut identity_manager = IdentityManager::new(&logger, None, InitializeIdentity::Disallow)?;
    identity_manager.instantiate_identity_from_name(identity_name, &logger)?;
    identity_manager
        .get_selected_identity_principal()
        .ok_or_else(|| anyhow!("Failed to get principal for identity `{}`", identity_name))
        .map(PrincipalId::from)
}
