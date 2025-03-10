use anyhow::{anyhow, Context, Result};
use dfx_core::config::model::network_descriptor::NetworkDescriptor;
use dfx_core::identity::identity_manager::InitializeIdentity;
use dfx_core::identity::IdentityManager;
use futures::future::join_all;
use ic_agent::{
    agent::route_provider::RoundRobinRouteProvider, identity::Secp256k1Identity, Agent,
};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_nervous_system_agent::nns::governance::list_neurons;
use ic_nervous_system_agent::nns::sns_wasm::get_sns_subnet_ids;
use ic_nervous_system_agent::nns::sns_wasm::list_upgrade_steps;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_ID;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    canister_id_to_nns_canister_name, CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LEDGER_INDEX_CANISTER_ID, LIFELINE_CANISTER_ID,
    REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::{ListNeurons, Neuron};
use k256::SecretKey;
use reqwest::Client;
use thiserror::Error;

pub const ALL_NNS_CANISTER_IDS: [&CanisterId; 9] = [
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
    &ROOT_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
    &SNS_WASM_CANISTER_ID,
    &REGISTRY_CANISTER_ID,
    &CYCLES_MINTING_CANISTER_ID,
    &LEDGER_INDEX_CANISTER_ID,
    &CYCLES_LEDGER_CANISTER_ID,
];

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

pub async fn check_canister_installed<C: CallCanisters>(
    agent: &C,
    canister_id: &CanisterId,
) -> bool {
    agent
        .canister_info(*canister_id)
        .await
        .map(|canister_info| canister_info.module_hash.is_some())
        .unwrap_or_default()
}

#[derive(Error, Debug, PartialEq)]
pub enum SnsTestingNetworkValidationError {
    #[error("NNS canister '{0}' is missing")]
    MissingNnsCanister(String),
    #[error("Network does not have any SNS subnets")]
    MissingSnsSubnets,
    #[error("Failed to get SNS subnet IDs: {0}")]
    FailedToGetSnsSubnetIds(String),
    #[error("SNS WASM doesn't have any upgrade steps")]
    MissingSnsWasmUpgradeSteps,
    #[error("Failed to get SNS WASM upgrade steps: {0}")]
    FailedToGetSnsWasmUpgradeSteps(String),
}

#[derive(Error, Debug, PartialEq)]
pub enum SnsTestingCanisterValidationError {
    #[error("Canister {0} is not installed")]
    CanisterNotInstalled(CanisterId),
    #[error("Canister {0} is not controlled by the NNS Root canister")]
    CanisterNotControlledByNnsRoot(CanisterId),
    #[error("Failed to get canister '{0}' info: {1}")]
    FailedToGetCanisterInfo(CanisterId, String),
}

// Function that validates the provided IC network setup.
// It ensures that all required NNS canisters exist and are installed
// and the network has at least one SNS subnet.
pub async fn validate_network<C: CallCanisters>(
    agent: &C,
) -> Vec<SnsTestingNetworkValidationError> {
    let canisters_installed = join_all(
        ALL_NNS_CANISTER_IDS
            .iter()
            .map(|canister_id| async { check_canister_installed(agent, canister_id).await }),
    )
    .await;
    let (_, validation_errors): (Vec<_>, Vec<_>) = ALL_NNS_CANISTER_IDS
        .iter()
        .zip(canisters_installed)
        .map(|(canister_id, installed)| {
            if !installed {
                Err(SnsTestingNetworkValidationError::MissingNnsCanister(
                    canister_id_to_nns_canister_name(**canister_id),
                ))
            } else {
                Ok(())
            }
        })
        .partition(Result::is_ok);
    let mut validation_errors: Vec<SnsTestingNetworkValidationError> = validation_errors
        .into_iter()
        .map(Result::unwrap_err)
        .collect();
    match get_sns_subnet_ids(agent).await {
        Ok(response) => {
            if response.sns_subnet_ids.is_empty() {
                validation_errors.push(SnsTestingNetworkValidationError::MissingSnsSubnets);
            }
        }
        Err(err) => {
            validation_errors.push(SnsTestingNetworkValidationError::FailedToGetSnsSubnetIds(
                err.to_string(),
            ));
        }
    }

    match list_upgrade_steps(agent, None, None, 0).await {
        Ok(response) => {
            if response.steps.is_empty() {
                validation_errors
                    .push(SnsTestingNetworkValidationError::MissingSnsWasmUpgradeSteps);
            }
        }
        Err(err) => {
            validation_errors.push(
                SnsTestingNetworkValidationError::FailedToGetSnsWasmUpgradeSteps(err.to_string()),
            );
        }
    }
    validation_errors
}

// Function that validates that provided canister is suitable to be used in SNS.
// It ensures that canister exists, is installed and controlled by the NNS Root canister.
pub async fn validate_target_canister<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
) -> Vec<SnsTestingCanisterValidationError> {
    let mut validation_errors = vec![];
    // let canister_info = agent.canister_info(canister_id).await;
    match agent.canister_info(canister_id).await {
        Ok(canister_info) => {
            if canister_info.module_hash.is_none() {
                validation_errors.push(SnsTestingCanisterValidationError::CanisterNotInstalled(
                    canister_id,
                ));
            }
            if !canister_info
                .controllers
                .contains(&ROOT_CANISTER_ID.get().into())
            {
                validation_errors.push(
                    SnsTestingCanisterValidationError::CanisterNotControlledByNnsRoot(canister_id),
                );
            }
        }
        Err(err) => {
            validation_errors.push(SnsTestingCanisterValidationError::FailedToGetCanisterInfo(
                canister_id,
                err.to_string(),
            ));
        }
    }
    validation_errors
}
