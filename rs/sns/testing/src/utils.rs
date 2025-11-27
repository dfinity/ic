use anyhow::{Result, anyhow};
use dfx_core::identity::IdentityManager;
use dfx_core::identity::identity_manager::InitializeIdentity;
use futures::future::join_all;
use ic_agent::Identity;
use ic_agent::{Agent, identity::Secp256k1Identity};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_agent::nns::governance::list_neurons;
use ic_nervous_system_agent::nns::ledger::transfer;
use ic_nervous_system_agent::nns::sns_wasm::{get_latest_sns_version_pretty, get_sns_subnet_ids};
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LEDGER_INDEX_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_WASM_CANISTER_ID, canister_id_to_nns_canister_name,
};
use ic_nns_governance_api::{ListNeurons, Neuron};
use icp_ledger::{AccountIdBlob, DEFAULT_TRANSFER_FEE, Memo, Tokens, TransferArgs, TransferError};
use k256::SecretKey;
use lazy_static::lazy_static;
use thiserror::Error;

pub const ALL_SNS_TESTING_CANISTER_IDS: [&CanisterId; 8] = [
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
    &ROOT_CANISTER_ID,
    &SNS_WASM_CANISTER_ID,
    &REGISTRY_CANISTER_ID,
    &CYCLES_MINTING_CANISTER_ID,
    &LEDGER_INDEX_CANISTER_ID,
    &CYCLES_LEDGER_CANISTER_ID,
];

/// The default NNS neuron ID used during NNS bootstrap and NNS proposal submission.
pub const DEFAULT_POWERFUL_NNS_NEURON_ID: NeuronId = NeuronId { id: 1 };

// Predefined secret keys used in sns-testing
lazy_static! {
    pub static ref TREASURY_SECRET_KEY: SecretKey = {
        let mut slice_vec = vec![0; 16];
        slice_vec.extend_from_slice(&200_usize.to_ne_bytes());
        SecretKey::from_slice(&slice_vec).unwrap()
    };
    pub static ref TREASURY_PRINCIPAL_ID: PrincipalId = {
        let identity = Secp256k1Identity::from_private_key(TREASURY_SECRET_KEY.clone());
        identity.sender().unwrap().into()
    };
}

/// Trait that allows to build ephemeral agents with a given secret key based on the provided agent.
///
/// "Ephemeral" agents are used for testing purposes and do not necessarily have a DFX identity
/// associated with them.
pub trait BuildEphemeralAgent {
    fn build_ephemeral_agent(&self, secret_key: SecretKey) -> Self;
}

impl<'a> BuildEphemeralAgent for PocketIcAgent<'a> {
    fn build_ephemeral_agent(&self, secret_key: SecretKey) -> PocketIcAgent<'a> {
        let principal = Secp256k1Identity::from_private_key(secret_key)
            .sender()
            .unwrap();
        PocketIcAgent::new(self.pocket_ic, principal)
    }
}

impl BuildEphemeralAgent for Agent {
    fn build_ephemeral_agent(&self, secret_key: SecretKey) -> Agent {
        let identity = Secp256k1Identity::from_private_key(secret_key);
        let mut agent = self.clone();
        agent.set_identity(identity);
        agent
    }
}

/// Function that creates a vector of ephemeral agents with unique determenistically
/// generated secret keys.
///
/// The function takes the following parameters:
/// 1) agent - The agent used to provide IC network connection info.
/// 2) number_of_participants - The number of participants to create ephemeral agents for.
pub fn build_ephemeral_agents<C: BuildEphemeralAgent>(
    agent: &C,
    number_of_participants: usize,
) -> Vec<C> {
    (0..number_of_participants)
        .map(|i| {
            let mut slice_vec = vec![0; 16];
            slice_vec.extend_from_slice(&(100 + i).to_ne_bytes());
            let secret_key = SecretKey::from_slice(&slice_vec).unwrap();
            agent.build_ephemeral_agent(secret_key)
        })
        .collect()
}

pub async fn get_nns_neuron_hotkeys<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
) -> Result<Vec<PrincipalId>> {
    let request = ListNeurons {
        neuron_ids: vec![neuron_id.id],
        ..Default::default()
    };
    let response = list_neurons(agent, request)
        .await
        .map_err(|err| anyhow!("Failed to list neurons {}", err))?;
    let neuron: Vec<Neuron> = response
        .full_neurons
        .into_iter()
        .filter(|n| n.id == Some(neuron_id))
        .collect();
    Ok(neuron.iter().flat_map(|n| n.hot_keys.clone()).collect())
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
    #[error("SNS WASM doesn't have all SNS WASM modules")]
    MissingSnsWasmModules,
    #[error("Failed to get the latest SNS version from SNS WASM: {0}")]
    FailedToGetLatestSnsVersion(String),
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
        ALL_SNS_TESTING_CANISTER_IDS
            .iter()
            .map(|canister_id| async { check_canister_installed(agent, canister_id).await }),
    )
    .await;
    let (_, validation_errors): (Vec<_>, Vec<_>) = ALL_SNS_TESTING_CANISTER_IDS
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

    match get_latest_sns_version_pretty(agent).await {
        Ok(response) => {
            if response
                .iter()
                .any(|(_canister, wasm_hash)| wasm_hash.is_empty())
            {
                validation_errors.push(SnsTestingNetworkValidationError::MissingSnsWasmModules);
            }
        }
        Err(err) => {
            validation_errors.push(
                SnsTestingNetworkValidationError::FailedToGetLatestSnsVersion(err.to_string()),
            );
        }
    }
    validation_errors
}

// Function that validates that provided canister is suitable to be controlled by SNS.
// It ensures that canister exists, is installed and controlled by the NNS Root canister.
pub async fn validate_target_canister<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
) -> Vec<SnsTestingCanisterValidationError> {
    let mut validation_errors = vec![];
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

/// This function performs a transfer of ICP tokens from the treasury account whose identity
/// is either provided by the `agent` or the `TREASURY_PRINCIPAL_ID based on the provided
/// `use_ephemeral_icp_treasury` argument.
///
/// The function takes the following parameters:
/// 1) agent - The agent used to provide IC network connection info
///    and optionally the identity of the treasury account if `use_ephemeral_icp_treasury`
///    argument is `false`.
/// 2) use_ephemeral_icp_treasury - If `true`, the function will use the ephemeral agent
///    with the hardcoded `TREASURY_PRINCIPAL_ID` to perform the transfer.
/// 3) to - The recipient of the transfer.
/// 4) amount - The amount of ICP tokens to transfer.
pub async fn transfer_icp_from_treasury<C: CallCanisters + BuildEphemeralAgent>(
    agent: &C,
    use_ephemeral_icp_treasury: bool,
    to: AccountIdBlob,
    amount: Tokens,
) -> Result<u64, TransferError> {
    let treasury_agent = if use_ephemeral_icp_treasury {
        &agent.build_ephemeral_agent(TREASURY_SECRET_KEY.clone())
    } else {
        agent
    };
    transfer(
        treasury_agent,
        TransferArgs {
            to,
            amount,
            fee: DEFAULT_TRANSFER_FEE,
            memo: Memo(0),
            from_subaccount: None,
            created_at_time: None,
        },
    )
    .await
    .unwrap()
}
