use ic_agent::{Agent, Certificate, export::Principal, hash_tree::Label, lookup_value};
use ic_base_types::SubnetId;
use ic_crypto_utils_threshold_sig_der::{parse_threshold_sig_key, public_key_to_der};
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_bytes, write_bytes},
    util::{block_on, write_public_key_to_file},
};
use slog::{Logger, debug, info};
use url::Url;

use std::{fmt::Display, path::Path};

const NNS_REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";

const SUBNET_LABEL: &[u8] = b"subnet";
const PUBLIC_KEY_LABEL: &[u8] = b"public_key";
const CANISTER_RANGES_LABEL: &[u8] = b"canister_ranges";

type StorageType = Vec<u8>;

/// Wrapper around the raw state tree with some utility functions.
///
/// Note: the state tree is pruned to include only the information (public key and canister ranges)
/// of a single subnet.
pub(crate) struct StateTree {
    certificate: Certificate,
    subnet_id: SubnetId,
}

impl StateTree {
    /// Saves the raw state tree to the disk, in CBOR format.
    pub(crate) fn save_to_file(&self, path: &Path) -> RecoveryResult<()> {
        serde_cbor::to_vec(&self.certificate)
            .map_err(|err| agent_error("Failed to serialize the state tree", err))
            .and_then(|bytes| write_bytes(path, bytes))
            .map_err(|err| agent_error("Failed to write the state tree to disk", err))
    }

    /// Reads the raw state tree from the disk.
    pub(crate) fn read_from_file(path: &Path, subnet_id: SubnetId) -> RecoveryResult<Self> {
        let serialized_state_tree = read_bytes(path)
            .map_err(|err| agent_error("Failed to read the state tree from the disk", err))?;

        let certificate = serde_cbor::from_slice(serialized_state_tree.as_slice())
            .map_err(|err| agent_error("Failed to deserialize the state tree", err))?;

        Ok(Self {
            subnet_id,
            certificate,
        })
    }

    /// Extracts the public key from the raw state tree and saves it to the disk.
    pub(crate) fn save_public_key_to_file(&self, path: &Path) -> RecoveryResult<()> {
        self.lookup_public_key()
            .and_then(|public_key| write_public_key_to_file(public_key, path))
            .map_err(|err| agent_error("Failed to write the public key to disk", err))
    }

    pub(crate) fn lookup_public_key(&self) -> RecoveryResult<&[u8]> {
        lookup_value(
            &self.certificate,
            create_path(self.subnet_id, PUBLIC_KEY_LABEL),
        )
        .map_err(|err| agent_error("Failed to retrieve the public key", err))
    }
}

/// Wrapper around [Agent]  with some utility functions.
pub(crate) struct AgentHelper {
    agent: Agent,
    nns_registry: Principal,
    logger: Logger,
}

impl AgentHelper {
    /// Creates a new instance of [AgentHelper].
    ///
    /// When the `nns_public_key_path` argument is not specified, the mainnet root key will be
    /// used.
    ///
    /// Returns an error when the underlying [Agent] fails to build or when there is something
    /// wrong with the provided NNS public key.
    pub(crate) fn new(
        nns_url: &Url,
        nns_public_key_path: Option<&Path>,
        logger: Logger,
    ) -> RecoveryResult<Self> {
        let agent = Agent::builder()
            .with_url(nns_url.to_string())
            .build()
            .map_err(|err| agent_error("Failed to build an Agent", err))?;

        // If we don't set a root key, the [Agent] will use the mainnet root key.
        if let Some(nns_public_key_path) = nns_public_key_path {
            info!(
                logger,
                "Reading the NNS public key from {}",
                nns_public_key_path.display()
            );

            let nns_public_key = parse_threshold_sig_key(nns_public_key_path)
                .map_err(|err| agent_error("Failed to parse NNS public key", err))?;
            let der_bytes = public_key_to_der(&nns_public_key.into_bytes())
                .map_err(|err| agent_error("Failed to convert the NNS public key to DER", err))?;

            agent.set_root_key(der_bytes);
        }

        let nns_registry = Principal::from_text(NNS_REGISTRY_CANISTER_ID)
            .map_err(|err| agent_error("Failed to parse NNS registry canister id", err))?;

        Ok(Self {
            agent,
            nns_registry,
            logger,
        })
    }

    /// Reads the state tree and prunes it to contain only the following paths:
    /// * /subnet_id/$subnet_id/public_key
    /// * /subnet_id/$subnet_id/canister_ranges
    ///
    /// See: https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree-subnet
    /// for more information
    pub(crate) fn read_subnet_data(&self, subnet_id: SubnetId) -> RecoveryResult<StateTree> {
        let certificate = block_on(self.agent.read_state_raw(
            vec![
                create_path(subnet_id, PUBLIC_KEY_LABEL),
                create_path(subnet_id, CANISTER_RANGES_LABEL),
            ],
            self.nns_registry,
        ))
        .map_err(|err| agent_error("Failed to read the state tree", err))?;

        debug!(self.logger, "State tree: {:#?}", certificate.tree);

        Ok(StateTree {
            certificate,
            subnet_id,
        })
    }

    /// Validates the state tree.
    pub(crate) fn validate_state_tree(&self, state_tree: &StateTree) -> RecoveryResult<()> {
        self.agent
            .verify(&state_tree.certificate, self.nns_registry)
            .map_err(|err| agent_error("Failed to verify the state tree", err))
    }
}

fn agent_error(message: impl Display, error: impl Display) -> RecoveryError {
    RecoveryError::AgentError(format!("{message}: {error}"))
}

fn create_path(subnet_id: SubnetId, label: &[u8]) -> Vec<Label<StorageType>> {
    vec![
        SUBNET_LABEL.into(),
        subnet_id.get().as_slice().into(),
        label.into(),
    ]
}
