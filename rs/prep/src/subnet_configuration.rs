use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    initialized_subnet::InitializedSubnet,
    internet_computer::INITIAL_REGISTRY_VERSION,
    node::{InitializeNodeError, InitializedNode, NodeConfiguration, NodeIndex},
};
use anyhow::Result;
use ic_config::subnet_config::SchedulerConfig;
use ic_crypto_test_utils_ni_dkg::{initial_dkg_transcript, InitialNiDkgConfig};
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_protobuf::registry::{
    crypto::v1::PublicKey,
    subnet::v1::{
        CatchUpPackageContents, ChainKeyConfig, EcdsaConfig, InitialNiDkgTranscriptRecord,
        SubnetRecord,
    },
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::crypto::threshold_sig::ni_dkg::ThresholdSigPublicKeyError;
use ic_types::{
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgTag, NiDkgTargetId},
            ThresholdSigPublicKey, ThresholdSigPublicKeyBytesConversionError,
        },
        CryptoError,
    },
    p2p, Height, NodeId, PrincipalId, ReplicaVersion, SubnetId,
};
use thiserror::Error;

pub type SubnetIndex = u64;
pub mod constants;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum SubnetRunningState {
    #[default]
    Active,
    Halted,
}

/// This represents the initial configuration of an NNS subnetwork of an IC
/// instance.
#[derive(Clone, Debug, Default)]
pub struct SubnetConfig {
    /// The subnet id of this subnetwork.
    pub subnet_index: SubnetIndex,

    /// The node ids that belong to this subnetwork.
    pub membership: BTreeMap<NodeIndex, NodeConfiguration>,

    /// maximum size of an ingress message
    pub max_ingress_bytes_per_message: u64,

    /// maximum number of ingress message per block
    pub max_ingress_messages_per_block: u64,

    /// maximum size in byte, payload can have in total
    pub max_block_payload_size: u64,

    /// Notarization delay parameters.
    pub unit_delay: Duration,
    pub initial_notary_delay: Duration,

    /// The length of a DKG interval.
    pub dkg_interval_length: Height,

    /// The upper bound for the number of dealings we allow in a block.
    pub dkg_dealings_per_block: usize,

    /// The version of the replica binary
    pub replica_version_id: ReplicaVersion,

    /// The type of the subnet
    pub subnet_type: SubnetType,

    /// The maximum number of instructions a message can execute.
    /// See the comments in `subnet_config.rs` for more details.
    pub max_instructions_per_message: u64,

    /// The maximum number of instructions a round can execute.
    /// See the comments in `subnet_config.rs` for more details.
    pub max_instructions_per_round: u64,

    /// The maximum number of instructions an `install_code` message can
    /// execute. See the comments in `subnet_config.rs` for more details.
    pub max_instructions_per_install_code: u64,

    /// Flags to mark which features are enabled for this subnet.
    pub features: SubnetFeatures,

    /// Optional ecdsa configuration for this subnet.
    pub ecdsa_config: Option<EcdsaConfig>,

    /// Optional chain key configuration for this subnet.
    pub chain_key_config: Option<ChainKeyConfig>,

    /// The number of canisters allowed to be created on this subnet.
    pub max_number_of_canisters: u64,

    /// The list of public keys whose owners have "readonly" SSH access to all
    /// replicas on this subnet.
    pub ssh_readonly_access: Vec<String>,

    /// The list of public keys whose owners have "backup" SSH access to nodes
    /// on the NNS subnet.
    pub ssh_backup_access: Vec<String>,

    /// The status of the subnet, i.e., whether it is running or halted.
    pub running_state: SubnetRunningState,

    /// The initial block height of this subnet in case it is initialized from a CUP.
    /// Defaults to 0, but the system test API overwrites this with a large default.
    pub initial_height: u64,
}

#[derive(Error, Debug)]
pub enum InitializeSubnetError {
    #[error("threshold signature public key: {source}")]
    ThresholdSigPublicKey {
        #[from]
        source: ThresholdSigPublicKeyBytesConversionError,
    },

    #[error("NI-DKG transcript threshold signature public key: {source}")]
    NiDkgTranscriptToThresholdSigPublicKey {
        #[from]
        source: ThresholdSigPublicKeyError,
    },

    #[error("crypto error: {source}")]
    Crypto {
        #[from]
        source: CryptoError,
    },

    #[error("saving node id to {path:?} failed: {source}")]
    SavingNodeId { source: io::Error, path: PathBuf },

    #[error("initializing node failed: {source}")]
    InitializeNode {
        #[from]
        source: InitializeNodeError,
    },
}

pub struct SubnetConfigParams {
    pub unit_delay: Duration,
    pub initial_notary_delay: Duration,
    pub dkg_interval_length: Height,
    pub max_ingress_bytes_per_message: u64,
    pub max_ingress_messages_per_block: u64,
    pub max_block_payload_size: u64,
    pub dkg_dealings_per_block: usize,
}

/// This helper function can be used to convert `Duration` to milliseconds.
/// For example, this is useful for creating payloads (see
/// `submit_create_application_subnet_proposal`).
pub fn duration_to_millis(unit_delay: Duration) -> u64 {
    u64::try_from(unit_delay.as_millis()).expect("cannot convert u128 to u64")
}

/// Returns config parameters, which depend on the type and size of the subnet.
/// The configuration for app subnets is used for new app subnets with at most
/// 13 nodes. App subnets with more than 13 nodes will be deployed with the NNS
/// subnet configs.

pub fn get_default_config_params(subnet_type: SubnetType, nodes_num: usize) -> SubnetConfigParams {
    let use_app_config =
        subnet_type == SubnetType::Application && nodes_num <= constants::SMALL_APP_SUBNET_MAX_SIZE;

    struct DynamicConfig {
        pub unit_delay: Duration,
        pub initial_notary_delay: Duration,
        pub dkg_interval_length: Height,
        pub max_ingress_bytes_per_message: u64,
    }

    let dynamic_config = if use_app_config {
        DynamicConfig {
            unit_delay: constants::UNIT_DELAY_APP_SUBNET,
            initial_notary_delay: constants::INITIAL_NOTARY_DELAY_APP_SUBNET,
            dkg_interval_length: constants::DKG_INTERVAL_LENGTH_APP_SUBNET,
            max_ingress_bytes_per_message: constants::MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET,
        }
    } else {
        DynamicConfig {
            unit_delay: constants::UNIT_DELAY_NNS_SUBNET,
            initial_notary_delay: constants::INITIAL_NOTARY_DELAY_NNS_SUBNET,
            dkg_interval_length: constants::DKG_INTERVAL_LENGTH_NNS_SUBNET,
            max_ingress_bytes_per_message: constants::MAX_INGRESS_BYTES_PER_MESSAGE_NNS_SUBNET,
        }
    };

    SubnetConfigParams {
        unit_delay: dynamic_config.unit_delay,
        initial_notary_delay: dynamic_config.initial_notary_delay,
        dkg_interval_length: dynamic_config.dkg_interval_length,
        max_ingress_bytes_per_message: dynamic_config.max_ingress_bytes_per_message,
        max_ingress_messages_per_block: constants::MAX_INGRESS_MESSAGES_PER_BLOCK,
        max_block_payload_size: constants::MAX_BLOCK_PAYLOAD_SIZE,
        dkg_dealings_per_block: constants::DKG_DEALINGS_PER_BLOCK,
    }
}

impl SubnetConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subnet_index: SubnetIndex,
        membership: BTreeMap<NodeIndex, NodeConfiguration>,
        replica_version_id: ReplicaVersion,
        max_ingress_bytes_per_message: Option<u64>,
        max_ingress_messages_per_block: Option<u64>,
        max_block_payload_size: Option<u64>,
        unit_delay: Option<Duration>,
        initial_notary_delay: Option<Duration>,
        dkg_interval_length: Option<Height>,
        dkg_dealings_per_block: Option<usize>,
        subnet_type: SubnetType,
        max_instructions_per_message: Option<u64>,
        max_instructions_per_round: Option<u64>,
        max_instructions_per_install_code: Option<u64>,
        features: Option<SubnetFeatures>,
        ecdsa_config: Option<EcdsaConfig>,
        chain_key_config: Option<ChainKeyConfig>,
        max_number_of_canisters: Option<u64>,
        ssh_readonly_access: Vec<String>,
        ssh_backup_access: Vec<String>,
        running_state: SubnetRunningState,
        initial_height: Option<u64>,
    ) -> Self {
        let scheduler_config = SchedulerConfig::default_for_subnet_type(subnet_type);

        // This set of default params depends on the type and size of the subnet.
        let config = get_default_config_params(subnet_type, membership.len());

        Self {
            subnet_index,
            membership,
            replica_version_id,
            max_ingress_bytes_per_message: max_ingress_bytes_per_message
                .unwrap_or(config.max_ingress_bytes_per_message),
            max_ingress_messages_per_block: max_ingress_messages_per_block
                .unwrap_or(config.max_ingress_messages_per_block),
            max_block_payload_size: max_block_payload_size.unwrap_or(config.max_block_payload_size),
            unit_delay: unit_delay.unwrap_or(config.unit_delay),
            initial_notary_delay: initial_notary_delay.unwrap_or(config.initial_notary_delay),
            dkg_interval_length: dkg_interval_length.unwrap_or(config.dkg_interval_length),
            dkg_dealings_per_block: dkg_dealings_per_block.unwrap_or(config.dkg_dealings_per_block),
            subnet_type,
            max_instructions_per_message: max_instructions_per_message
                .unwrap_or_else(|| scheduler_config.max_instructions_per_message.get()),
            max_instructions_per_round: max_instructions_per_round
                .unwrap_or_else(|| scheduler_config.max_instructions_per_round.get()),
            max_instructions_per_install_code: max_instructions_per_install_code
                .unwrap_or_else(|| scheduler_config.max_instructions_per_install_code.get()),
            features: features.unwrap_or_default(),
            ecdsa_config,
            chain_key_config,
            max_number_of_canisters: max_number_of_canisters.unwrap_or(0),
            ssh_readonly_access,
            ssh_backup_access,
            running_state,
            initial_height: initial_height.unwrap_or(0),
        }
    }

    pub fn initialize<P: AsRef<Path>>(
        self,
        subnet_path: P,
    ) -> Result<InitializedSubnet, InitializeSubnetError> {
        let subnet_config = self.clone();
        let subnet_path = PathBuf::from(subnet_path.as_ref());
        let subnet_index = self.subnet_index;
        let mut initialized_nodes: BTreeMap<NodeIndex, InitializedNode> = BTreeMap::new();

        for (node_index, node_config) in self.membership {
            let node_path = InitializedSubnet::build_node_path(subnet_path.as_path(), node_index);
            let initialized_node = node_config.initialize(node_path.as_path())?;

            initialized_nodes.insert(node_index, initialized_node);
        }

        let nodes_in_subnet: BTreeSet<NodeId> = initialized_nodes
            .values()
            .map(|initialized_node| initialized_node.node_id)
            .collect();

        let membership_nodes: Vec<Vec<u8>> = initialized_nodes
            .values()
            .map(|initialized_node| initialized_node.node_id.get().into_vec())
            .collect();

        let subnet_record = SubnetRecord {
            membership: membership_nodes,
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message,
            max_ingress_messages_per_block: self.max_ingress_messages_per_block,
            max_block_payload_size: self.max_block_payload_size,
            unit_delay_millis: self.unit_delay.as_millis() as u64,
            initial_notary_delay_millis: self.initial_notary_delay.as_millis() as u64,
            replica_version_id: self.replica_version_id.to_string(),
            dkg_interval_length: self.dkg_interval_length.get(),
            dkg_dealings_per_block: self.dkg_dealings_per_block as u64,
            gossip_config: Some(p2p::build_default_gossip_config()),
            // This is not something ic-prep will participate in, so it is safe
            // to set it to false. ic-admin can set it to true when adding a
            // subnet via NNS.
            start_as_nns: false,
            subnet_type: self.subnet_type.into(),
            is_halted: self.running_state == SubnetRunningState::Halted,
            halt_at_cup_height: false,
            max_instructions_per_message: self.max_instructions_per_message,
            max_instructions_per_round: self.max_instructions_per_round,
            max_instructions_per_install_code: self.max_instructions_per_install_code,
            features: Some(self.features.into()),
            max_number_of_canisters: self.max_number_of_canisters,
            ssh_readonly_access: self.ssh_readonly_access,
            ssh_backup_access: self.ssh_backup_access,
            ecdsa_config: self.ecdsa_config,
            chain_key_config: self.chain_key_config,
            // TODO[NNS1-2969]: Use this field rather than ecdsa_config.
        };

        let dkg_dealing_encryption_pubkeys: BTreeMap<_, _> = initialized_nodes
            .values()
            .map(|initialized_node| {
                (
                    initialized_node.node_id,
                    initialized_node.dkg_dealing_encryption_pubkey.clone(),
                )
            })
            .collect();
        let random_ni_dkg_target_id = NiDkgTargetId::new(rand::random::<[u8; 32]>());
        let ni_dkg_transcript_low_threshold = initial_dkg_transcript(
            InitialNiDkgConfig::new(
                &nodes_in_subnet,
                SubnetId::from(PrincipalId::new_subnet_test_id(subnet_index)),
                NiDkgTag::LowThreshold,
                random_ni_dkg_target_id,
                INITIAL_REGISTRY_VERSION,
            ),
            &dkg_dealing_encryption_pubkeys,
            &mut rand::rngs::OsRng,
        );
        let ni_dkg_transcript_high_threshold = initial_dkg_transcript(
            InitialNiDkgConfig::new(
                &nodes_in_subnet,
                SubnetId::from(PrincipalId::new_subnet_test_id(subnet_index)),
                NiDkgTag::HighThreshold,
                random_ni_dkg_target_id,
                INITIAL_REGISTRY_VERSION,
            ),
            &dkg_dealing_encryption_pubkeys,
            &mut rand::rngs::OsRng,
        );
        let subnet_threshold_signing_public_key = PublicKey::from(ThresholdSigPublicKey::try_from(
            &ni_dkg_transcript_high_threshold,
        )?);

        let pk = ThresholdSigPublicKey::try_from(subnet_threshold_signing_public_key.clone())?;
        let der_pk = threshold_sig_public_key_to_der(pk)?;
        let subnet_id = SubnetId::from(PrincipalId::new_self_authenticating(&der_pk[..]));

        let state_hash = if self.initial_height != 0 {
            let state_hashes: Vec<_> = initialized_nodes
                .values()
                .map(|initialized_node| {
                    initialized_node.generate_initial_state(subnet_id, self.subnet_type)
                })
                .collect();

            // Make sure that all states have the same state shash
            assert_eq!(
                state_hashes,
                vec![state_hashes[0].clone(); state_hashes.len()],
                "Generated initial states do not have the same state hash"
            );
            state_hashes[0].clone()
        } else {
            vec![]
        };

        let subnet_dkg = CatchUpPackageContents {
            initial_ni_dkg_transcript_low_threshold: Some(InitialNiDkgTranscriptRecord::from(
                ni_dkg_transcript_low_threshold,
            )),
            initial_ni_dkg_transcript_high_threshold: Some(InitialNiDkgTranscriptRecord::from(
                ni_dkg_transcript_high_threshold,
            )),
            state_hash,
            height: self.initial_height,
            ..Default::default()
        };

        Ok(InitializedSubnet {
            subnet_index,
            subnet_id,
            initialized_nodes,
            subnet_record,
            subnet_dkg,
            subnet_threshold_signing_public_key,
            subnet_path,
            subnet_config,
        })
    }
}
