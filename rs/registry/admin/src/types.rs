//! Helper types used by `ic-admin`.

use ic_protobuf::registry::{
    node::v1::IPv4InterfaceConfig,
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    subnet::v1::{GossipConfig as GossipConfigProto, SubnetRecord as SubnetRecordProto},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_features::{ChainKeyConfig, EcdsaConfig, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_types::PrincipalId;
use indexmap::IndexMap;
use serde::Serialize;
use std::str::FromStr;
use std::{
    convert::{From, TryFrom, TryInto},
    net::{Ipv4Addr, Ipv6Addr},
};

/// All or part of the registry
#[derive(Default, Serialize)]
pub(crate) struct Registry {
    /// The registry version being shown
    pub version: u64, //RegistryVersion,

    /// 0 or more RegistryRecord, depending on what was requested
    pub records: Vec<RegistryRecord>,
}

/// The contents of a single record
#[derive(Default, Serialize)]
pub(crate) struct RegistryRecord {
    pub key: String,
    pub version: u64,
    pub value: RegistryValue,
}

/// The types of RegistryRecorsds that can be serialized to user friendly JSON
#[derive(Default, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum RegistryValue {
    #[default]
    Unknown,
    SubnetRecord(SubnetRecord),
    ProvisionalWhitelistRecord(ProvisionalWhitelistRecord),
}

/// User-friendly representation of a v1::SubnetRecord. For instance,
/// the `membership` field is a `Vec<String>` to pretty-print the node IDs.
#[derive(Default, Serialize, Clone)]
pub(crate) struct SubnetRecord {
    pub membership: Vec<String>,
    pub nodes: IndexMap<PrincipalId, NodeDetails>,
    pub max_ingress_bytes_per_message: u64,
    pub max_ingress_messages_per_block: u64,
    pub max_block_payload_size: u64,
    pub unit_delay_millis: u64,
    pub initial_notary_delay_millis: u64,
    pub replica_version_id: String,
    pub dkg_interval_length: u64,
    pub gossip_config: Option<GossipConfigProto>,
    pub start_as_nns: bool,
    pub subnet_type: SubnetType,
    pub max_instructions_per_message: u64,
    pub max_instructions_per_round: u64,
    pub max_instructions_per_install_code: u64,
    pub features: SubnetFeatures,
    pub max_number_of_canisters: u64,
    pub ssh_readonly_access: Vec<String>,
    pub ssh_backup_access: Vec<String>,
    pub ecdsa_config: Option<EcdsaConfig>,
    pub chain_key_config: Option<ChainKeyConfig>,
}

impl SubnetRecord {
    pub fn with_node_details(mut self, node_details: &IndexMap<PrincipalId, NodeDetails>) -> Self {
        self.nodes = self
            .membership
            .iter()
            .map(|n| {
                let node_id = PrincipalId::from_str(n)
                    .expect("could not create PrincipalId from membership entry");
                let node_details = node_details.get(&node_id).unwrap().clone();
                (node_id, node_details)
            })
            .collect();
        self
    }
}

impl From<&SubnetRecordProto> for SubnetRecord {
    /// Convert a v1::SubnetRecord to a SubnetRecord. Most data is passed
    /// through unchanged, except the `membership` list, which is converted
    /// to a `Vec<String>` for nicer display.
    fn from(value: &SubnetRecordProto) -> Self {
        Self {
            membership: value
                .membership
                .iter()
                .map(|n| {
                    PrincipalId::try_from(&n[..])
                        .expect("could not create PrincipalId from membership entry")
                        .to_string()
                })
                .collect(),
            nodes: IndexMap::default(),
            max_ingress_bytes_per_message: value.max_ingress_bytes_per_message,
            max_ingress_messages_per_block: value.max_ingress_messages_per_block,
            max_block_payload_size: value.max_block_payload_size,
            unit_delay_millis: value.unit_delay_millis,
            initial_notary_delay_millis: value.initial_notary_delay_millis,
            replica_version_id: value.replica_version_id.clone(),
            dkg_interval_length: value.dkg_interval_length,
            gossip_config: value.gossip_config.clone(),
            start_as_nns: value.start_as_nns,
            subnet_type: SubnetType::try_from(value.subnet_type).unwrap(),
            max_instructions_per_message: value.max_instructions_per_message,
            max_instructions_per_round: value.max_instructions_per_round,
            max_instructions_per_install_code: value.max_instructions_per_install_code,
            features: value.features.clone().unwrap_or_default().into(),
            max_number_of_canisters: value.max_number_of_canisters,
            ssh_readonly_access: value.ssh_readonly_access.clone(),
            ssh_backup_access: value.ssh_backup_access.clone(),
            ecdsa_config: value
                .ecdsa_config
                .as_ref()
                .map(|c| c.clone().try_into().unwrap()),
            chain_key_config: value
                .chain_key_config
                .as_ref()
                .map(|c| c.clone().try_into().unwrap()),
        }
    }
}

/// User-friendly representation of the v1::IPv4InterfaceConfig.
/// Ipv4 is parsed into Ipv4Addr. Other fields are omitted for now.
#[derive(Serialize, Clone)]
pub(crate) struct IPv4Interface {
    pub address: Ipv4Addr,
    pub gateways: Vec<Ipv4Addr>,
    pub prefix_length: u32,
}

/// Encapsulates a node/node operator id pair.
#[derive(Serialize, Clone)]
pub(crate) struct NodeDetails {
    pub ipv6: Ipv6Addr,
    pub ipv4: Option<IPv4Interface>,
    pub node_operator_id: PrincipalId,
    pub node_provider_id: PrincipalId,
    pub dc_id: String,
    pub hostos_version_id: Option<String>,
    pub domain: Option<String>,
}

impl From<IPv4InterfaceConfig> for IPv4Interface {
    fn from(value: IPv4InterfaceConfig) -> Self {
        Self {
            address: value
                .ip_addr
                .parse::<Ipv4Addr>()
                .expect("couldn't parse ipv4 address"),
            gateways: value
                .gateway_ip_addr
                .into_iter()
                .map(|s| s.parse::<Ipv4Addr>().expect("couldn't parse ipv4 address"))
                .collect(),
            prefix_length: value.prefix_length,
        }
    }
}

/// User-friendly representation of a v1::ProvisionalWhitelist.
/// The principal IDs are parsed into their text representations.
#[derive(Serialize)]
pub(crate) enum ProvisionalWhitelistRecord {
    Set(Vec<String>),
    All,
}

impl From<ProvisionalWhitelistProto> for ProvisionalWhitelistRecord {
    fn from(value: ProvisionalWhitelistProto) -> Self {
        match ProvisionalWhitelist::try_from(value).unwrap() {
            ProvisionalWhitelist::All => Self::All,
            ProvisionalWhitelist::Set(set) => Self::Set(
                set.into_iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>(),
            ),
        }
    }
}
