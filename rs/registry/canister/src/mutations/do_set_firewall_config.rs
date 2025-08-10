use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::firewall::v1::FirewallConfig;
use ic_registry_keys::make_firewall_config_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Sets the firewall config record in the registry.
    ///
    /// This method is called by the governance canister.
    pub fn do_set_firewall_config(&mut self, payload: SetFirewallConfigPayload) {
        println!("{}do_set_firewall_config: firewall_config: {:?}, ipv4_prefixes: {:?}, ipv6_prefixes: {:?}", LOG_PREFIX, payload.firewall_config, payload.ipv4_prefixes, payload.ipv6_prefixes);

        let firewall_config: FirewallConfig = payload.into();

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: make_firewall_config_record_key().into_bytes(),
            value: firewall_config.encode_to_vec(),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to set the firewall configuration
///
/// See /rs/protobuf/def/registry/firewall/v1/firewall.proto
#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct SetFirewallConfigPayload {
    /// The firewall configuration content
    #[prost(string, tag = "1")]
    pub firewall_config: ::prost::alloc::string::String,
    /// List of allowed IPv4 prefixes
    #[prost(string, repeated, tag = "2")]
    pub ipv4_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// List of allowed IPv6 prefixes
    #[prost(string, repeated, tag = "3")]
    pub ipv6_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

impl From<SetFirewallConfigPayload> for FirewallConfig {
    fn from(val: SetFirewallConfigPayload) -> Self {
        FirewallConfig {
            firewall_config: val.firewall_config,
            ipv4_prefixes: val.ipv4_prefixes,
            ipv6_prefixes: val.ipv6_prefixes,
        }
    }
}

impl From<FirewallConfig> for SetFirewallConfigPayload {
    fn from(config: FirewallConfig) -> Self {
        SetFirewallConfigPayload {
            firewall_config: config.firewall_config,
            ipv4_prefixes: config.ipv4_prefixes,
            ipv6_prefixes: config.ipv6_prefixes,
        }
    }
}
