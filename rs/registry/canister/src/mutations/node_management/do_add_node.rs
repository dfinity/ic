use crate::{common::LOG_PREFIX, registry::Registry};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_utils_basic_sig::conversions as crypto_basicsig_conversions;
use ic_protobuf::registry::{
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::{ConnectionEndpoint, IPv4InterfaceConfig, NodeRecord, NodeRewardType},
};
use idna::domain_to_ascii_strict;
use std::fmt::Display;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::mutations::node_management::common::{
    get_node_operator_nodes, get_node_reward_type_for_node,
};
use crate::mutations::node_management::{
    common::{
        get_node_operator_record, make_add_node_registry_mutations, node_exists_with_ipv4,
        scan_for_nodes_by_ip,
    },
    do_remove_node_directly::RemoveNodeDirectlyPayload,
};
use crate::rate_limits::{commit_add_node_capacity, try_reserve_add_node_capacity};
use ic_nervous_system_time_helpers::now_system_time;
use ic_registry_canister_api::AddNodePayload;
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use ic_types::{crypto::CurrentNodePublicKeys, time::Time};
use prost::Message;

impl Registry {
    /// Adds a new node to the registry.
    ///
    /// This method is called directly by the node or tool that needs to add a node.
    pub fn do_add_node(&mut self, payload: AddNodePayload) -> Result<NodeId, String> {
        // Get the caller ID and check if it is in the registry
        let caller_id = dfn_core::api::caller();
        println!("{LOG_PREFIX}do_add_node started: {payload:?} caller: {caller_id:?}");
        self.do_add_node_(payload, caller_id, now_system_time())
    }

    fn do_add_node_(
        &mut self,
        payload: AddNodePayload,
        caller_id: PrincipalId,
        now: SystemTime,
    ) -> Result<NodeId, String> {
        let node_operator_record = get_node_operator_record(self, caller_id)
            .map_err(|err| format!("{LOG_PREFIX}do_add_node: Aborting node addition: {err}"))?;

        let reservation =
            self.try_reserve_capacity_for_node_operator_operation(now, caller_id, 1)?;

        // Validate keys and get the node id
        let (node_id, valid_pks) = valid_keys_from_payload(&payload)
            .map_err(|err| format!("{LOG_PREFIX}do_add_node: {err}"))?;

        println!("{LOG_PREFIX}do_add_node: The node id is {node_id:?}");

        // Get valid node_rewards_type if type is in request
        let node_reward_type = payload
            .node_reward_type
            .as_ref()
            .map(|t| {
                validate_str_as_node_reward_type(t).map_err(|e| {
                    format!("{LOG_PREFIX}do_add_node: Error parsing node type from payload: {e}")
                })
            })
            .transpose()?;

        // Clear out any nodes that already exist at this IP.
        // This will only succeed if the same NO was in control of the original nodes.
        //
        // (We use the http endpoint to be in line with what is used by the
        // release dashboard.)
        let http_endpoint = connection_endpoint_from_string(&payload.http_endpoint);

        // 2a. Check IP-based rate limiting (1 node addition per day per IP)
        let ip_addr = http_endpoint.ip_addr.clone();
        let ip_reservation = try_reserve_add_node_capacity(now, ip_addr.clone())
            .map_err(|e| format!("{LOG_PREFIX}do_add_node: {e}"))?;

        let nodes_with_same_ip = scan_for_nodes_by_ip(self, &http_endpoint.ip_addr);
        let mut mutations = Vec::new();
        let mut num_removed_same_ip_same_type = 0;
        if !nodes_with_same_ip.is_empty() {
            for node_with_same_ip in &nodes_with_same_ip {
                let node_same_ip_reward_type =
                    get_node_reward_type_for_node(self, *node_with_same_ip)
                        .map_err(|e| format!("{LOG_PREFIX}do_add_node: {e}"))?;

                if Some(node_same_ip_reward_type) == node_reward_type {
                    num_removed_same_ip_same_type += 1;
                }
            }
            if nodes_with_same_ip.len() == 1 {
                mutations = self.make_remove_or_replace_node_mutations(
                    RemoveNodeDirectlyPayload {
                        node_id: nodes_with_same_ip[0],
                    },
                    caller_id,
                    Some(node_id),
                );
            } else {
                // In the unlikely situation that multiple nodes share the same IP address as the new node,
                // this will remove the existing nodes.
                // While the situation is unexpected, the behavior is backwards compatible.
                // This may happen only if there is a bug in the registry code and the registry invariant isn't enforced,
                // due to which the node id was not properly removed.
                for previous_node_id in nodes_with_same_ip {
                    mutations.extend(self.make_remove_or_replace_node_mutations(
                        RemoveNodeDirectlyPayload {
                            node_id: previous_node_id,
                        },
                        caller_id,
                        // If there are multiple nodes with the same IP, then each of them could in principle be in a (different) subnet.
                        // In that case replacing all different node ids with the same new node isn't an option.
                        // To cover for this corner case, we don't replace the node id but just remove the node and potentially fail.
                        None,
                    ));
                }
            }
        }

        if self.are_node_rewards_enabled() {
            let node_reward_type = node_reward_type.ok_or(format!(
                "{LOG_PREFIX}do_add_node: Node reward type is required."
            ))?;

            let max_rewardable_nodes_same_type = *node_operator_record
                .max_rewardable_nodes
                .get(&(node_reward_type.to_string()))
                .ok_or(format!("{LOG_PREFIX}do_add_node: Node Operator does not have rewardable nodes for {node_reward_type}"))?;

            let num_in_registry_same_type = get_node_operator_nodes(self, caller_id)
                .into_iter()
                .filter_map(|node| node.node_reward_type)
                .filter(|t| t == &(node_reward_type as i32))
                .count() as u32;

            // Validate node operator's max_rewardable_nodes quota
            if max_rewardable_nodes_same_type
                <= num_in_registry_same_type.saturating_sub(num_removed_same_ip_same_type)
            {
                return Err(format!(
                    "{LOG_PREFIX}do_add_node: Node Operator has reached max_rewardable_nodes quota for {node_reward_type}.\
                    Number of nodes in the registry with {node_reward_type} type = {num_in_registry_same_type},\
                    Number of removed nodes with same IP and same type = {num_removed_same_ip_same_type},\
                    {node_reward_type} quota = {max_rewardable_nodes_same_type}"
                ));
            }
        }

        // 5. Validate the domain
        let domain: Option<String> = payload
            .domain
            .as_ref()
            .map(|domain| {
                if !domain_to_ascii_strict(domain).is_ok_and(|s| s == *domain) {
                    return Err(format!(
                        "{LOG_PREFIX}do_add_node: Domain name `{domain}` has invalid format"
                    ));
                }
                Ok(domain.clone())
            })
            .transpose()?;

        // If there is an IPv4 config, make sure that the same IPv4 address is not used by any other node
        let ipv4_intf_config = payload.public_ipv4_config.clone().map(|ipv4_config| {
            ipv4_config.panic_on_invalid();
            IPv4InterfaceConfig {
                ip_addr: ipv4_config.ip_addr().to_string(),
                gateway_ip_addr: vec![ipv4_config.gateway_ip_addr().to_string()],
                prefix_length: ipv4_config.prefix_length(),
            }
        });
        if let Some(ipv4_config) = ipv4_intf_config.clone()
            && node_exists_with_ipv4(self, &ipv4_config.ip_addr)
        {
            return Err(format!(
                "{}do_add_node: There is already another node with the same IPv4 address ({}).",
                LOG_PREFIX, ipv4_config.ip_addr,
            ));
        }

        // Create the Node Record
        let node_record = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
            node_operator_id: caller_id.into_vec(),
            hostos_version_id: None,
            chip_id: payload.chip_id.clone(),
            public_ipv4_config: ipv4_intf_config,
            domain,
            node_reward_type: node_reward_type.map(|t| t as i32),
            ssh_node_state_write_access: vec![],
        };

        // Insert node, public keys, and crypto keys
        mutations.extend(make_add_node_registry_mutations(
            node_id,
            node_record,
            valid_pks,
        ));

        // Check invariants and then apply mutations
        self.maybe_apply_mutation_internal(mutations);

        println!("{LOG_PREFIX}do_add_node finished: {payload:?}");

        if let Err(e) = self.commit_used_capacity_for_node_operator_operation(now, reservation) {
            println!("{LOG_PREFIX}do_add_node did not use reservation capacity: {e}");
        }

        // 11. Commit IP-based rate limiter reservation
        if let Err(e) = commit_add_node_capacity(now, ip_reservation) {
            println!("{LOG_PREFIX}do_add_node did not use IP reservation capacity: {e}");
        }

        Ok(node_id)
    }

    /// Currently, we know that node rewards are enabled based on the presence of the table in the
    /// registry.
    fn are_node_rewards_enabled(&self) -> bool {
        self.get(NODE_REWARDS_TABLE_KEY.as_bytes(), self.latest_version())
            .is_some()
    }
}

// try to convert input string into NodeRewardType enum
// If a type is no longer supported for newly registered nodes, it should be removed from this function
fn validate_str_as_node_reward_type<T: AsRef<str> + Display>(
    type_string: T,
) -> Result<NodeRewardType, String> {
    Ok(match type_string.as_ref() {
        "type0" => NodeRewardType::Type0,
        "type1" => NodeRewardType::Type1,
        "type2" => NodeRewardType::Type2,
        "type3" => NodeRewardType::Type3,
        "type3.1" => NodeRewardType::Type3dot1,
        "type1.1" => NodeRewardType::Type1dot1,
        _ => return Err(format!("Invalid node type: {type_string}")),
    })
}

/// Parses the ConnectionEndpoint string
///
/// The string is written in form: `ipv4:port` or `[ipv6]:port`.
pub fn connection_endpoint_from_string(endpoint: &str) -> ConnectionEndpoint {
    match endpoint.parse::<SocketAddr>() {
        Err(e) => panic!("Could not convert {endpoint:?} to a connection endpoint: {e:?}"),
        Ok(sa) => ConnectionEndpoint {
            ip_addr: sa.ip().to_string(),
            port: sa.port() as u32, // because protobufs don't have u16
        },
    }
}

/// Validates the payload and extracts node's public keys
fn valid_keys_from_payload(
    payload: &AddNodePayload,
) -> Result<(NodeId, ValidNodePublicKeys), String> {
    // 1. verify that the keys we got are not empty
    if payload.node_signing_pk.is_empty() {
        return Err(String::from("node_signing_pk is empty"));
    };
    if payload.committee_signing_pk.is_empty() {
        return Err(String::from("committee_signing_pk is empty"));
    };
    if payload.ni_dkg_dealing_encryption_pk.is_empty() {
        return Err(String::from("ni_dkg_dealing_encryption_pk is empty"));
    };
    if payload.transport_tls_cert.is_empty() {
        return Err(String::from("transport_tls_cert is empty"));
    };
    // TODO(NNS1-1197): Refactor this when nodes are provisioned for threshold ECDSA subnets
    if let Some(idkg_dealing_encryption_pk) = &payload.idkg_dealing_encryption_pk
        && idkg_dealing_encryption_pk.is_empty()
    {
        return Err(String::from("idkg_dealing_encryption_pk is empty"));
    };

    // 2. get the keys for verification -- for that, we need to create
    // NodePublicKeys first
    let node_signing_pk = PublicKey::decode(&payload.node_signing_pk[..])
        .map_err(|e| format!("node_signing_pk is not in the expected format: {e:?}"))?;
    let committee_signing_pk = PublicKey::decode(&payload.committee_signing_pk[..])
        .map_err(|e| format!("committee_signing_pk is not in the expected format: {e:?}"))?;
    let tls_certificate = X509PublicKeyCert::decode(&payload.transport_tls_cert[..])
        .map_err(|e| format!("transport_tls_cert is not in the expected format: {e:?}"))?;
    let dkg_dealing_encryption_pk = PublicKey::decode(&payload.ni_dkg_dealing_encryption_pk[..])
        .map_err(|e| {
            format!("ni_dkg_dealing_encryption_pk is not in the expected format: {e:?}")
        })?;
    // TODO(NNS1-1197): Refactor when nodes are provisioned for threshold ECDSA subnets
    let idkg_dealing_encryption_pk =
        if let Some(idkg_de_pk_bytes) = &payload.idkg_dealing_encryption_pk {
            Some(PublicKey::decode(&idkg_de_pk_bytes[..]).map_err(|e| {
                format!("idkg_dealing_encryption_pk is not in the expected format: {e:?}")
            })?)
        } else {
            None
        };

    // 3. get the node id from the node_signing_pk
    let node_id = crypto_basicsig_conversions::derive_node_id(&node_signing_pk)
        .map_err(|e| format!("node signing public key couldn't be converted to a NodeId: {e:?}"))?;

    // 4. get the keys for verification -- for that, we need to create
    let node_pks = CurrentNodePublicKeys {
        node_signing_public_key: Some(node_signing_pk),
        committee_signing_public_key: Some(committee_signing_pk),
        tls_certificate: Some(tls_certificate),
        dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_pk),
        idkg_dealing_encryption_public_key: idkg_dealing_encryption_pk,
    };

    // 5. validate the keys and the node_id
    match ValidNodePublicKeys::try_from(node_pks, node_id, now()?) {
        Ok(valid_pks) => Ok((node_id, valid_pks)),
        Err(e) => Err(format!("Could not validate public keys, due to {e:?}")),
    }
}

fn now() -> Result<Time, String> {
    let duration = dfn_core::api::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Could not get current time since UNIX_EPOCH: {e}"))?;

    let nanos = u64::try_from(duration.as_nanos())
        .map_err(|e| format!("Current time cannot be converted to u64: {e:?}"))?;

    Ok(Time::from_nanos_since_unix_epoch(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{
        invariant_compliant_registry, prepare_registry_with_nodes,
        registry_add_node_operator_for_node, registry_create_subnet_with_nodes,
    };
    use crate::rate_limits::get_available_add_node_capacity;
    use ic_base_types::{NodeId, PrincipalId};
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord, node_operator::v1::NodeOperatorRecord,
    };
    use ic_registry_canister_api::IPv4Config;
    use ic_registry_keys::{
        make_api_boundary_node_record_key, make_node_operator_record_key, make_node_record_key,
    };
    use ic_registry_transport::{delete, insert, update};
    use ic_types::ReplicaVersion;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use maplit::btreemap;
    use prost::Message;

    /// Prepares the payload to add a new node, for tests.
    pub fn prepare_add_node_payload(
        mutation_id: u8,
        node_reward_type: NodeRewardType,
    ) -> (AddNodePayload, ValidNodePublicKeys) {
        // As the node canister checks for validity of keys, we need to generate them first
        let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
        let node_public_keys =
            generate_node_keys_once(&config, None).expect("error generating node public keys");
        // Create payload message
        let node_signing_pk = node_public_keys.node_signing_key().encode_to_vec();
        let committee_signing_pk = node_public_keys.committee_signing_key().encode_to_vec();
        let ni_dkg_dealing_encryption_pk = node_public_keys
            .dkg_dealing_encryption_key()
            .encode_to_vec();
        let transport_tls_cert = node_public_keys.tls_certificate().encode_to_vec();
        let idkg_dealing_encryption_pk = node_public_keys
            .idkg_dealing_encryption_key()
            .encode_to_vec();
        // Create the payload
        let payload = AddNodePayload {
            node_signing_pk,
            committee_signing_pk,
            ni_dkg_dealing_encryption_pk,
            transport_tls_cert,
            idkg_dealing_encryption_pk: Some(idkg_dealing_encryption_pk),
            xnet_endpoint: format!("128.0.{mutation_id}.100:1234"),
            http_endpoint: format!("128.0.{mutation_id}.100:4321"),
            chip_id: None,
            public_ipv4_config: None,
            domain: Some("api-example.com".to_string()),
            // Unused section follows
            p2p_flow_endpoints: Default::default(),
            prometheus_metrics_endpoint: Default::default(),
            node_reward_type: Some(node_reward_type.to_string()),
        };

        (payload, node_public_keys)
    }

    #[derive(Clone)]
    struct TestData {
        node_pks: ValidNodePublicKeys,
    }

    impl TestData {
        fn new() -> Self {
            let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
            Self {
                node_pks: generate_node_keys_once(&config, None)
                    .expect("error generating node public keys"),
            }
        }
    }

    // This is to avoid calling the expensive key generation operation for every
    // test.
    lazy_static! {
        static ref TEST_DATA: TestData = TestData::new();
        static ref PAYLOAD: AddNodePayload = AddNodePayload {
            node_signing_pk: vec![],
            committee_signing_pk: vec![],
            ni_dkg_dealing_encryption_pk: vec![],
            transport_tls_cert: vec![],
            idkg_dealing_encryption_pk: Some(vec![]),
            xnet_endpoint: "127.0.0.1:1234".to_string(),
            http_endpoint: "127.0.0.1:8123".to_string(),
            chip_id: None,
            public_ipv4_config: None,
            domain: None,
            // Unused section follows
            p2p_flow_endpoints: Default::default(),
            prometheus_metrics_endpoint: Default::default(),
            node_reward_type: None,
        };
    }

    #[test]
    fn empty_node_signing_key_is_detected() {
        let payload = PAYLOAD.clone();
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    fn empty_committee_signing_key_is_detected() {
        let mut payload = PAYLOAD.clone();
        let node_signing_pubkey = TEST_DATA.node_pks.node_signing_key().encode_to_vec();
        payload.node_signing_pk = node_signing_pubkey;
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    fn empty_dkg_dealing_key_is_detected() {
        let mut payload = PAYLOAD.clone();
        let node_signing_pubkey = TEST_DATA.node_pks.node_signing_key().encode_to_vec();
        let committee_signing_pubkey = TEST_DATA.node_pks.committee_signing_key().encode_to_vec();
        payload.node_signing_pk = node_signing_pubkey;
        payload.committee_signing_pk = committee_signing_pubkey;
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    fn empty_tls_cert_is_detected() {
        let mut payload = PAYLOAD.clone();
        let node_signing_pubkey = TEST_DATA.node_pks.node_signing_key().encode_to_vec();
        let committee_signing_pubkey = TEST_DATA.node_pks.committee_signing_key().encode_to_vec();
        let ni_dkg_dealing_encryption_pubkey = TEST_DATA
            .node_pks
            .dkg_dealing_encryption_key()
            .encode_to_vec();
        payload.node_signing_pk = node_signing_pubkey;
        payload.committee_signing_pk = committee_signing_pubkey;
        payload.ni_dkg_dealing_encryption_pk = ni_dkg_dealing_encryption_pubkey;
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    fn empty_idkg_key_is_detected() {
        let mut payload = PAYLOAD.clone();
        let node_signing_pubkey = TEST_DATA.node_pks.node_signing_key().encode_to_vec();
        let committee_signing_pubkey = TEST_DATA.node_pks.committee_signing_key().encode_to_vec();
        let ni_dkg_dealing_encryption_pubkey = TEST_DATA
            .node_pks
            .dkg_dealing_encryption_key()
            .encode_to_vec();
        let tls_certificate = TEST_DATA.node_pks.tls_certificate().encode_to_vec();
        payload.node_signing_pk = node_signing_pubkey;
        payload.committee_signing_pk = committee_signing_pubkey;
        payload.ni_dkg_dealing_encryption_pk = ni_dkg_dealing_encryption_pubkey;
        payload.transport_tls_cert = tls_certificate;
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    #[should_panic]
    fn empty_string_causes_panic() {
        connection_endpoint_from_string("");
    }

    #[test]
    #[should_panic]
    fn no_port_causes_panic() {
        connection_endpoint_from_string("0.0.0.0:");
    }

    #[test]
    #[should_panic]
    fn no_addr_causes_panic() {
        connection_endpoint_from_string(":1234");
    }

    #[test]
    #[should_panic]
    fn bad_addr_causes_panic() {
        connection_endpoint_from_string("xyz:1234");
    }

    #[test]
    #[should_panic]
    fn ipv6_no_brackets_causes_panic() {
        connection_endpoint_from_string("::1:1234");
    }

    #[test]
    fn good_ipv4() {
        assert_eq!(
            connection_endpoint_from_string("192.168.1.3:8080"),
            ConnectionEndpoint {
                ip_addr: "192.168.1.3".to_string(),
                port: 8080u32,
            }
        );
    }

    #[test]
    #[should_panic]
    fn bad_ipv4_port() {
        connection_endpoint_from_string("192.168.1.3:80800");
    }

    #[test]
    fn good_ipv6() {
        assert_eq!(
            connection_endpoint_from_string("[fe80::1]:80"),
            ConnectionEndpoint {
                ip_addr: "fe80::1".to_string(),
                port: 80u32,
            }
        );
    }

    #[test]
    fn should_fail_if_domain_name_is_invalid() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 1 }, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(0);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (mut payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        // Set an invalid domain name
        payload.domain = Some("invalid_domain_name".to_string());
        // Act
        let result = registry.do_add_node_(payload.clone(), node_operator_id, now_system_time());
        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Domain name `invalid_domain_name` has invalid format"
        );
    }

    #[test]
    fn should_fail_if_node_operator_is_absent_in_registry() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        let node_operator_id = PrincipalId::new_user_test_id(0);
        let (payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        // Act
        let result = registry.do_add_node_(payload.clone(), node_operator_id, now_system_time());
        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Aborting node addition: Node Operator Id node_operator_record_d2zjj-uyaaa-aaaaa-aaaap-4ai not found in the registry."
        );
    }

    #[test]
    fn should_succeed_for_adding_one_node() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 1 },
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(0);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);

        // Act
        let node_id: NodeId = registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");
        // Assert node record is correct
        let expected_node_record = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            node_reward_type: Some(NodeRewardType::Type1 as i32),
            ..Default::default()
        };
        let observed_node_record = registry.get_node_or_panic(node_id);
        assert_eq!(observed_node_record, expected_node_record);

        let observed_node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(observed_node_operator_record, node_operator_record);
    }

    #[test]
    fn should_succeed_for_adding_one_node_with_rewards_disabled() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // This disabled node provider rewards.
        registry.maybe_apply_mutation_internal(vec![delete(NODE_REWARDS_TABLE_KEY.as_bytes())]);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(0);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (mut payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        payload.node_reward_type = None;
        // Act
        let node_id: NodeId = registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");
        // Assert node record is correct
        let expected_node_record = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
            node_operator_id: node_operator_id.to_vec(),
            domain: Some("api-example.com".to_string()),
            ..Default::default()
        };
        let observed_node_record = registry.get_node_or_panic(node_id);
        assert_eq!(observed_node_record, expected_node_record);

        let observed_node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(observed_node_operator_record, node_operator_record);
    }

    #[test]
    fn should_succeed_for_adding_two_nodes_with_different_ips() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 2 }, // needed for adding two nodes
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(0);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (payload_1, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        // Set a different IP for the second node
        let (mut payload_2, _) = prepare_add_node_payload(2, NodeRewardType::Type1);
        payload_2.http_endpoint = "128.0.1.10:4321".to_string();
        assert_ne!(payload_1.http_endpoint, payload_2.http_endpoint);
        // Act: add two nodes with the different IPs
        let node_id_1: NodeId = registry
            .do_add_node_(payload_1.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");
        let node_id_2: NodeId = registry
            .do_add_node_(payload_2.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");
        // Assert both node records are in the registry and are correct
        let expected_node_record_1 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_1.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_1.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            node_reward_type: Some(NodeRewardType::from(payload_1.node_reward_type.unwrap()) as i32),
            ..Default::default()
        };
        let expected_node_record_2 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_2.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_2.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            node_reward_type: Some(NodeRewardType::from(payload_2.node_reward_type.unwrap()) as i32),
            ..Default::default()
        };
        let node_record_1 = registry.get_node_or_panic(node_id_1);
        assert_eq!(node_record_1, expected_node_record_1);
        let node_record_2 = registry.get_node_or_panic(node_id_2);
        assert_eq!(node_record_2, expected_node_record_2);
        // Assert max rewardable nodes isn't changed
        let observed_node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(observed_node_operator_record, node_operator_record);
    }

    #[test]
    fn should_succeed_for_adding_two_nodes_with_identical_ips() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            // Set max rewardable nodes to 1 to make sure the first node is removed
            max_rewardable_nodes: btreemap! { "type1".to_string() => 1 },
            ..Default::default()
        };

        let node_operator_id = PrincipalId::new_user_test_id(0);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Use payloads with the same IPs
        let (payload_1, _) = prepare_add_node_payload(1, NodeRewardType::Type1);

        let (mut payload_2, _) = prepare_add_node_payload(2, NodeRewardType::Type1);
        payload_2.http_endpoint.clone_from(&payload_1.http_endpoint);
        assert_eq!(payload_1.http_endpoint, payload_2.http_endpoint);

        // Act: Add two nodes with the same IPs
        let node_id_1: NodeId = registry
            .do_add_node_(payload_1.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");
        let expected_node_record_1 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_1.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_1.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            node_reward_type: Some(NodeRewardType::from(payload_1.node_reward_type.unwrap()) as i32),
            ..Default::default()
        };

        let node_record_1 = registry.get_node_or_panic(node_id_1);
        assert_eq!(node_record_1, expected_node_record_1);
        // Add the second node, this should remove the first one from the registry
        let node_id_2: NodeId = registry
            .do_add_node_(payload_2.clone(), node_operator_id, now_system_time())
            .unwrap();
        // Assert second node record is in the registry and is correct
        let expected_node_record_2 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_2.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_2.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            node_reward_type: Some(NodeRewardType::from(payload_2.node_reward_type.unwrap()) as i32),
            ..Default::default()
        };
        let node_record_2 = registry.get_node_or_panic(node_id_2);
        assert_eq!(node_record_2, expected_node_record_2);
        // Assert first node record is removed from the registry because of the IP conflict
        assert!(
            registry
                .get(
                    make_node_record_key(node_id_1).as_bytes(),
                    registry.latest_version()
                )
                .is_none()
        );
        // Assert max_rewardable_nodes has not changed
        let observed_node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(
            observed_node_operator_record.max_rewardable_nodes,
            node_operator_record.max_rewardable_nodes
        );
    }

    #[test]
    fn should_fail_for_adding_two_nodes_with_same_ipv4s() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 2 }, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(0);
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // create an IPv4 config
        let ipv4_config = Some(IPv4Config::maybe_invalid_new(
            "204.153.51.58".to_string(),
            "204.153.51.1".to_string(),
            24,
        ));

        // create two node payloads with the same IPv4 config
        let (mut payload_1, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        payload_1.public_ipv4_config.clone_from(&ipv4_config);

        let (mut payload_2, _) = prepare_add_node_payload(2, NodeRewardType::Type1);
        payload_2.public_ipv4_config = ipv4_config;

        // Act
        let _ = registry.do_add_node_(payload_1.clone(), node_operator_id, now_system_time());
        let e = registry
            .do_add_node_(payload_2.clone(), node_operator_id, now_system_time())
            .unwrap_err();
        assert!(
            e.contains("do_add_node: There is already another node with the same IPv4 address")
        );
    }

    // This test is disabled until it becomes possible to directly replace nodes that are active in a subnet.
    #[ignore]
    #[test]
    fn should_add_node_and_replace_existing_node_in_subnet() {
        // This test verifies that adding a new node replaces an existing node in a subnet
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 6);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            node_ids[0],
            btreemap! { NodeRewardType::Type1 => 6 },
        );

        // Create a subnet with the first 4 nodes
        let subnet_id =
            registry_create_subnet_with_nodes(&mut registry, &node_ids_and_dkg_pks, &[0, 1, 2, 3]);
        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        let subnet_membership = subnet_record
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .collect::<Vec<NodeId>>();
        let expected_remove_node_id = node_ids[1]; // same offset as the subnet membership vector
        let expected_remove_node = registry.get_node(subnet_membership[1]).unwrap();

        println!("Original subnet membership (node ids): {subnet_membership:?}");

        // Add a new node with the same IP address and port as an existing node, which should replace the existing node
        let (mut payload, _valid_pks) = prepare_add_node_payload(2, NodeRewardType::Type1);
        let http = expected_remove_node.http.unwrap();
        payload
            .http_endpoint
            .clone_from(&format!("[{}]:{}", http.ip_addr, http.port));
        let new_node_id = registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");

        // Verify the subnet record is updated with the new node
        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        let mut expected_membership = subnet_membership.clone();
        expected_membership[1] = new_node_id;
        expected_membership.sort();
        let actual_membership: Vec<NodeId> = subnet_record
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .sorted()
            .collect();
        assert_eq!(actual_membership, expected_membership);

        // Verify the old node is removed from the registry
        assert!(registry.get_node(expected_remove_node_id).is_none());

        // Verify the new node is present in the registry
        assert!(registry.get_node(new_node_id).is_some());

        // Verify node operator allowance is unchanged
        let updated_operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(updated_operator.node_allowance, 0);
    }

    #[test]
    fn should_add_node_with_no_subnet_conflict() {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 4);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            node_ids[0],
            btreemap! { NodeRewardType::Type1 => 5 },
        );

        // Prepare payload to add a new node
        let (payload, _valid_pks) = prepare_add_node_payload(2, NodeRewardType::Type1);

        // Add the new node
        let new_node_id = registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");

        // Verify the new node is present in the registry
        assert!(registry.get_node(new_node_id).is_some());

        // Verify all nodes are in the registry
        for node_id in node_ids {
            assert!(registry.get_node(node_id).is_some());
        }
    }

    #[test]
    fn should_add_node_and_replace_existing_api_boundary_node() {
        // This test verifies that adding a new node replaces an existing node in a subnet
        let mut registry = invariant_compliant_registry(0);

        // Add a node to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();

        let old_node_id = node_ids[0];
        let old_node = registry.get_node(old_node_id).unwrap();

        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            old_node_id,
            btreemap! { NodeRewardType::Type1 => 1 },
        );

        // Turn that node into an API boundary node
        let api_bn = ApiBoundaryNodeRecord {
            version: ReplicaVersion::default().to_string(),
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_api_boundary_node_record_key(old_node_id),
            api_bn.encode_to_vec(),
        )]);

        // Add a new node with the same IP address and port as an existing node, which should replace the existing node
        let (mut payload, _valid_pks) = prepare_add_node_payload(2, NodeRewardType::Type1);

        let http = old_node.http.unwrap();
        payload
            .http_endpoint
            .clone_from(&format!("[{}]:{}", http.ip_addr, http.port));
        let new_node_id = registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .expect("failed to add a node");

        // Verify that there is an API boundary node record for the new node
        assert!(
            registry
                .get(
                    make_api_boundary_node_record_key(new_node_id).as_bytes(),
                    registry.latest_version()
                )
                .is_some()
        );

        // Verify the old node is removed from the registry
        assert!(registry.get_node(old_node_id).is_none());

        // Verify the new node is present in the registry
        assert!(registry.get_node(new_node_id).is_some());

        // Verify node operator max rewardable nodes is unchanged
        let operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(
            operator.max_rewardable_nodes,
            btreemap! { "type1".to_string() => 1 }
        );
    }

    #[test]
    #[should_panic(
        expected = "[Registry] do_add_node: Node Operator has reached max_rewardable_nodes quota for type1"
    )]
    fn should_panic_if_max_rewardable_nodes_is_exhausted_for_type1() {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            node_ids[0],
            // One node with type1 is already in the registry
            btreemap! { NodeRewardType::Type1 => 1 },
        );

        // Prepare payload to add a new node
        let (payload, _valid_pks) = prepare_add_node_payload(2, NodeRewardType::Type1);

        // Attempt to add the new node, which should panic due to exhausted max rewardable nodes
        registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "[Registry] do_add_node: Node Operator has reached max_rewardable_nodes quota for type1.1"
    )]
    fn should_panic_if_max_rewardable_nodes_is_exhausted_for_type1dot1() {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            node_ids[0],
            btreemap! { NodeRewardType::Type1 => 2 , NodeRewardType::Type1dot1 => 0 },
        );

        // Prepare payload to add a new node
        let (payload, _valid_pks) = prepare_add_node_payload(2, NodeRewardType::Type1dot1);

        // Attempt to add the new node, which should panic due to exhausted max rewardable nodes
        registry
            .do_add_node_(payload.clone(), node_operator_id, now_system_time())
            .unwrap();
    }

    #[test]
    fn test_node_reward_type_is_required() {
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 1 }, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(10001);

        registry.maybe_apply_mutation_internal(vec![update(
            NODE_REWARDS_TABLE_KEY,
            NodeRewardsTable::default().encode_to_vec(),
        )]);

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (mut payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        payload.node_reward_type = None;
        // Code under test
        let result = registry.do_add_node_(payload.clone(), node_operator_id, now_system_time());

        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Node reward type is required."
        );
    }

    #[test]
    fn test_node_reward_type_is_not_required_if_no_node_rewards_table_present() {
        let mut registry = invariant_compliant_registry(0);
        // This disabled node provider rewards.
        registry.maybe_apply_mutation_internal(vec![delete(NODE_REWARDS_TABLE_KEY.as_bytes())]);

        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            node_allowance: 1, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(10001);

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (mut payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        payload.node_reward_type = None;
        // Code under test
        let result = registry.do_add_node_(payload.clone(), node_operator_id, now_system_time());

        // Assert
        assert!(
            result.is_ok(),
            "Could not create node with no node reward type: {result:?}"
        );
    }

    #[test]
    fn test_invalid_node_types_return_error() {
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 1 },
            ..Default::default()
        };
        let node_operator_id = PrincipalId::new_user_test_id(10001);

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (mut payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        payload.node_reward_type = Some("invalid_type".to_string());
        // Code under test
        let result = registry.do_add_node_(payload.clone(), node_operator_id, now_system_time());

        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Error parsing node type from payload: Invalid node type: invalid_type"
        );
    }

    #[test]
    fn test_do_add_node_fails_when_rate_limits_exceeded() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);

        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: node_operator_id.to_vec(),
            node_provider_principal_id: node_provider_id.to_vec(),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: btreemap! { "type1.2".to_string() => 1 },
        };

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        let (payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);
        // Exhaust the rate limit capacity
        let available_operator =
            registry.get_available_node_operator_op_capacity(node_operator_id, now);
        let available_provider =
            registry.get_available_node_provider_op_capacity(node_provider_id, now);
        let available = available_operator.min(available_provider);
        let reservation = registry
            .try_reserve_capacity_for_node_operator_operation(now, node_operator_id, available)
            .unwrap();
        registry
            .commit_used_capacity_for_node_operator_operation(now, reservation)
            .unwrap();

        let error = registry
            .do_add_node_(payload, node_operator_id, now)
            .unwrap_err();

        assert_eq!(
            error,
            "Rate Limit Capacity exceeded. Please wait and try again later."
        );
    }

    #[test]
    fn test_ip_rate_limiting_for_add_node() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        let node_operator_id = PrincipalId::new_user_test_id(1);

        // Add node operator record with sufficient allowance
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 10 },
            ..Default::default()
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Prepare an add_node payload.
        let (template_payload, _) = prepare_add_node_payload(1, NodeRewardType::Type1);

        let now = now_system_time();
        let test_ip = connection_endpoint_from_string(&template_payload.http_endpoint).ip_addr;

        let add_node_payload_with_same_ip = |i| {
            let (mut new_payload, _) = prepare_add_node_payload(i, NodeRewardType::Type1);
            new_payload.http_endpoint = template_payload.http_endpoint.clone();
            new_payload
                .http_endpoint
                .clone_from(&template_payload.http_endpoint);
            new_payload
        };

        // Check that we start with capacity available
        let initial_capacity = get_available_add_node_capacity(test_ip.clone(), now);
        assert_eq!(initial_capacity, 7, "Should start with 7 capacity");

        // Act: Add first node with a specific IP - should succeed
        let result_1 =
            registry.do_add_node_(add_node_payload_with_same_ip(1), node_operator_id, now);
        assert!(result_1.is_ok(), "First node addition should succeed");

        assert_eq!(get_available_add_node_capacity(test_ip.clone(), now), 6,);

        // The next 6 should also succeed.
        for i in 2..=7 {
            registry
                .do_add_node_(add_node_payload_with_same_ip(i), node_operator_id, now)
                .unwrap();
        }
        assert_eq!(
            get_available_add_node_capacity(test_ip.clone(), now),
            0,
            "Capacity should be exhausted after 7 nodes"
        );

        let new_payload = add_node_payload_with_same_ip(8);
        let result_2 = registry.do_add_node_(new_payload.clone(), node_operator_id, now);
        assert!(
            result_2.is_err(),
            "Second node addition should fail due to rate limiting"
        );
        let error_message = result_2.unwrap_err();
        assert!(
            error_message.contains("Capacity exceeded") || error_message.contains("Rate"),
            "Error message should mention rate/capacity limit, got: {error_message}"
        );

        // Act: Try again after 24 hours - should succeed
        let one_day_later = now + std::time::Duration::from_secs(86401);
        let after_day_capacity = get_available_add_node_capacity(test_ip.clone(), one_day_later);
        assert_eq!(
            after_day_capacity, 1,
            "Capacity should be restored after 24 hours"
        );

        let result_3 = registry.do_add_node_(new_payload.clone(), node_operator_id, one_day_later);
        assert!(
            result_3.is_ok(),
            "Node addition should succeed after 24 hours"
        );

        let result_4 = registry.do_add_node_(new_payload, node_operator_id, one_day_later);
        let error_message = result_4.unwrap_err();
        assert!(
            error_message.contains("Capacity exceeded") || error_message.contains("Rate"),
            "Error message should mention rate/capacity limit, got: {error_message}"
        );
    }

    #[test]
    fn test_ip_rate_limiting_different_ips() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        let node_operator_id = PrincipalId::new_user_test_id(1);

        // Add node operator record with sufficient allowance
        let node_operator_record = NodeOperatorRecord {
            max_rewardable_nodes: btreemap! { "type1".to_string() => 10 },
            ..Default::default()
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        let now = now_system_time();

        // Add 8 nodes with different IP address at the same time
        for i in 0..8 {
            let (payload, _) = prepare_add_node_payload(i, NodeRewardType::Type1);
            let result = registry.do_add_node_(payload, node_operator_id, now);
            assert!(
                result.is_ok(),
                "Attempt {i} should succeed but got {result:?}"
            );
        }
    }
}
