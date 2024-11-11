use crate::{common::LOG_PREFIX, registry::Registry};

use std::net::SocketAddr;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_utils_basic_sig::conversions as crypto_basicsig_conversions;
use ic_protobuf::registry::{
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::{ConnectionEndpoint, IPv4InterfaceConfig, NodeRecord},
};
use idna::domain_to_ascii_strict;

use crate::mutations::node_management::{
    common::{
        get_node_operator_record, make_add_node_registry_mutations,
        make_update_node_operator_mutation, node_exists_with_ipv4, scan_for_nodes_by_ip,
    },
    do_remove_node_directly::RemoveNodeDirectlyPayload,
};
use ic_registry_canister_api::AddNodePayload;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::time::Time;
use prost::Message;

impl Registry {
    /// Adds a new node to the registry.
    ///
    /// This method is called directly by the node or tool that needs to add a node.
    pub fn do_add_node(&mut self, payload: AddNodePayload) -> Result<NodeId, String> {
        // Get the caller ID and check if it is in the registry
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_add_node started: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );
        self.do_add_node_(payload, caller_id)
    }

    fn do_add_node_(
        &mut self,
        payload: AddNodePayload,
        caller_id: PrincipalId,
    ) -> Result<NodeId, String> {
        let mut node_operator_record = get_node_operator_record(self, caller_id)
            .map_err(|err| format!("{}do_add_node: Aborting node addition: {}", LOG_PREFIX, err))?;

        // 1. Clear out any nodes that already exist at this IP.
        // This will only succeed if:
        // - the same NO was in control of the original nodes.
        // - the nodes are no longer in subnets.
        //
        // (We use the http endpoint to be in line with what is used by the
        // release dashboard.)
        let http_endpoint = connection_endpoint_from_string(&payload.http_endpoint);
        let nodes_with_same_ip = scan_for_nodes_by_ip(self, &http_endpoint.ip_addr);
        if !nodes_with_same_ip.is_empty() {
            for node_id in nodes_with_same_ip {
                self.do_remove_node(RemoveNodeDirectlyPayload { node_id }, caller_id);
            }

            // Update the NO record, as the available allowance may have changed.
            node_operator_record = get_node_operator_record(self, caller_id).map_err(|err| {
                format!("{}do_add_node: Aborting node addition: {}", LOG_PREFIX, err)
            })?
        }

        // 2. Check if adding one more node will get us over the cap for the Node Operator
        if node_operator_record.node_allowance == 0 {
            return Err(format!(
                "{}do_add_node: Node allowance for this Node Operator is exhausted",
                LOG_PREFIX
            ));
        }

        // 3. Validate keys and get the node id
        let (node_id, valid_pks) = valid_keys_from_payload(&payload)
            .map_err(|err| format!("{}do_add_node: {}", LOG_PREFIX, err))?;

        // 4. Validate the domain is valid
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

        // 5. If there is an IPv4 config, make sure that the IPv4 is not used by anyone else
        let ipv4_intf_config = payload.public_ipv4_config.clone().map(|ipv4_config| {
            ipv4_config.panic_on_invalid();
            IPv4InterfaceConfig {
                ip_addr: ipv4_config.ip_addr().to_string(),
                gateway_ip_addr: vec![ipv4_config.gateway_ip_addr().to_string()],
                prefix_length: ipv4_config.prefix_length(),
            }
        });
        if let Some(ipv4_config) = ipv4_intf_config.clone() {
            if node_exists_with_ipv4(self, &ipv4_config.ip_addr) {
                return Err(format!(
                    "{}do_add_node: There is already another node with the same IPv4 address ({}).",
                    LOG_PREFIX, ipv4_config.ip_addr,
                ));
            }
        }

        println!("{}do_add_node: The node id is {:?}", LOG_PREFIX, node_id);

        // 6. Create the Node Record
        let node_record = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
            node_operator_id: caller_id.into_vec(),
            hostos_version_id: None,
            chip_id: payload.chip_id.clone(),
            public_ipv4_config: ipv4_intf_config,
            domain,
        };

        // 7. Insert node, public keys, and crypto keys
        let mut mutations = make_add_node_registry_mutations(node_id, node_record, valid_pks);

        // 8. Update the Node Operator record
        node_operator_record.node_allowance -= 1;

        let update_node_operator_record =
            make_update_node_operator_mutation(caller_id, &node_operator_record);

        mutations.push(update_node_operator_record);

        // 9. Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        println!("{}do_add_node finished: {:?}", LOG_PREFIX, payload);

        Ok(node_id)
    }
}

/// Parses the ConnectionEndpoint string
///
/// The string is written in form: `ipv4:port` or `[ipv6]:port`.
pub fn connection_endpoint_from_string(endpoint: &str) -> ConnectionEndpoint {
    match endpoint.parse::<SocketAddr>() {
        Err(e) => panic!(
            "Could not convert {:?} to a connection endpoint: {:?}",
            endpoint, e
        ),
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
    if let Some(idkg_dealing_encryption_pk) = &payload.idkg_dealing_encryption_pk {
        if idkg_dealing_encryption_pk.is_empty() {
            return Err(String::from("idkg_dealing_encryption_pk is empty"));
        };
    }

    // 2. get the keys for verification -- for that, we need to create
    // NodePublicKeys first
    let node_signing_pk = PublicKey::decode(&payload.node_signing_pk[..])
        .map_err(|e| format!("node_signing_pk is not in the expected format: {:?}", e))?;
    let committee_signing_pk =
        PublicKey::decode(&payload.committee_signing_pk[..]).map_err(|e| {
            format!(
                "committee_signing_pk is not in the expected format: {:?}",
                e
            )
        })?;
    let tls_certificate = X509PublicKeyCert::decode(&payload.transport_tls_cert[..])
        .map_err(|e| format!("transport_tls_cert is not in the expected format: {:?}", e))?;
    let dkg_dealing_encryption_pk = PublicKey::decode(&payload.ni_dkg_dealing_encryption_pk[..])
        .map_err(|e| {
            format!(
                "ni_dkg_dealing_encryption_pk is not in the expected format: {:?}",
                e
            )
        })?;
    // TODO(NNS1-1197): Refactor when nodes are provisioned for threshold ECDSA subnets
    let idkg_dealing_encryption_pk =
        if let Some(idkg_de_pk_bytes) = &payload.idkg_dealing_encryption_pk {
            Some(PublicKey::decode(&idkg_de_pk_bytes[..]).map_err(|e| {
                format!(
                    "idkg_dealing_encryption_pk is not in the expected format: {:?}",
                    e
                )
            })?)
        } else {
            None
        };

    // 3. get the node id from the node_signing_pk
    let node_id = crypto_basicsig_conversions::derive_node_id(&node_signing_pk).map_err(|e| {
        format!(
            "node signing public key couldn't be converted to a NodeId: {:?}",
            e
        )
    })?;

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
        Err(e) => Err(format!("Could not validate public keys, due to {:?}", e)),
    }
}

fn now() -> Result<Time, String> {
    let duration = dfn_core::api::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Could not get current time since UNIX_EPOCH: {e}"))?;

    let nanos = u64::try_from(duration.as_nanos())
        .map_err(|e| format!("Current time cannot be converted to u64: {:?}", e))?;

    Ok(Time::from_nanos_since_unix_epoch(nanos))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        common::test_helpers::invariant_compliant_registry, mutations::common::test::TEST_NODE_ID,
    };

    use super::*;
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
    use ic_registry_canister_api::IPv4Config;
    use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
    use ic_registry_transport::insert;
    use lazy_static::lazy_static;
    use prost::Message;

    /// Prepares the payload to add a new node, for tests.
    pub fn prepare_add_node_payload(mutation_id: u8) -> (AddNodePayload, ValidNodePublicKeys) {
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
            xnet_endpoint: format!("128.0.{mutation_id}.1:1234"),
            http_endpoint: format!("128.0.{mutation_id}.1:4321"),
            chip_id: None,
            public_ipv4_config: None,
            domain: Some("api-example.com".to_string()),
            // Unused section follows
            p2p_flow_endpoints: Default::default(),
            prometheus_metrics_endpoint: Default::default(),
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
            node_allowance: 1, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (mut payload, _) = prepare_add_node_payload(1);
        // Set an invalid domain name
        payload.domain = Some("invalid_domain_name".to_string());
        // Act
        let result = registry.do_add_node_(payload.clone(), node_operator_id);
        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Domain name `invalid_domain_name` has invalid format"
        );
    }

    #[test]
    fn should_fail_if_node_allowance_is_zero() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record with node allowance 0.
        let node_operator_record = NodeOperatorRecord {
            node_allowance: 0,
            ..Default::default()
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (payload, _) = prepare_add_node_payload(1);
        // Act
        let result = registry.do_add_node_(payload.clone(), node_operator_id);
        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Node allowance for this Node Operator is exhausted"
        );
    }

    #[test]
    fn should_fail_if_node_operator_is_absent_in_registry() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        let (payload, _) = prepare_add_node_payload(1);
        // Act
        let result = registry.do_add_node_(payload.clone(), node_operator_id);
        // Assert
        assert_eq!(
            result.unwrap_err(),
            "[Registry] do_add_node: Aborting node addition: Node Operator Id node_operator_record_2vxsx-fae not found in the registry."
        );
    }

    #[test]
    fn should_succeed_for_adding_one_node() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            node_allowance: 1, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (payload, _) = prepare_add_node_payload(1);
        // Act
        let node_id: NodeId = registry
            .do_add_node_(payload.clone(), node_operator_id)
            .expect("failed to add a node");
        // Assert node record is correct
        let node_record_expected = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            ..Default::default()
        };
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record, node_record_expected);
        // Assert node allowance counter has decremented
        let node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(node_operator_record.node_allowance, 0);
    }

    #[test]
    fn should_succeed_for_adding_two_nodes_with_different_ips() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            node_allowance: 2, // needed for adding two nodes
            ..Default::default()
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let (payload_1, _) = prepare_add_node_payload(1);
        // Set a different IP for the second node
        let (mut payload_2, _) = prepare_add_node_payload(2);
        payload_2.http_endpoint = "128.0.1.10:4321".to_string();
        assert_ne!(payload_1.http_endpoint, payload_2.http_endpoint);
        // Act: add two nodes with the different IPs
        let node_id_1: NodeId = registry
            .do_add_node_(payload_1.clone(), node_operator_id)
            .expect("failed to add a node");
        let node_id_2: NodeId = registry
            .do_add_node_(payload_2.clone(), node_operator_id)
            .expect("failed to add a node");
        // Assert both node records are in the registry and are correct
        let node_record_expected_1 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_1.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_1.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            ..Default::default()
        };
        let node_record_expected_2 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_2.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_2.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            ..Default::default()
        };
        let node_record_1 = registry.get_node_or_panic(node_id_1);
        assert_eq!(node_record_1, node_record_expected_1);
        let node_record_2 = registry.get_node_or_panic(node_id_2);
        assert_eq!(node_record_2, node_record_expected_2);
        // Assert node allowance counter has decremented by two
        let node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(node_operator_record.node_allowance, 0);
    }

    #[test]
    fn should_succeed_for_adding_two_nodes_with_identical_ips() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            node_allowance: 2, // needed for adding two nodes
            ..Default::default()
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        // Use payloads with the same IPs
        let (payload_1, _) = prepare_add_node_payload(1);
        let (mut payload_2, _) = prepare_add_node_payload(2);
        payload_2.http_endpoint.clone_from(&payload_1.http_endpoint);
        assert_eq!(payload_1.http_endpoint, payload_2.http_endpoint);
        // Act: Add two nodes with the same IPs
        let node_id_1: NodeId = registry
            .do_add_node_(payload_1.clone(), node_operator_id)
            .expect("failed to add a node");
        let node_record_expected_1 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_1.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_1.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            ..Default::default()
        };
        let node_record_1 = registry.get_node_or_panic(node_id_1);
        assert_eq!(node_record_1, node_record_expected_1);
        // Add the second node, this should remove the first one from the registry
        let node_id_2: NodeId = registry
            .do_add_node_(payload_2.clone(), node_operator_id)
            .expect("failed to add a node");
        // Assert second node record is in the registry and is correct
        let node_record_expected_2 = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload_2.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload_2.http_endpoint)),
            node_operator_id: node_operator_id.into(),
            domain: Some("api-example.com".to_string()),
            ..Default::default()
        };
        let node_record_2 = registry.get_node_or_panic(node_id_2);
        assert_eq!(node_record_2, node_record_expected_2);
        // Assert first node record is removed from the registry because of the IP conflict
        assert!(registry
            .get(
                make_node_record_key(node_id_1).as_bytes(),
                registry.latest_version()
            )
            .is_none());
        // Assert node allowance counter has decremented by one (as only one node record was effectively added)
        let node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("failed to get node operator");
        assert_eq!(node_operator_record.node_allowance, 1);
    }

    #[test]
    fn should_fail_for_adding_two_nodes_with_same_ipv4s() {
        // Arrange
        let mut registry = invariant_compliant_registry(0);
        // Add node operator record first
        let node_operator_record = NodeOperatorRecord {
            node_allowance: 2, // Should be > 0 to add a new node
            ..Default::default()
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
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
        let (mut payload_1, _) = prepare_add_node_payload(1);
        payload_1.public_ipv4_config.clone_from(&ipv4_config);

        let (mut payload_2, _) = prepare_add_node_payload(2);
        payload_2.public_ipv4_config = ipv4_config;

        // Act
        let _ = registry.do_add_node_(payload_1.clone(), node_operator_id);
        let e = registry
            .do_add_node_(payload_2.clone(), node_operator_id)
            .unwrap_err();
        assert!(e.contains("do_add_node: There is already another node with the same IPv4 address"));
    }
}
