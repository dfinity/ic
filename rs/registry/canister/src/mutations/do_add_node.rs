use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use std::net::SocketAddr;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::NodeId;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_utils_basic_sig::conversions as crypto_basicsig_conversions;
use ic_protobuf::{
    crypto::v1::NodePublicKeys,
    registry::{
        crypto::v1::{PublicKey, X509PublicKeyCert},
        node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint, NodeRecord},
        node_operator::v1::NodeOperatorRecord,
    },
};
use ic_registry_keys::{
    make_crypto_node_key, make_crypto_tls_cert_key, make_node_operator_record_key,
    make_node_record_key,
};
use ic_registry_transport::{insert, pb::v1::RegistryValue, update};
use ic_types::crypto::KeyPurpose;

use prost::Message;

impl Registry {
    /// Adds a new node to the registry.
    ///
    /// This method is called directly by the node or tool that needs to
    /// add a node.
    pub fn do_add_node(&mut self, payload: AddNodePayload) -> Result<NodeId, String> {
        println!("{}do_add_node: {:?}", LOG_PREFIX, payload);

        // The steps are now:
        // 1. get the caller ID and check if it is in the registry
        let caller = dfn_core::api::caller();

        let node_operator_key = make_node_operator_record_key(caller);
        let RegistryValue {
            value: node_operator_record,
            version: _,
            deletion_marker: _,
        } = self
            .get(node_operator_key.as_bytes(), self.latest_version())
            .map_or(Err(format!(
                "{}do_add_node: Node Operator Id {:} not found in the registry, aborting node addition.",
                LOG_PREFIX, caller)), Ok)?;

        // 2. check if adding one more node will get us over the cap for the Node
        // Operator
        if decode_registry_value::<NodeOperatorRecord>(node_operator_record.clone()).node_allowance
            == 0
        {
            return Err("Node allowance for this Node Operator is exhausted".to_string());
        }

        // 3. Validate keys and get the node id
        let (node_id, valid_pks) = valid_keys_from_payload(&payload)?;

        println!("{}do_add_node: The node id is {:?}", LOG_PREFIX, node_id);

        // 4. create the Node Record
        let node_record = NodeRecord {
            xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
            http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
            p2p_flow_endpoints: payload
                .p2p_flow_endpoints
                .iter()
                .map(|x| flow_endpoint_from_string(x))
                .collect(),
            node_operator_id: caller.into_vec(),
            prometheus_metrics_http: Some(connection_endpoint_from_string(
                &payload.prometheus_metrics_endpoint,
            )),
            public_api: vec![],
            private_api: vec![],
            prometheus_metrics: vec![],
            xnet_api: vec![],
        };

        // 5. Update registry with the new subnet data
        let add_node_entry = insert(
            make_node_record_key(node_id).as_bytes().to_vec(),
            encode_or_panic(&node_record),
        );

        // 6. Add the crypto keys
        let add_committee_signing_key = insert(
            make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning)
                .as_bytes()
                .to_vec(),
            encode_or_panic(valid_pks.committee_signing_key()),
        );
        let add_node_signing_key = insert(
            make_crypto_node_key(node_id, KeyPurpose::NodeSigning)
                .as_bytes()
                .to_vec(),
            encode_or_panic(valid_pks.node_signing_key()),
        );
        let add_dkg_dealing_key = insert(
            make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption)
                .as_bytes()
                .to_vec(),
            encode_or_panic(valid_pks.dkg_dealing_encryption_key()),
        );
        let add_tls_certificate = insert(
            make_crypto_tls_cert_key(node_id).as_bytes().to_vec(),
            encode_or_panic(valid_pks.tls_certificate()),
        );

        // Finally, update the Node Operator record
        let mut node_operator_record =
            decode_registry_value::<NodeOperatorRecord>(node_operator_record.to_vec());
        node_operator_record.node_allowance -= 1;
        let update_node_operator_record = update(
            node_operator_key.as_bytes().to_vec(),
            encode_or_panic(&node_operator_record),
        );

        let mutations = vec![
            add_node_entry,
            add_committee_signing_key,
            add_node_signing_key,
            add_dkg_dealing_key,
            add_tls_certificate,
            update_node_operator_record,
        ];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        Ok(node_id)
    }
}

/// The payload of an update request to add a new node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddNodePayload {
    // Raw bytes of the protobuf, but these should be PublicKey
    pub node_signing_pk: Vec<u8>,
    pub committee_signing_pk: Vec<u8>,
    pub ni_dkg_dealing_encryption_pk: Vec<u8>,
    // Raw bytes of the protobuf, but these should be X509PublicKeyCert
    pub transport_tls_cert: Vec<u8>,

    pub xnet_endpoint: String,
    pub http_endpoint: String,
    pub p2p_flow_endpoints: Vec<String>,
    pub prometheus_metrics_endpoint: String,
}

/// Parses the ConnectionEndpoint string
///
/// The string is written in form: `ipv4:port` or `[ipv6]:port`.
// TODO(P2P-520): Support parsing the protocol
pub fn connection_endpoint_from_string(endpoint: &str) -> ConnectionEndpoint {
    match endpoint.parse::<SocketAddr>() {
        Err(e) => panic!(
            "Could not convert '{:?}' to a connection endpoint: {:?}",
            endpoint, e
        ),
        Ok(sa) => ConnectionEndpoint {
            ip_addr: sa.ip().to_string(),
            port: sa.port() as u32, // because protobufs don't have u16
            protocol: Protocol::Http1 as i32,
        },
    }
}

/// Parses a P2P flow encoded in a string
///
/// The string is written in form: `flow,ipv4:port` or `flow,[ipv6]:port`.
pub fn flow_endpoint_from_string(endpoint: &str) -> FlowEndpoint {
    let parts = endpoint.splitn(2, ',').collect::<Vec<&str>>();
    println!("Parts are {:?} and {:?}", parts[0], parts[1]);
    let flow = parts[0].parse::<u32>().unwrap();
    match parts[1].parse::<SocketAddr>() {
        Err(e) => panic!(
            "Could not convert '{:?}' to a connection endpoint: {:?}",
            endpoint, e
        ),
        Ok(sa) => FlowEndpoint {
            flow_tag: flow,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: sa.ip().to_string(),
                port: sa.port() as u32, // because protobufs don't have u16
                protocol: Protocol::Http1 as i32,
            }),
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

    // 3. get the node id from the node_signing_pk
    let node_id = crypto_basicsig_conversions::derive_node_id(&node_signing_pk).map_err(|e| {
        format!(
            "node signing public key couldn't be converted to a NodeId: {:?}",
            e
        )
    })?;

    // 4. get the keys for verification -- for that, we need to create
    let node_pks = NodePublicKeys {
        version: 1, // irrelevant
        node_signing_pk: Some(node_signing_pk),
        committee_signing_pk: Some(committee_signing_pk),
        tls_certificate: Some(tls_certificate),
        dkg_dealing_encryption_pk: Some(dkg_dealing_encryption_pk),
    };

    // 5. validate the keys and the node_id
    match ValidNodePublicKeys::try_from(&node_pks, node_id) {
        Ok(valid_pks) => Ok((node_id, valid_pks)),
        Err(e) => Err(format!("Could not validate public keys, due to {:?}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::NodeId;
    use ic_crypto::utils::get_node_keys_or_generate_if_missing;
    use ic_nns_common::registry::encode_or_panic;
    use ic_protobuf::crypto::v1::NodePublicKeys;
    use ic_test_utilities::crypto::temp_dir::temp_dir;
    use lazy_static::lazy_static;

    #[derive(Clone)]
    struct TestData {
        node_id: NodeId,
        node_pks: NodePublicKeys,
    }

    impl TestData {
        fn new() -> Self {
            let temp_dir = temp_dir();
            let (node_pks, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
            Self { node_id, node_pks }
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
            xnet_endpoint: "127.0.0.1:1234".to_string(),
            http_endpoint: "127.0.0.1:8123".to_string(),
            p2p_flow_endpoints: vec!["123,127.0.0.1:10000".to_string()],
            prometheus_metrics_endpoint: "127.0.0.1:5555".to_string(),
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
        let node_signing_pubkey =
            encode_or_panic(&TEST_DATA.clone().node_pks.node_signing_pk.unwrap());
        payload.node_signing_pk = node_signing_pubkey;
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    fn empty_dkg_dealing_key_is_detected() {
        let mut payload = PAYLOAD.clone();
        let node_pks = TEST_DATA.clone().node_pks;
        let node_signing_pubkey = encode_or_panic(&node_pks.node_signing_pk.unwrap());
        let committee_signing_pubkey = encode_or_panic(&node_pks.committee_signing_pk.unwrap());
        payload.node_signing_pk = node_signing_pubkey;
        payload.committee_signing_pk = committee_signing_pubkey;
        assert!(valid_keys_from_payload(&payload).is_err());
    }

    #[test]
    fn empty_tls_cert_is_detected() {
        let mut payload = PAYLOAD.clone();
        let node_pks = TEST_DATA.clone().node_pks;
        let node_signing_pubkey = encode_or_panic(&node_pks.node_signing_pk.unwrap());
        let committee_signing_pubkey = encode_or_panic(&node_pks.committee_signing_pk.unwrap());
        let ni_dkg_dealing_encryption_pubkey =
            encode_or_panic(&node_pks.dkg_dealing_encryption_pk.unwrap());
        payload.node_signing_pk = node_signing_pubkey;
        payload.committee_signing_pk = committee_signing_pubkey;
        payload.ni_dkg_dealing_encryption_pk = ni_dkg_dealing_encryption_pubkey;
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
                protocol: Protocol::Http1 as i32,
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
                protocol: Protocol::Http1 as i32,
            }
        );
    }

    #[test]
    #[should_panic]
    fn no_flow_id_causes_panic() {
        flow_endpoint_from_string("127.0.0.1:8080");
    }

    #[test]
    #[should_panic]
    fn empty_flow_endpoint_string_causes_panic() {
        flow_endpoint_from_string("");
    }

    #[test]
    #[should_panic]
    fn non_numeric_flow_id_causes_panic() {
        flow_endpoint_from_string("abcd,127.0.0.1:8080");
    }

    #[test]
    fn good_flow_id_ipv4() {
        assert_eq!(
            flow_endpoint_from_string("1337,127.0.0.1:8080"),
            FlowEndpoint {
                flow_tag: 1337,
                endpoint: Some(ConnectionEndpoint {
                    ip_addr: "127.0.0.1".to_string(),
                    port: 8080u32,
                    protocol: Protocol::Http1 as i32,
                })
            }
        );
    }
}
