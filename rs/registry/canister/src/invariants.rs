use crate::common::LOG_PREFIX;
use crate::{mutations::common::decode_registry_value, registry::Registry};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::TryFrom,
    error,
    fmt::{Display, Formatter, Result as FmtResult},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
};

use prost::{alloc::collections::BTreeSet, bytes::Buf, Message};
use url::Url;

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_crypto_key_validation::ValidNodePublicKeys;
use ic_protobuf::{
    crypto::v1::NodePublicKeys,
    registry::{
        conversion_rate::v1::IcpXdrConversionRateRecord,
        crypto::v1::{PublicKey, X509PublicKeyCert},
        node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord},
        node_operator::v1::NodeOperatorRecord,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
        routing_table::v1 as pb,
        subnet::v1::{SubnetListRecord, SubnetRecord},
    },
};
use ic_registry_keys::{
    get_node_record_node_id, make_blessed_replica_version_key,
    make_icp_xdr_conversion_rate_record_key, make_node_operator_record_key, make_node_record_key,
    make_replica_version_key, make_routing_table_record_key, make_subnet_list_record_key,
    make_subnet_record_key, maybe_parse_crypto_node_key, maybe_parse_crypto_tls_cert_key,
    CRYPTO_RECORD_KEY_PREFIX, CRYPTO_TLS_CERT_KEY_PREFIX, NODE_RECORD_KEY_PREFIX, SUBNET_LIST_KEY,
    SUBNET_RECORD_KEY_PREFIX,
};
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{registry_mutation::Type, RegistryMutation};
use ic_types::crypto::KeyPurpose;

/// A representation of the data held by the registry.
/// It is kept in-memory only, for global consistency checks before mutations
/// are finalized.
type RegistrySnapshot = BTreeMap<Vec<u8>, Vec<u8>>;

// All crypto public keys found for the nodes or for the subnets in the
// registry.
type AllPublicKeys = BTreeMap<(NodeId, KeyPurpose), PublicKey>;

// All TLS certificates found for the nodes in the registry.
type AllTlsCertificates = BTreeMap<NodeId, X509PublicKeyCert>;

// Returns all nodes' public keys in the snapshot.
fn get_all_nodes_public_keys(snapshot: &RegistrySnapshot) -> AllPublicKeys {
    let mut pks = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(CRYPTO_RECORD_KEY_PREFIX.as_bytes()) {
            let (node_id, key_purpose) = maybe_parse_crypto_node_key(
                &String::from_utf8(k.to_owned()).expect("invalid crypto node key bytes"),
            )
            .expect("invalid crypto node key");
            let pk = decode_registry_value::<PublicKey>(v.clone());
            pks.insert((node_id, key_purpose), pk);
        }
    }
    pks
}

// Returns all TLS certificates in the snapshot.
fn get_all_tls_certs(snapshot: &RegistrySnapshot) -> AllTlsCertificates {
    let mut certs = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(CRYPTO_TLS_CERT_KEY_PREFIX.as_bytes()) {
            let node_id = maybe_parse_crypto_tls_cert_key(
                &String::from_utf8(k.to_owned()).expect("invalid tls cert key bytes"),
            )
            .expect("invalid tls cert key");
            let cert = decode_registry_value::<X509PublicKeyCert>(v.clone());
            certs.insert(node_id, cert);
        }
    }
    certs
}

/// Returns all node records from the snapshot.
fn get_node_records(snapshot: &RegistrySnapshot) -> BTreeMap<NodeId, NodeRecord> {
    let mut result = BTreeMap::<NodeId, NodeRecord>::new();
    for key in snapshot.keys() {
        if let Some(principal_id) =
            get_node_record_node_id(String::from_utf8(key.clone()).unwrap().as_str())
        {
            // This is indeed a node record
            let node_record = match snapshot.get(key) {
                Some(node_record_bytes) => {
                    decode_registry_value::<NodeRecord>(node_record_bytes.clone())
                }
                None => panic!("Cannot fetch node record for an existing key"),
            };
            let node_id = NodeId::from(principal_id);
            result.insert(node_id, node_record);
        }
    }
    result
}

#[derive(Debug)]
struct InvariantCheckError {
    msg: String,
    source: Option<Box<dyn error::Error + 'static>>,
}

impl Display for InvariantCheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "InvariantCheckError: {:?}", self.msg)
    }
}

// TODO(NNS1-488) Improved error handling
impl error::Error for InvariantCheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl Registry {
    pub fn check_global_invariants(&self, mutations: &[RegistryMutation]) {
        println!("{}check_global_invariants: {:?}", LOG_PREFIX, mutations);

        let snapshot = self.take_latest_snapshot_with_mutations(mutations);
        // Conversion rate invariants
        self.check_conversion_rate_invariants(&snapshot);

        // Node invariants
        // TODO(NNS1-202): re-enable this check when cd hourly test issues are sorted
        // out. if let Err(e) = check_node_crypto_keys_invariants(&snapshot) {
        //     // TODO(NNS1-202): `expect` or `panic!` instead of `println!`
        //    println!("{}check_node_crypto_keys_invariants: {}", LOG_PREFIX, e)
        // }

        // Node operator invariants
        self.check_node_operator_invariants(&snapshot, false);

        self.check_routing_table_invariants(&snapshot);

        // Subnet invariants
        self.check_subnet_invariants(&snapshot);

        // Replica version invariants
        Self::check_replica_version_records(&snapshot, false);

        if let Err(e) = Self::check_endpoints_invariants(&snapshot, false) {
            panic!("{}", e.msg);
        }
    }

    /// Node records are valid with connection endpoints containing
    /// syntactically correct data ("ip_addr" field parses as an IP address,
    /// "port" field is <= 65535):
    ///    * An Xnet endpoint entry exists (either .xnet or .xnet_api)
    ///    * A HTTP endpoint entry exists (either .http or .public_api)
    ///    * IP address is not 0.0.0.0 ("unspecified" address)
    ///    * IP address is not 255.255.255.255 ("broadcast" address)
    ///    * We might want to ban others as well: must be global, not link-local
    ///    * IP address and ports are distinct (i.e., no two nodes share the
    ///      same ip:port pairs for anything, no node has the same ip:port for
    ///      multiple endpoints), i.e., all IP:port-pairs of all nodes are
    ///      mutually exclusive (this includes the prometheus-endpoints)
    /// Strict check imposes stricter rules on IP addresses
    fn check_endpoints_invariants(
        snapshot: &RegistrySnapshot,
        strict: bool,
    ) -> Result<(), InvariantCheckError> {
        let mut valid_endpoints = BTreeSet::<(IpAddr, u16)>::new();
        for (node_id, node_record) in get_node_records(&snapshot) {
            let mut node_endpoints = BTreeSet::<(IpAddr, u16)>::new();
            let mut endpoints_to_check = Vec::<ConnectionEndpoint>::new();

            if node_record.xnet.is_none() && node_record.xnet_api.is_empty() {
                return Err(InvariantCheckError {
                    msg: format!("No Xnet endpoint found for node {}", node_id),
                    source: None,
                });
            }

            if node_record.http.is_none() && node_record.public_api.is_empty() {
                return Err(InvariantCheckError {
                    msg: format!("No HTTP/Public API endpoint found for node {}", node_id),
                    source: None,
                });
            }

            // Xnet endpoint
            if node_record.xnet.is_some() {
                endpoints_to_check.push(node_record.xnet.unwrap());
            }

            // HTTP endpoint
            if node_record.http.is_some() {
                endpoints_to_check.push(node_record.http.unwrap());
            }

            // Private API endpoints
            endpoints_to_check.extend(node_record.private_api);

            // Public API endpoints
            endpoints_to_check.extend(node_record.public_api);

            // Xnet API endpoints
            endpoints_to_check.extend(node_record.xnet_api);

            // Prometheus metrics endpoints
            endpoints_to_check.extend(node_record.prometheus_metrics);

            // Prometheus metrics HTTP endpoint
            if node_record.prometheus_metrics_http.is_some() {
                endpoints_to_check.push(node_record.prometheus_metrics_http.unwrap());
            }

            // P2P endpoints
            //    * For each of the flow endpoints that belong to one node, the identifier
            //      must be distinct (a node may have multiple flow endpoints). That is, the
            //      address-port-pair of different flow endpoints of the same node can be
            //      the same, but the flow identifier must be different. However, 2 nodes
            //      can have he same flow endpoints.
            let mut flow_ids = BTreeSet::<u32>::new();
            for endpoint in node_record.p2p_flow_endpoints {
                let connection_endpoint = match endpoint.endpoint {
                    None => {
                        return Err(InvariantCheckError {
                            msg: format!(
                                "No connection endpoint specified for flow ({:?})",
                                endpoint.flow_tag
                            ),
                            source: None,
                        })
                    }
                    Some(ep) => ep,
                };
                validate_endpoint(&connection_endpoint, strict)?;

                if flow_ids.contains(&endpoint.flow_tag) {
                    return Err(InvariantCheckError {
                        msg: format!(
                            "Duplicate flow_tag for p2p flow endpoints: {}",
                            endpoint.flow_tag
                        ),
                        source: None,
                    });
                }
                flow_ids.insert(endpoint.flow_tag);
            }

            if strict {
                // Validate all endpoints of this node (excluding p2p flow endpoints which are
                // validated separately)
                for endpoint in endpoints_to_check {
                    if !node_endpoints.insert(validate_endpoint(&endpoint, strict)?) {
                        return Err(InvariantCheckError {
                            msg: format!(
                                "Duplicate endpoint ({:?}, {:?})",
                                &endpoint.ip_addr, &endpoint.port
                            ),
                            source: None,
                        });
                    }
                }
            }

            // Check that there is no intersection with other nodes
            if !node_endpoints.is_disjoint(&valid_endpoints) {
                return Err(InvariantCheckError {
                    msg: format!(
                        "Duplicate endpoints detected across nodes (for node {})",
                        node_id
                    ),
                    source: None,
                });
            }

            // All is good -- add current endpoints to global set
            valid_endpoints.append(&mut node_endpoints);
        }

        Ok(())
    }

    /// If there is a proposal for a new conversion rate, the function makes
    /// sure that the timestamp of the proposed conversion rate record is
    /// larger than the current timestamp in the current record.
    fn check_conversion_rate_invariants(&self, snapshot: &RegistrySnapshot) {
        // Check if there is a conversion rate in the mutated snapshot:
        if let Some(proposed_conversion_rate_bytes) =
            snapshot.get(&make_icp_xdr_conversion_rate_record_key().into_bytes())
        {
            // Decode the proposed conversion rate:
            let proposed_conversion_rate = decode_registry_value::<IcpXdrConversionRateRecord>(
                proposed_conversion_rate_bytes.clone(),
            );
            // Assert that the rate is positive (this is an additional sanity check as the
            // rate should always be at least `minimum_icp_xdr_rate`):
            assert!(proposed_conversion_rate.xdr_permyriad_per_icp > 0);
            // Check if there is a conversion rate in the registry (without mutations):
            if let Some(conversion_rate_bytes) = self.get(
                &make_icp_xdr_conversion_rate_record_key().into_bytes(),
                self.latest_version(),
            ) {
                // Decode the current conversion rate:
                let conversion_rate = decode_registry_value::<IcpXdrConversionRateRecord>(
                    conversion_rate_bytes.clone().value,
                );
                // Assert that the records are equal, i.e., there is no mutation, or the
                // timestamp is larger in the proposed conversion rate:
                assert!(
                    proposed_conversion_rate == conversion_rate
                        || proposed_conversion_rate.timestamp_seconds
                            > conversion_rate.timestamp_seconds
                );
            }
        }
    }

    fn take_latest_snapshot_with_mutations(
        &self,
        mutations: &[RegistryMutation],
    ) -> RegistrySnapshot {
        let mut snapshot = self.take_latest_snapshot();
        for mutation in mutations.iter() {
            let key = &mutation.key;
            match Type::from_i32(mutation.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => {
                    snapshot.insert(key.to_vec(), mutation.value.clone());
                }
                Type::Delete => {
                    snapshot.remove(&key.to_vec());
                }
            }
        }
        snapshot
    }

    fn take_latest_snapshot(&self) -> RegistrySnapshot {
        let mut snapshot = RegistrySnapshot::new();

        for (key, values) in self.store.iter() {
            let registry_value = values.back().unwrap();
            if !registry_value.deletion_marker {
                snapshot.insert(key.to_vec(), registry_value.value.clone());
            }
        }
        snapshot
    }

    /// A predicate on the replica version records contained in a registry
    /// snapshot.
    ///
    /// For each replica version that is either referred to in an SubnetRecord
    /// of a subnet that is listed in the subnet list or that is contained
    /// the BlessedReplicaVersions-List, the following is checked:
    ///
    /// * The corresponding ReplicaVersionRecord exists.
    /// * At least one of either the replica, nodemanager or release package is
    ///   specified.
    /// * Each set URL is well-formed.
    /// * Each set hash is a well-formed hex-encoded SHA256 value.
    fn check_replica_version_records(snapshot: &RegistrySnapshot, strict: bool) {
        let mut versions = Self::get_all_versions_of_subnets(snapshot);
        let blessed_version_ids = snapshot
            .get(make_blessed_replica_version_key().as_bytes())
            .map(|bytes| {
                let version_list: BlessedReplicaVersions =
                    Self::decode_pb_message(bytes.as_slice());
                version_list.blessed_version_ids
            })
            .unwrap_or_else(Vec::default);
        versions.extend(blessed_version_ids);
        versions.dedup();

        for version in versions {
            let r = Self::get_replica_version_record(snapshot, version);

            // An entry where all URLs are unspecified is invalid.
            if r.binary_url.is_empty()
                && r.node_manager_binary_url.is_empty()
                && r.release_package_url.is_empty()
            {
                panic!("At least one URL must be set.");
            }

            if strict {
                // Assert that URL and hash of the replica binary is well-formed.
                // Allow file:/// URLs.
                Self::assert_valid_url_and_hash(&r.binary_url, &r.sha256_hex, true);
                // dito for nodemanager. Allow file:/// URLs.
                Self::assert_valid_url_and_hash(
                    &r.node_manager_binary_url,
                    &r.node_manager_sha256_hex,
                    true,
                );
                // Check whether release package URL (iso image) and corresponding
                // hash is well-formed. As file-based URLs are only used in
                // test-deployments, we disallow file:/// URLs.
                Self::assert_valid_url_and_hash(
                    &r.release_package_url,
                    &r.release_package_sha256_hex,
                    false,
                );
            }
        }
    }

    fn get_replica_version_record(
        snapshot: &RegistrySnapshot,
        version: String,
    ) -> ReplicaVersionRecord {
        Self::get_registry_value(snapshot, make_replica_version_key(version.clone()))
            .unwrap_or_else(|| panic!("Could not find replica version: {}", version))
    }

    /// Returns the list of replica versions where each version is referred to
    /// by at least one subnet.
    fn get_all_versions_of_subnets(snapshot: &RegistrySnapshot) -> Vec<String> {
        Self::get_subnet_ids(snapshot)
            .iter()
            .map(|subnet_id| Self::get_subnet_record(snapshot, *subnet_id).replica_version_id)
            .collect()
    }

    fn get_subnet_ids(snapshot: &RegistrySnapshot) -> Vec<SubnetId> {
        Self::get_registry_value::<SubnetListRecord>(snapshot, make_subnet_list_record_key())
            .map(|r| {
                r.subnets
                    .iter()
                    .map(|s| SubnetId::from(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
                    .collect()
            })
            .unwrap_or_else(Vec::new)
    }

    fn get_subnet_record(snapshot: &RegistrySnapshot, subnet_id: SubnetId) -> SubnetRecord {
        Self::get_registry_value(snapshot, make_subnet_record_key(subnet_id))
            .unwrap_or_else(|| panic!("Could not get subnet record for subnet: {}", subnet_id))
    }

    fn assert_valid_url_and_hash(url: &str, hash: &str, allow_file_url: bool) {
        // Either both, the URL and the hash are set, or both are not set.
        if (url.is_empty() as i32 ^ hash.is_empty() as i32) > 0 {
            panic!("Either both, an url and a hash must be set, or none.");
        }
        if url.is_empty() {
            return;
        }

        Self::assert_sha256(hash);
        // File URLs are used in test deployments. We only disallow non-ASCII.
        if allow_file_url && url.starts_with("file://") {
            if !url.is_ascii() {
                panic!("file-URL contains non-ASCII characters.");
            }
            return;
        }

        let _ = Url::parse(url).expect("Could not parse URL.");
    }

    fn assert_sha256(s: &str) {
        if s.len() != 64 {
            panic!(format!(
                "Hash value should be 64 characters long. (actual len: {})",
                s.len()
            ));
        }
        if s.bytes().any(|x| !x.is_ascii_hexdigit()) {
            panic!(format!(
                "Hash contains at least one invalid character: `{}`",
                s
            ));
        }
    }

    fn get_registry_value<T: Message + Default>(
        snapshot: &RegistrySnapshot,
        key: String,
    ) -> Option<T> {
        snapshot
            .get(key.as_bytes())
            .map(|v| Self::decode_pb_message(v.as_slice()))
    }

    fn decode_pb_message<T: Message + Default, B: Buf>(msg: B) -> T {
        T::decode(msg).expect("Could not decode PB message.")
    }

    /// Routing table invariants hold if it is well formed
    fn check_routing_table_invariants(&self, snapshot: &RegistrySnapshot) {
        match get_routing_table(snapshot).well_formed() {
            Ok(()) => {}
            Err(error) => panic!("Routing table is not well formed {:?}", error),
        };
    }

    /// Node operator invariants hold iff:
    ///    * All node operators referred to in node records are registered
    fn check_node_operator_invariants(&self, snapshot: &RegistrySnapshot, strict: bool) {
        if strict {
            for node_record in get_all_node_records(snapshot) {
                let node_operator_id =
                    PrincipalId::try_from(node_record.node_operator_id.clone()).unwrap();
                let key = make_node_operator_record_key(node_operator_id);
                match snapshot.get(key.as_bytes()) {
                    Some(node_operator_record_vec) => {
                        decode_registry_value::<NodeOperatorRecord>(
                            (*node_operator_record_vec).clone(),
                        );
                    }
                    None => {
                        panic!("Node operator {:} not in snapshot", node_operator_id);
                    }
                }
            }
        }
    }

    /// Subnet invariants hold iff:
    ///    * Subnet membership contains no repetition
    ///    * Each node belongs to at most one subnet
    ///    * Each subnet contains at least one node
    ///    * There is at least one system subnet
    ///    * Each subnet in the registry occurs in the subnet list and vice
    ///      versa
    fn check_subnet_invariants(&self, snapshot: &RegistrySnapshot) {
        let mut accumulated_nodes_in_subnets: HashSet<NodeId> = HashSet::new();
        let mut system_subnet_count = 0;
        let mut subnet_records_map = get_subnet_records_map(snapshot);
        let subnet_id_list = get_subnet_id_list(snapshot);
        for subnet_id_vec in &subnet_id_list {
            let subnet_id = SubnetId::from(PrincipalId::try_from(subnet_id_vec.clone()).unwrap());
            // Subnets in the subnet list have a subnet record
            let subnet_record = subnet_records_map
                .remove(&make_subnet_record_key(subnet_id).into_bytes())
                .unwrap_or_else(|| {
                    panic!(
                        "Subnet {:} is in subnet list but no record exists",
                        subnet_id
                    )
                });
            let num_nodes = subnet_record.membership.len();
            let mut subnet_members: HashSet<NodeId> = subnet_record
                .membership
                .iter()
                .map(|v| NodeId::from(PrincipalId::try_from(v).unwrap()))
                .collect();

            // Subnet membership must contain registered nodes only
            subnet_members.retain(|&k| {
                let node_key = make_node_record_key(k);
                snapshot.contains_key(node_key.as_bytes())
            });

            // Each node appears at most once in a subnet membership
            if num_nodes > subnet_members.len() {
                panic!("Repeated nodes in subnet {:}", subnet_id);
            }
            // Each subnet contains at least one node
            if subnet_members.is_empty() {
                panic!("No node in subnet {:}", subnet_id);
            }
            let intersection = accumulated_nodes_in_subnets
                .intersection(&subnet_members)
                .collect::<HashSet<_>>();
            // Each node appears at most once in at most one subnet membership
            if !intersection.is_empty() {
                panic!(
                    "Nodes in subnet {:} also belong to other subnets",
                    subnet_id
                );
            }
            accumulated_nodes_in_subnets.extend(&subnet_members);
            // Count occurrence of system subnets
            if subnet_record.subnet_type == i32::from(SubnetType::System) {
                system_subnet_count += 1;
            }
        }
        // There is at least one system subnet
        if system_subnet_count < 1 {
            panic!("No system subnet");
        }
        // TODO (OR1-22): uncomment the following when NNS disaster recovery
        // has fully been implemented which guarantees that no unnecessary
        // subnet records are in the registry.
        // All subnet records have been listed
        // if !subnet_records_map.is_empty() {
        //    panic!(
        //        "Subnets {:?} has not been listed in the snapshot",
        //       subnet_records_map.keys()
        //    );
        //}
    }
}

// Return list of subnet ids in the snapshot
fn get_subnet_id_list(snapshot: &RegistrySnapshot) -> Vec<Vec<u8>> {
    match snapshot.get(SUBNET_LIST_KEY.as_bytes()) {
        Some(subnet_list_record_vec) => {
            decode_registry_value::<SubnetListRecord>((*subnet_list_record_vec).clone()).subnets
        }
        None => panic!("No subnet list in snapshot"),
    }
}

// Return all node records in the snapshot
fn get_all_node_records(snapshot: &RegistrySnapshot) -> Vec<NodeRecord> {
    let mut nodes: Vec<NodeRecord> = Vec::new();
    for (k, v) in snapshot {
        if k.starts_with(NODE_RECORD_KEY_PREFIX.as_bytes()) {
            let record = decode_registry_value::<NodeRecord>(v.clone());
            nodes.push(record);
        }
    }
    nodes
}

// Return all subnet records in the snapshot
fn get_subnet_records_map(snapshot: &RegistrySnapshot) -> BTreeMap<Vec<u8>, SubnetRecord> {
    let mut subnets: BTreeMap<Vec<u8>, SubnetRecord> = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(SUBNET_RECORD_KEY_PREFIX.as_bytes()) {
            let record = decode_registry_value::<SubnetRecord>(v.clone());
            subnets.insert((*k).clone(), record);
        }
    }
    subnets
}

// Return routing table from snapshot
fn get_routing_table(snapshot: &RegistrySnapshot) -> RoutingTable {
    match snapshot.get(make_routing_table_record_key().as_bytes()) {
        Some(routing_table_vec) => RoutingTable::try_from(
            decode_registry_value::<pb::RoutingTable>((*routing_table_vec).clone()),
        )
        .unwrap(),
        None => panic!("No routing table in snapshot"),
    }
}

// Checks node invariants related to crypto keys:
//  * every node has the required public keys and these keys are well formed and
//    valid. The required keys are:
//     - node signing public key
//     - committee signing public key
//     - DKG dealing encryption public key
//     - TLS certificate
//  * every node's id (node_id) is correctly derived from its node signing
//    public key
//  * all the public keys and all the TLS certificates belonging to the all the
//    nodes are unique
//
// TODO(NNS1-202): should we also check that there are no "left-over" public
// keys or TLS certificates in the registry, i.e. every key/certificate is
// assigned to some existing node?
#[allow(dead_code)]
fn check_node_crypto_keys_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let nodes = get_node_records(snapshot);
    let mut pks = get_all_nodes_public_keys(snapshot);
    let mut certs = get_all_tls_certs(snapshot);
    let mut unique_pks: BTreeMap<Vec<u8>, NodeId> = BTreeMap::new();
    let mut unique_certs: HashMap<Vec<u8>, NodeId> = HashMap::new();

    for node_id in nodes.keys() {
        let valid_node_pks = check_node_keys(node_id, &mut pks, &mut certs)?;
        check_node_keys_are_unique(&valid_node_pks, &mut unique_pks)?;
        check_tls_certs_are_unique(&valid_node_pks, &mut unique_certs)?;
    }
    Ok(())
}

fn check_node_keys(
    node_id: &NodeId,
    pks: &mut AllPublicKeys,
    certs: &mut AllTlsCertificates,
) -> Result<ValidNodePublicKeys, InvariantCheckError> {
    let npk = NodePublicKeys {
        version: 0,
        node_signing_pk: pks.remove(&(*node_id, KeyPurpose::NodeSigning)),
        committee_signing_pk: pks.remove(&(*node_id, KeyPurpose::CommitteeSigning)),
        dkg_dealing_encryption_pk: pks.remove(&(*node_id, KeyPurpose::DkgDealingEncryption)),
        tls_certificate: certs.remove(node_id),
    };
    let vnpk = ValidNodePublicKeys::try_from(&npk, *node_id).map_err(|e| InvariantCheckError {
        msg: format!(
            "crypto key validation for node {} failed with {}",
            node_id, e
        ),
        source: None,
    })?;
    Ok(vnpk)
}

fn check_node_keys_are_unique(
    node_pks: &ValidNodePublicKeys,
    unique_pks: &mut BTreeMap<Vec<u8>, NodeId>,
) -> Result<(), InvariantCheckError> {
    for pk in &[
        node_pks.node_signing_key(),
        node_pks.committee_signing_key(),
        node_pks.dkg_dealing_encryption_key(),
    ] {
        let mut pk_bytes: Vec<u8> = vec![];
        pk.encode(&mut pk_bytes).expect("encode cannot fail.");
        match unique_pks.get(&pk_bytes) {
            Some(existing_id) => {
                return Err(InvariantCheckError {
                    msg: format!(
                        "nodes {} and {} use the same public key {:?}",
                        existing_id,
                        node_pks.node_id(),
                        pk
                    ),
                    source: None,
                })
            }
            None => {
                unique_pks.insert(pk_bytes, node_pks.node_id());
            }
        }
    }
    Ok(())
}

fn check_tls_certs_are_unique(
    node_pks: &ValidNodePublicKeys,
    unique_certs: &mut HashMap<Vec<u8>, NodeId>,
) -> Result<(), InvariantCheckError> {
    let mut cert_bytes: Vec<u8> = vec![];
    node_pks
        .tls_certificate()
        .encode(&mut cert_bytes)
        .expect("encode cannot fail.");
    match unique_certs.get(&cert_bytes) {
        Some(existing_id) => Err(InvariantCheckError {
            msg: format!(
                "nodes {} and {} use the same TLS certificate {:?}",
                existing_id,
                node_pks.node_id(),
                node_pks.tls_certificate()
            ),
            source: None,
        }),
        None => {
            unique_certs.insert(cert_bytes, node_pks.node_id());
            Ok(())
        }
    }
}

const IPV4_STRICT_CHECKS: [(Ipv4Addr, Ipv4Addr, &str); 6] = [
    (
        Ipv4Addr::new(240, 0, 0, 0),
        Ipv4Addr::new(0xf0, 0, 0, 0),
        "RESERVED - IETF RFC 1112",
    ),
    (
        Ipv4Addr::new(192, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        "IETF PROTOCOL ASSIGNMENT - IETF RFC 6890",
    ),
    (
        Ipv4Addr::new(198, 18, 0, 0),
        Ipv4Addr::new(255, 0xfe, 0, 0),
        "BENCHMARKING - IETF RFC 2544 errata 423",
    ),
    (
        Ipv4Addr::new(192, 0, 2, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        "DOCUMENTATION - IETF RFC 5737 - TEST-NET-1",
    ),
    (
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        "DOCUMENTATION - IETF RFC 5737 - TEST-NET-2",
    ),
    (
        Ipv4Addr::new(203, 0, 113, 0),
        Ipv4Addr::new(255, 255, 255, 0),
        "DOCUMENTATION - IETF RFC 5737 - TEST-NET-3",
    ),
];

const IPV6_STRICT_CHECKS: [(Ipv6Addr, Ipv6Addr, &str); 4] = [
    (
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0xffff, 0xc000, 0, 0, 0, 0, 0, 0),
        "UNICAST LINK LOCAL - IETF RFC 4291 sec. 2.4",
    ),
    (
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0xfffe, 0, 0, 0, 0, 0, 0, 0),
        "UNICAST UNIQUE LOCAL - IETF RFC 4193",
    ),
    (
        Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0xfffe, 0, 0, 0, 0, 0, 0, 0),
        "UNICAST SITE LOCAL - IETF RFC 4291 sec. 2.5.7",
    ),
    (
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
        "IPv6 DOCUMENTATION - IETF RFC 3849",
    ),
];

/// A helper function that validates invariants for a single endpoint
///    * IP address is valid (either v4 or v6, correct format)
///    * Port number is valid (<= 65535)
///    * IP address is not unspecified
///    * IP address is not broadcast
///    * IP address is not a multicast address
///
/// Strict check also checks that:
///    * IPv4 address is not private, reserved, documentation address,
///      link-local, benchmarking
///    * IPv6 address is not link-local or unique-local unicast address
fn validate_endpoint(
    endpoint: &ConnectionEndpoint,
    strict: bool,
) -> Result<(IpAddr, u16), InvariantCheckError> {
    if endpoint.protocol() != Protocol::Http1
        && endpoint.protocol() != Protocol::Http1Tls13
        && endpoint.protocol() != Protocol::P2p1Tls13
    {
        return Err(InvariantCheckError {
            msg: format!(
                "Endpoint protocol is not supported: {:?}",
                endpoint.protocol
            ),
            source: None,
        });
    }

    let ip: IpAddr = endpoint
        .ip_addr
        .parse::<IpAddr>()
        .map_err(|e| InvariantCheckError {
            msg: format!("Failed to parse IP address: {:?}", endpoint.ip_addr),
            source: Some(Box::new(e)),
        })?;

    let port = u16::try_from(endpoint.port).map_err(|e| InvariantCheckError {
        msg: format!("Failed to parse port: {:?}", endpoint.port),
        source: Some(Box::new(e)),
    })?;

    if ip.is_unspecified() {
        return Err(InvariantCheckError {
            msg: format!("IP Address {:?} is unspecified", ip),
            source: None,
        });
    }

    if let IpAddr::V4(ipv4) = ip {
        if ipv4.is_broadcast() {
            return Err(InvariantCheckError {
                msg: format!("IP Address {:?} is a broadcast address", ip),
                source: None,
            });
        }

        if ipv4.is_multicast() {
            return Err(InvariantCheckError {
                msg: format!("IP Address {:?} is a multicast address", ip),
                source: None,
            });
        }
    } else if let IpAddr::V6(ipv6) = ip {
        let multicast_addr_and_mask = Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0);
        if mask_ipv6(ipv6, multicast_addr_and_mask) == multicast_addr_and_mask {
            return Err(InvariantCheckError {
                msg: format!("IP Address {:?} is a multicast address", ip),
                source: None,
            });
        }
    }

    if strict {
        if ip.is_loopback() {
            return Err(InvariantCheckError {
                msg: format!("IP Address {:?} is the loopback address", ip),
                source: None,
            });
        }

        if let IpAddr::V4(ipv4) = ip {
            if ipv4.is_private() {
                return Err(InvariantCheckError {
                    msg: format!("IP Address {:?} is a private address", ip),
                    source: None,
                });
            }
            if ipv4.is_link_local() {
                return Err(InvariantCheckError {
                    msg: format!("IP Address {:?} is a link local address", ip),
                    source: None,
                });
            }
            for (addr, mask, res_type) in &IPV4_STRICT_CHECKS {
                if mask_ipv4(ipv4, *mask) == *addr {
                    return Err(InvariantCheckError {
                        msg: format!("IP Address {:?} is not allowed ({})", ip, res_type),
                        source: None,
                    });
                }
            }
        } else if let IpAddr::V6(ipv6) = ip {
            for (addr, mask, res_type) in &IPV6_STRICT_CHECKS {
                if mask_ipv6(ipv6, *mask) == *addr {
                    return Err(InvariantCheckError {
                        msg: format!("IP Address {:?} is not allowed ({})", ip, res_type),
                        source: None,
                    });
                }
            }
        }
    }

    Ok((ip, port))
}

fn mask_ipv4(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let octets: Vec<u8> = addr
        .octets()
        .iter()
        .zip(mask.octets().iter())
        .map(|(a, m)| a & m)
        .collect();

    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
}

fn mask_ipv6(addr: Ipv6Addr, mask: Ipv6Addr) -> Ipv6Addr {
    let segments: Vec<u16> = addr
        .segments()
        .iter()
        .zip(mask.segments().iter())
        .map(|(a, m)| a & m)
        .collect();

    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutations::do_add_node::connection_endpoint_from_string;
    use std::str::FromStr;

    use dfn_core::api::PrincipalId;
    use ic_crypto::utils::get_node_keys_or_generate_if_missing;
    use ic_nns_common::registry::encode_or_panic;
    use ic_nns_constants::ids::TEST_USER1_PRINCIPAL;
    use ic_protobuf::registry::{
        node::v1::FlowEndpoint, node_operator::v1::NodeOperatorRecord,
        routing_table::v1::RoutingTable, subnet::v1::GossipConfig,
    };
    use ic_registry_keys::{
        make_crypto_node_key, make_crypto_tls_cert_key, make_node_operator_record_key,
        make_node_record_key, make_routing_table_record_key, make_subnet_record_key,
    };
    use ic_registry_transport::{
        delete, insert,
        pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
        Error,
    };
    use ic_test_utilities::crypto::temp_dir::temp_dir;

    #[test]
    #[should_panic(expected = "No routing table in snapshot")]
    fn routing_table_invariants_do_not_hold() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });
        let registry = Registry::new();
        let mutation = vec![insert(key.as_bytes(), &value)];
        registry.check_global_invariants(&mutation);
    }

    /// This helper function creates a valid registry.
    fn create_valid_registry() -> Registry {
        let mut registry = Registry::new();
        let key1 = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value1 = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });
        let mutation1 = vec![insert(key1.as_bytes(), &value1)];
        assert!(try_mutate(&mut registry, &mutation1).is_empty());

        let snapshot = registry.take_latest_snapshot_with_mutations(&[]);

        let snapshot_data = snapshot.get(key1.as_bytes());
        assert!(snapshot_data.is_some());

        let node_id = NodeId::from(
            PrincipalId::from_str(
                "2swaj-5toxl-53gkj-bl5z7-uophv-ok4yw-s5onf-nbf5h-uorsd-xnshe-aae",
            )
            .unwrap(),
        );
        let key2 = make_node_record_key(node_id);
        let value2 = encode_or_panic(&NodeRecord {
            node_operator_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string("127.0.0.1:1234")),
            http: Some(connection_endpoint_from_string("127.0.0.1:8123")),
            p2p_flow_endpoints: vec![],
            public_api: vec![],
            private_api: vec![],
            xnet_api: vec![],
            prometheus_metrics_http: Some(connection_endpoint_from_string("127.0.0.1:5555")),
            prometheus_metrics: vec![],
        });
        let mutation2 = vec![insert(key2.as_bytes(), &value2)];
        assert!(try_mutate(&mut registry, &mutation2).is_empty());

        let routing_table = RoutingTable::default();
        let key3 = make_routing_table_record_key();
        let value3 = encode_or_panic(&routing_table);
        let mutation3 = vec![insert(key3.as_bytes(), &value3)];
        assert!(try_mutate(&mut registry, &mutation3).is_empty());

        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );
        let key4 = make_subnet_record_key(subnet_id);
        let value4 = encode_or_panic(&SubnetRecord {
            membership: vec![node_id]
                .iter()
                .map(|id| id.get().into_vec())
                .collect::<Vec<_>>(),
            initial_dkg_transcript: Some(Default::default()),
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(GossipConfig {
                max_artifact_streams_per_peer: 10,
                max_chunk_wait_ms: 100,
                max_duplicity: 2,
                max_chunk_size: 10,
                receive_check_cache_size: 1024,
                pfn_evaluation_period_ms: 100,
                registry_poll_period_ms: 100,
                retransmission_request_ms: 100,
            }),
            start_as_nns: false,
            subnet_type: SubnetType::System.into(),
            is_halted: false,
        });
        let mutation4 = vec![insert(key4.as_bytes(), &value4)];
        assert!(try_mutate(&mut registry, &mutation4).is_empty());

        const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";
        let key5 = make_replica_version_key("version_42");
        let value5 = encode_or_panic(&ReplicaVersionRecord {
            sha256_hex: MOCK_HASH.into(),
            binary_url: "http://megaupload.com/replica_version_42_definitely_not_a_scam"
                .to_string(),
            node_manager_binary_url: "http://nodemanager.tar.gz".into(),
            node_manager_sha256_hex: MOCK_HASH.into(),
            release_package_url: "http://release_package.tar.gz".into(),
            release_package_sha256_hex: MOCK_HASH.into(),
        });
        let mutation5 = vec![insert(key5.as_bytes(), &value5)];
        assert!(try_mutate(&mut registry, &mutation5).is_empty());

        let mut subnet_list_record = SubnetListRecord::default();
        subnet_list_record.subnets.push(subnet_id.get().to_vec());
        let key6 = SUBNET_LIST_KEY;
        let value6 = encode_or_panic(&subnet_list_record);
        let mutation6 = vec![insert(key6.as_bytes(), &value6)];
        assert!(try_mutate(&mut registry, &mutation6).is_empty());
        registry
    }

    #[test]
    /// Create a minimal set of registry entries that pass the invariants check.
    /// This includes a system type subnet with one node belonging to a node
    /// operator with allowance 0, a subnet list with the aforementioned subnet
    /// and an empty routing table.
    fn invariants_hold() {
        let registry = create_valid_registry();
        registry.check_global_invariants(&[]);
    }

    /// Shorthand to try a mutation with no preconditions.
    fn try_mutate(registry: &mut Registry, mutations: &[RegistryMutation]) -> Vec<Error> {
        registry
            .maybe_apply_mutations(RegistryAtomicMutateRequest {
                preconditions: vec![],
                mutations: mutations.to_vec(),
            })
            .errors
            .into_iter()
            .map(Error::from)
            .collect()
    }

    #[test]
    fn snapshot_reflects_latest_registry_state() {
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&RoutingTable { entries: vec![] });

        let key2 = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value2 = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });

        let mutation1 = vec![insert(key1.as_bytes(), &value1)];
        let mutation2 = vec![insert(key2.as_bytes(), &value2)];
        let mut registry = Registry::new();
        assert!(try_mutate(&mut registry, &mutation1).is_empty());
        assert!(try_mutate(&mut registry, &mutation2).is_empty());

        let snapshot = registry.take_latest_snapshot_with_mutations(&[]);

        let snapshot_data = snapshot.get(key1.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value1);

        let snapshot_data = snapshot.get(key2.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value2);
    }

    #[test]
    fn snapshot_data_are_updated() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
        });
        let mut mutations = vec![insert(key.as_bytes(), &value)];

        let registry = Registry::new();
        let snapshot = registry.take_latest_snapshot_with_mutations(&mutations);

        let snapshot_data = snapshot.get(key.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value);

        mutations.append(&mut vec![delete(key.as_bytes())]);
        let snapshot = registry.take_latest_snapshot_with_mutations(&mutations);
        let snapshot_data = snapshot.get(key.as_bytes());
        assert!(snapshot_data.is_none());
    }

    #[test]
    fn test_mask_ip() {
        assert_eq!(
            mask_ipv4(
                Ipv4Addr::new(192, 168, 13, 241),
                Ipv4Addr::new(255, 255, 255, 0)
            ),
            Ipv4Addr::new(192, 168, 13, 0)
        );
        assert_eq!(
            mask_ipv4(
                Ipv4Addr::new(192, 168, 13, 241),
                Ipv4Addr::new(255, 255, 0, 0)
            ),
            Ipv4Addr::new(192, 168, 0, 0)
        );
        assert_eq!(
            mask_ipv4(
                Ipv4Addr::new(192, 168, 0xaa, 241),
                Ipv4Addr::new(255, 255, 0xf0, 0)
            ),
            Ipv4Addr::new(192, 168, 0xa0, 0)
        );
        assert_eq!(
            mask_ipv6(
                Ipv6Addr::new(0xabcd, 0xdef0, 0x1234, 0x5678, 0x9abc, 0, 0, 0x1234),
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)
            ),
            Ipv6Addr::new(0xabcd, 0xdef0, 0x1234, 0x5678, 0, 0, 0, 0)
        );
        assert_eq!(
            mask_ipv6(
                Ipv6Addr::new(0xabcd, 0xdef0, 0x1234, 0x5678, 0x9abc, 0, 0, 0x1234),
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xff00, 0, 0, 0, 0)
            ),
            Ipv6Addr::new(0xabcd, 0xdef0, 0x1234, 0x5600, 0, 0, 0, 0)
        );
    }

    #[test]
    fn test_validate_endpoint() {
        let loopback_ipv4_endpoint = ConnectionEndpoint {
            ip_addr: "127.0.0.1".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&loopback_ipv4_endpoint, true).is_err());

        let loopback_ipv6_endpoint = ConnectionEndpoint {
            ip_addr: "::1".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&loopback_ipv6_endpoint, true).is_err());

        let bad_port_endpoint = ConnectionEndpoint {
            ip_addr: "212.13.11.77".to_string(),
            port: 80802,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&bad_port_endpoint, true).is_err());
        assert!(validate_endpoint(&bad_port_endpoint, false).is_err());

        let bad_ipv4_endpoint = ConnectionEndpoint {
            ip_addr: "280.13.11.77".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&bad_ipv4_endpoint, true).is_err());
        assert!(validate_endpoint(&bad_ipv4_endpoint, false).is_err());

        let bad_ipv6_endpoint = ConnectionEndpoint {
            ip_addr: "0fab:12345::".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&bad_ipv6_endpoint, true).is_err());
        assert!(validate_endpoint(&bad_ipv6_endpoint, false).is_err());

        let multicast_ipv4_endpoint = ConnectionEndpoint {
            ip_addr: "224.0.0.1".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&multicast_ipv4_endpoint, true).is_err());
        assert!(validate_endpoint(&multicast_ipv4_endpoint, false).is_err());

        let multicast_ipv6_endpoint = ConnectionEndpoint {
            ip_addr: "ff00:1:2::".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&multicast_ipv6_endpoint, true).is_err());
        assert!(validate_endpoint(&multicast_ipv6_endpoint, false).is_err());

        let private_ipv4_endpoint = ConnectionEndpoint {
            ip_addr: "192.168.0.1".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&private_ipv4_endpoint, true).is_err());
        assert!(validate_endpoint(&private_ipv4_endpoint, false).is_ok());

        let unique_ipv6_endpoint = ConnectionEndpoint {
            ip_addr: "fc00:1234::".to_string(),
            port: 8080,
            protocol: Protocol::Http1 as i32,
        };
        assert!(validate_endpoint(&unique_ipv6_endpoint, true).is_err());
        assert!(validate_endpoint(&unique_ipv6_endpoint, false).is_ok());
    }

    #[test]
    fn test_endpoints_invariants() {
        let mut snapshot = RegistrySnapshot::new();

        // Valid node
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));
        snapshot.insert(
            make_node_record_key(node_id).into_bytes(),
            encode_or_panic::<NodeRecord>(&NodeRecord {
                node_operator_id: vec![0],
                xnet: None,
                http: None,
                p2p_flow_endpoints: vec![
                    FlowEndpoint {
                        flow_tag: 1,
                        endpoint: Some(ConnectionEndpoint {
                            ip_addr: "200.1.1.1".to_string(),
                            port: 8080,
                            protocol: Protocol::P2p1Tls13 as i32,
                        }),
                    },
                    FlowEndpoint {
                        flow_tag: 2,
                        endpoint: Some(ConnectionEndpoint {
                            ip_addr: "200.1.1.2".to_string(),
                            port: 8080,
                            protocol: Protocol::P2p1Tls13 as i32,
                        }),
                    },
                ],
                prometheus_metrics_http: None,
                public_api: vec![ConnectionEndpoint {
                    ip_addr: "200.1.1.3".to_string(),
                    port: 9000,
                    protocol: Protocol::Http1 as i32,
                }],
                private_api: vec![],
                prometheus_metrics: vec![],
                xnet_api: vec![ConnectionEndpoint {
                    ip_addr: "200.1.1.3".to_string(),
                    port: 9001,
                    protocol: Protocol::Http1 as i32,
                }],
            }),
        );

        assert!(Registry::check_endpoints_invariants(&snapshot, true).is_ok());

        // Add a node with conflicting sockets
        let node_id = NodeId::from(PrincipalId::new_node_test_id(2));
        let key = make_node_record_key(node_id).into_bytes();
        snapshot.insert(
            key.clone(),
            encode_or_panic::<NodeRecord>(&NodeRecord {
                node_operator_id: vec![0],
                xnet: None,
                http: None,
                p2p_flow_endpoints: vec![
                    FlowEndpoint {
                        flow_tag: 1,
                        endpoint: Some(ConnectionEndpoint {
                            ip_addr: "200.1.1.3".to_string(),
                            port: 8080,
                            protocol: Protocol::P2p1Tls13 as i32,
                        }),
                    },
                    FlowEndpoint {
                        flow_tag: 2,
                        endpoint: Some(ConnectionEndpoint {
                            ip_addr: "200.1.1.1".to_string(),
                            port: 8080,
                            protocol: Protocol::P2p1Tls13 as i32,
                        }),
                    },
                ],
                prometheus_metrics_http: None,
                public_api: vec![ConnectionEndpoint {
                    ip_addr: "200.1.1.3".to_string(),
                    port: 9000,
                    protocol: Protocol::Http1 as i32,
                }],
                private_api: vec![],
                prometheus_metrics: vec![],
                xnet_api: vec![ConnectionEndpoint {
                    ip_addr: "200.1.1.1".to_string(),
                    port: 9001,
                    protocol: Protocol::Http1 as i32,
                }],
            }),
        );
        assert!(Registry::check_endpoints_invariants(&snapshot, true).is_err());

        snapshot.remove(&key);

        // Add a node with conflicting flow IDs
        let node_id = NodeId::from(PrincipalId::new_node_test_id(2));
        let key = make_node_record_key(node_id).into_bytes();
        snapshot.insert(
            key,
            encode_or_panic::<NodeRecord>(&NodeRecord {
                node_operator_id: vec![0],
                xnet: None,
                http: None,
                p2p_flow_endpoints: vec![
                    FlowEndpoint {
                        flow_tag: 1,
                        endpoint: Some(ConnectionEndpoint {
                            ip_addr: "200.1.1.3".to_string(),
                            port: 8080,
                            protocol: Protocol::P2p1Tls13 as i32,
                        }),
                    },
                    FlowEndpoint {
                        flow_tag: 1,
                        endpoint: Some(ConnectionEndpoint {
                            ip_addr: "200.1.1.1".to_string(),
                            port: 8080,
                            protocol: Protocol::P2p1Tls13 as i32,
                        }),
                    },
                ],
                prometheus_metrics_http: None,
                public_api: vec![ConnectionEndpoint {
                    ip_addr: "200.1.1.2".to_string(),
                    port: 9000,
                    protocol: Protocol::Http1 as i32,
                }],
                private_api: vec![],
                prometheus_metrics: vec![],
                xnet_api: vec![ConnectionEndpoint {
                    ip_addr: "200.1.1.2".to_string(),
                    port: 9001,
                    protocol: Protocol::Http1 as i32,
                }],
            }),
        );
        assert!(Registry::check_endpoints_invariants(&snapshot, true).is_err());
    }

    fn valid_node_keys_and_node_id() -> (NodePublicKeys, NodeId) {
        let temp_dir = temp_dir();
        get_node_keys_or_generate_if_missing(temp_dir.path())
    }

    fn insert_dummy_node(node_id: &NodeId, snapshot: &mut RegistrySnapshot) {
        snapshot.insert(
            make_node_record_key(node_id.to_owned()).into_bytes(),
            encode_or_panic::<NodeRecord>(&NodeRecord::default()),
        );
    }

    fn insert_node_crypto_keys(
        node_id: &NodeId,
        npks: &NodePublicKeys,
        snapshot: &mut RegistrySnapshot,
    ) {
        if npks.node_signing_pk.is_some() {
            snapshot.insert(
                make_crypto_node_key(node_id.to_owned(), KeyPurpose::NodeSigning).into_bytes(),
                encode_or_panic::<PublicKey>(&npks.node_signing_pk.clone().unwrap()),
            );
        };
        if npks.committee_signing_pk.is_some() {
            snapshot.insert(
                make_crypto_node_key(node_id.to_owned(), KeyPurpose::CommitteeSigning).into_bytes(),
                encode_or_panic::<PublicKey>(&npks.committee_signing_pk.clone().unwrap()),
            );
        };
        if npks.dkg_dealing_encryption_pk.is_some() {
            snapshot.insert(
                make_crypto_node_key(node_id.to_owned(), KeyPurpose::DkgDealingEncryption)
                    .into_bytes(),
                encode_or_panic::<PublicKey>(&npks.dkg_dealing_encryption_pk.clone().unwrap()),
            );
        };
        if npks.tls_certificate.is_some() {
            snapshot.insert(
                make_crypto_tls_cert_key(node_id.to_owned()).into_bytes(),
                encode_or_panic::<X509PublicKeyCert>(&npks.tls_certificate.clone().unwrap()),
            );
        };
    }

    #[test]
    fn node_crypto_keys_invariants_valid_snapshot() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);
        insert_node_crypto_keys(&node_id_2, &npks_2, &mut snapshot);
        assert!(check_node_crypto_keys_invariants(&snapshot).is_ok());
    }

    #[test]
    fn node_crypto_keys_invariants_missing_committee_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let incomplete_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: None,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &incomplete_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("committee"));
        assert!(err.to_string().contains("key is missing"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_node_signing_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let incomplete_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: None,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &incomplete_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("node signing key"));
        assert!(err.to_string().contains("key is missing"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_tls_cert() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let incomplete_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: None,
        };
        insert_node_crypto_keys(&node_id_2, &incomplete_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("certificate"));
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn node_crypto_keys_invariants_invalid_dkg_encryption_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let invalid_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: Some(PublicKey {
                version: 0,
                algorithm: 0,
                key_value: vec![],
                proof_data: None,
            }),
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &invalid_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err
            .to_string()
            .contains("invalid DKG dealing encryption key"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_committee_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let duplicated_key_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_1.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &duplicated_key_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_1.to_string()));
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("the same public key"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_tls_cert() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let duplicated_cert_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_1.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &duplicated_cert_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("invalid TLS certificate"));
    }

    #[test]
    fn node_crypto_keys_invariants_inconsistent_node_id() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let (npks_3, _node_id_3) = valid_node_keys_and_node_id();
        let inconsistent_signing_key_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_3.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &inconsistent_signing_key_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("invalid node signing key"));
    }

    #[test]
    /// The test ensures that the conversion rate proposal passes the invariants
    /// check if a) there is currently no record in the registry or
    /// b) the proposal contains a timestamp that is larger than the timestamp
    /// of the conversion rate record in the registry.
    fn conversion_rate_invariant_valid_timestamp() {
        // Create a valid registry:
        let mut registry = create_valid_registry();
        // Create a conversion rate to be added to the snapshot:
        let proposed_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 3141592,
            xdr_permyriad_per_icp: 123451234,
        };
        // Create a snapshot with the proposed conversion rate:
        let snapshot = registry.take_latest_snapshot_with_mutations(&[insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&proposed_conversion_rate),
        )]);
        // The conversion rate invariants should be satisfied because there is no record
        // in the registry:
        registry.check_conversion_rate_invariants(&snapshot);

        // Manually add an initial rate with a smaller timestamp:
        let initial_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 1415926,
            xdr_permyriad_per_icp: 123451234,
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&initial_conversion_rate),
        )]);
        // The conversion rate invariants should still be satisfied:
        registry.check_conversion_rate_invariants(&snapshot);
    }

    #[test]
    /// The test ensures that the conversion rate proposal does not pass the
    /// invariants check if the proposal contains a timestamp that is
    /// smaller than the timestamp of the conversion rate record in the
    /// registry.
    #[should_panic]
    fn conversion_rate_invariant_invalid_timestamp() {
        // Create a valid registry:
        let mut registry = create_valid_registry();
        // Add an initial conversion rate:
        let initial_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 1000000,
            xdr_permyriad_per_icp: 2000000,
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&initial_conversion_rate),
        )]);
        // Create a conversion rate to be added to the snapshot:
        let proposed_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 999999,
            xdr_permyriad_per_icp: 2000000,
        };
        // Get a snapshot with the proposed conversion rate:
        let snapshot = registry.take_latest_snapshot_with_mutations(&[insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&proposed_conversion_rate),
        )]);
        // The conversion rate invariants should not be satisfied because the timestamp
        // in the proposal is smaller:
        registry.check_conversion_rate_invariants(&snapshot);
    }

    #[test]
    /// The test ensures that registry mutations not affecting the conversion
    /// rate are possible when a conversion rate is set in the registry.
    fn conversion_rate_invariant_unrelated_mutation() {
        // Create a valid registry:
        let mut registry = create_valid_registry();
        // Create a conversion rate to be added to the registry:
        let proposed_conversion_rate = IcpXdrConversionRateRecord {
            timestamp_seconds: 3141592,
            xdr_permyriad_per_icp: 123451234,
        };
        // Add the conversion rate to the registry:
        registry.maybe_apply_mutation_internal(vec![insert(
            &make_icp_xdr_conversion_rate_record_key().into_bytes(),
            encode_or_panic::<IcpXdrConversionRateRecord>(&proposed_conversion_rate),
        )]);
        // All global invariants should be satisfied when introducing an unrelated
        // mutation, e.g., resetting the routing table:
        registry.check_global_invariants(&[insert(
            make_routing_table_record_key(),
            encode_or_panic(&RoutingTable::default()),
        )]);
    }
}
