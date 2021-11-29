//! In this context, a configuration is a description of a IC-network topology
//! plus some initial parameters, such as the ip addresses of the nodes and
//! consensus parameters of subnetworks.
//!
//! _Initializing_ consumes a configuration, generates corresponding files on
//! disk and returns an initialized ic.

use std::{
    collections::BTreeMap,
    convert::TryInto,
    fmt,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    str::FromStr,
};

use openssl::pkey;
use serde_json::Value;
use thiserror::Error;
use url::Url;

use ic_interfaces::registry::{
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_protobuf::registry::{
    node_operator::v1::NodeOperatorRecord,
    provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::RoutingTable as PbRoutingTable,
    subnet::v1::SubnetListRecord,
};
use ic_protobuf::types::v1::{PrincipalId as PrincipalIdProto, SubnetId as SubnetIdProto};
use ic_registry_client::client::RegistryDataProviderError;
use ic_registry_common::{
    local_store::{Changelog, KeyMutation, LocalStoreImpl, LocalStoreWriter},
    proto_registry_data_provider::ProtoRegistryDataProvider,
};
use ic_registry_keys::{
    make_blessed_replica_version_key, make_node_operator_record_key,
    make_provisional_whitelist_record_key, make_replica_version_key, make_routing_table_record_key,
    make_subnet_list_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_types::{
    NodeId, PrincipalId, PrincipalIdParseError, RegistryVersion, ReplicaVersion, SubnetId,
};

use crate::subnet_configuration::{SubnetConfig, SubnetIndex};
use crate::util::write_registry_entry;
use crate::{
    initialized_subnet::InitializedSubnet,
    node::{InitializeNodeError, InitializedNode, NodeConfiguration, NodeIndex},
    subnet_configuration::InitializeSubnetError,
};

/// Path to the Registry Local Store
pub const IC_REGISTRY_LOCAL_STORE_PATH: &str = "ic_registry_local_store";
/// Path of the Root Public Key
// nns_ is a misnomer from the days we didn't care about separation of concerns.
pub const IC_ROOT_PUB_KEY_PATH: &str = "nns_public_key.pem";

/// In production, initialized nodes are not 'visible' as the network goes
/// through a 'switch-over' which removes the bootstrapped nodes from the
/// network.
///
/// For testing purposes, the bootstrapped nodes can be configured to have a
/// node operator. The corresponding allowance is the number of configured
/// initial nodes mulitplied by this value.
pub const INITIAL_NODE_ALLOWANCE_MULTIPLIER: usize = 2;

pub const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

#[derive(Clone, Debug, Default)]
pub struct TopologyConfig {
    subnets: BTreeMap<SubnetIndex, SubnetConfig>,
    subnet_ids: BTreeMap<SubnetIndex, SubnetId>,
    unassigned_nodes: BTreeMap<NodeIndex, NodeConfiguration>,
}

impl TopologyConfig {
    pub fn insert_subnet(&mut self, subnet_index: SubnetIndex, config: SubnetConfig) {
        assert_eq!(subnet_index, config.subnet_index);
        self.subnets.insert(subnet_index, config);
    }

    /// Based on the setting of `self.subnets` generate a suitable
    /// `RoutingTable`
    fn get_routing_table(&self, nns_subnet_index: Option<&u64>) -> RoutingTable {
        let mut routing_table = RoutingTable::default();
        // make sure nns subnet is inserted first
        if let Some(subnet_index) = nns_subnet_index {
            routing_table_insert_subnet(&mut routing_table, self.subnet_ids[subnet_index]).unwrap();
        }
        for subnet_index in self.subnets.keys() {
            if Some(subnet_index) != nns_subnet_index {
                routing_table_insert_subnet(&mut routing_table, self.subnet_ids[subnet_index])
                    .unwrap();
            }
        }
        routing_table
    }

    pub fn insert_unassigned_node(&mut self, idx: NodeIndex, nc: NodeConfiguration) {
        self.unassigned_nodes.insert(idx, nc);
    }

    /// Set all node providers to the principal `node_operator`.
    pub fn with_initial_node_operator(mut self, node_operator: PrincipalId) -> Self {
        for (_, sc) in self.subnets.iter_mut() {
            for (_, nc) in sc.membership.iter_mut() {
                nc.node_operator_principal_id = Some(node_operator);
            }
        }

        for (_, nc) in self.unassigned_nodes.iter_mut() {
            nc.node_operator_principal_id = Some(node_operator);
        }
        self
    }

    pub fn node_count(&self) -> usize {
        let assigned = self
            .subnets
            .iter()
            .fold(0usize, |a, (_, x)| a + x.membership.len());
        let unassigned = self.unassigned_nodes.len();
        assigned + unassigned
    }
}

#[derive(Clone)]
pub struct NodeOperatorPublicKey {
    pkey_wrapper: pkey::PKey<pkey::Public>,
}

// We need to implement a wrapper and the debug trait since PKey does not
// implement Debug
impl fmt::Debug for NodeOperatorPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeOperatorPublicKey")
            .field("pkey_wrapper", &self.pkey_wrapper.public_key_to_der())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct NodeOperatorEntry {
    name: String,
    principal_id: PrincipalId,
    node_provider_principal_id: Option<PrincipalId>,
    node_allowance: u64,
    dc_id: String,
    rewardable_nodes: BTreeMap<String, u32>,
}

// We must be able to inject a values of type NodeOperatorEntry into the
// NodeOperatorRecord representation used in the registry.
impl From<NodeOperatorEntry> for NodeOperatorRecord {
    fn from(item: NodeOperatorEntry) -> Self {
        NodeOperatorRecord {
            node_operator_principal_id: item.principal_id.to_vec(),
            node_allowance: item.node_allowance,
            node_provider_principal_id: item
                .node_provider_principal_id
                .map(|x| x.to_vec())
                .unwrap_or_else(Vec::new),
            dc_id: item.dc_id,
            rewardable_nodes: item.rewardable_nodes,
        }
    }
}

pub type InitializedTopology = BTreeMap<NodeIndex, InitializedSubnet>;
pub type UnassignedNodes = BTreeMap<NodeId, InitializedNode>;

#[derive(Clone, Debug)]
pub struct IcConfig {
    target_dir: PathBuf,
    topology_config: TopologyConfig,
    /// When a node starts up, the node manager fetches the replica binary found
    /// at the URL in the blessed version record that carries the version
    /// id referred to in the subnet record that the node belongs to.
    ///
    /// The following are parameters used for all subnets in the initial
    /// topology of the network.
    ///
    /// The version id of the initial replica.
    initial_replica_version_id: ReplicaVersion,
    /// The URL of the initial replica version.
    initial_replica_download_url: Url,
    /// The hash of the initial replica version.
    initial_replica_hash: Option<String>,
    /// The URL of the initial nodemanager version.
    initial_nodemanager_url: Option<Url>,
    /// The hash of the initial nodemanager version.
    initial_nodemanager_sha256_hex: Option<String>,
    /// The URL of the initial release package.
    initial_release_package_url: Option<Url>,
    /// The hash of the initial release package.
    initial_release_package_sha256_hex: Option<String>,
    /// Should the tool generate the subnet records.
    generate_subnet_records: bool,
    /// The index of the NNS subnet, if any.
    nns_subnet_index: Option<u64>,

    /// Vector of node operator records
    initial_registry_node_operator_entries: Vec<NodeOperatorEntry>,

    provisional_whitelist: Option<ProvisionalWhitelist>,

    /// Mutations to apply to the initial Registry
    /// TODO (VER-624): Make ic-prep API orthogonal again
    pub initial_mutations: Vec<RegistryMutation>,

    /// If set, all NodeRecords created via ic-prep will contain this principal
    /// id as the node operator (the respective field is named
    /// `NodeRecord::dc_operator_principal_id` for historical reasons).
    ///
    /// A corresponding `NodeOperatorRecord` will be created with a
    /// `node_allowance` equal to the number of initially created nodes.
    pub initial_node_operator: Option<PrincipalId>,

    /// The node provider principal id of the node operator record will be set
    /// to to this initial node provider id.
    pub initial_node_provider: Option<PrincipalId>,
}

#[derive(Error, Debug)]
pub enum InitializeError {
    #[error("io error: {source}")]
    IoError {
        #[from]
        source: io::Error,
    },

    #[error("JSON parsing error: {source}")]
    JsonError {
        #[from]
        source: serde_json::Error,
    },

    #[error("OpenSSL error: {source}")]
    OpenSslError {
        #[from]
        source: openssl::error::ErrorStack,
    },

    #[error("principal did not parse: {source}")]
    PrincipalParse {
        #[from]
        source: PrincipalIdParseError,
    },

    #[error("key {key} not found in {object}")]
    MissingKey { key: String, object: String },

    #[error("value for key {key} is not a u64: {value}")]
    NotU64 { key: String, value: String },

    #[error("value for key {key:} is not a string: {value:}")]
    NotString { key: String, value: String },

    #[error("could not parse ipv6_prefixes value")]
    IPv6PrefixParse,

    #[error("initializing subnet failed: {source}")]
    InitializeSubnet {
        #[from]
        source: InitializeSubnetError,
    },

    #[error("initializing node failed: {source}")]
    InitializeNode {
        #[from]
        source: InitializeNodeError,
    },

    #[error("registry data provider failed: {source}")]
    RegistryDataProvider {
        #[from]
        source: RegistryDataProviderError,
    },
}

impl IcConfig {
    pub fn set_provisional_whitelist(&mut self, provisional_whitelist: ProvisionalWhitelist) {
        self.provisional_whitelist = Some(provisional_whitelist);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new<P: AsRef<Path>>(
        target_dir: P,
        topology_config: TopologyConfig,
        replica_version_id: Option<ReplicaVersion>,
        replica_download_url: Option<Url>,
        replica_hash: Option<String>,
        generate_subnet_records: bool,
        nns_subnet_index: Option<u64>,
        nodemanager_url: Option<Url>,
        nodemanager_sha256_hex: Option<String>,
        release_package_url: Option<Url>,
        release_package_sha256_hex: Option<String>,
        provisional_whitelist: Option<ProvisionalWhitelist>,
        initial_node_operator: Option<PrincipalId>,
        initial_node_provider: Option<PrincipalId>,
    ) -> Self {
        Self {
            target_dir: PathBuf::from(target_dir.as_ref()),
            topology_config,
            initial_replica_version_id: replica_version_id.unwrap_or_else(ReplicaVersion::default),
            initial_replica_download_url: replica_download_url
                .unwrap_or_else(|| Url::parse("http://example.internetcomputer.org").unwrap()),
            initial_replica_hash: replica_hash,
            generate_subnet_records,
            nns_subnet_index,
            initial_nodemanager_url: nodemanager_url,
            initial_nodemanager_sha256_hex: nodemanager_sha256_hex,
            initial_release_package_url: release_package_url,
            initial_release_package_sha256_hex: release_package_sha256_hex,
            initial_registry_node_operator_entries: Vec::new(),
            provisional_whitelist,
            initial_mutations: Vec::new(),
            initial_node_operator,
            initial_node_provider,
        }
    }

    /// initialize the IC. Generates ...
    /// * ... the secret key store for each node in this IC
    /// * ... registry entries to be picked up by ic-admin
    /// * ... a registry file to be used as a static registry
    pub fn initialize(mut self) -> Result<InitializedIc, InitializeError> {
        let version = INITIAL_REGISTRY_VERSION;
        let data_provider = ProtoRegistryDataProvider::new();
        data_provider
            .add_mutations(self.initial_mutations.clone())
            .expect("Failed to add initial mutations");
        let mut initialized_topology = InitializedTopology::new();

        if let Some(node_operator_id) = self.initial_node_operator {
            assert!(self.initial_node_provider.is_some());

            // If an initial node provider is specified, write out a corresponding entry.
            let node_allowance = (self.topology_config.node_count()
                * INITIAL_NODE_ALLOWANCE_MULTIPLIER)
                .try_into()
                .expect("Could not convert usize into u64.");

            self.topology_config = self
                .topology_config
                .with_initial_node_operator(node_operator_id);
            self.initial_registry_node_operator_entries
                .push(NodeOperatorEntry {
                    name: "initial".into(),
                    node_allowance,
                    principal_id: node_operator_id,
                    node_provider_principal_id: self.initial_node_provider,
                    dc_id: "".into(),
                    rewardable_nodes: BTreeMap::new(),
                });
        }

        for (subnet_index, subnet_config) in self.topology_config.subnets.clone() {
            let init_subnet = subnet_config
                .clone()
                .initialize(self.target_dir.as_path())?;
            init_subnet.write_registry_entries(
                &data_provider,
                version,
                self.generate_subnet_records,
            )?;
            self.topology_config
                .subnet_ids
                .insert(subnet_index, init_subnet.subnet_id);
            initialized_topology.insert(subnet_index, init_subnet);
        }

        let mut unassigned_nodes = BTreeMap::new();
        for (n_idx, nc) in self.topology_config.unassigned_nodes.iter() {
            let node_path = InitializedSubnet::build_node_path(self.target_dir.as_path(), *n_idx);
            let init_node = nc.clone().initialize(node_path)?;
            init_node.write_registry_entries(&data_provider, version)?;
            unassigned_nodes.insert(init_node.node_id, init_node);
        }

        // Set the routing table after initializing the subnet ids
        let routing_table_record = if self.generate_subnet_records {
            PbRoutingTable::from(
                self.topology_config
                    .get_routing_table(self.nns_subnet_index.as_ref()),
            )
        } else {
            PbRoutingTable::from(RoutingTable::default())
        };

        if let Some(subnet_index) = self.nns_subnet_index {
            let subnet = initialized_topology.get(&subnet_index).unwrap();
            let nns_subnet_id_proto = SubnetIdProto {
                principal_id: Some(PrincipalIdProto {
                    raw: subnet.subnet_id.get().into_vec(),
                }),
            };
            write_registry_entry(
                &data_provider,
                self.target_dir.as_path(),
                ROOT_SUBNET_ID_KEY,
                version,
                nns_subnet_id_proto,
            );

            let key_file = self.target_dir.join(IC_ROOT_PUB_KEY_PATH);
            crate::util::store_threshold_sig_pk(
                &subnet.subnet_threshold_signing_public_key,
                key_file,
            );
        }

        // set subnet list
        let subnet_list_record = SubnetListRecord {
            subnets: initialized_topology
                .values()
                .map(|s| s.subnet_id.get().into_vec())
                .collect(),
        };

        if self.generate_subnet_records {
            write_registry_entry(
                &data_provider,
                self.target_dir.as_path(),
                make_subnet_list_record_key().as_str(),
                version,
                subnet_list_record,
            );
        }

        write_registry_entry(
            &data_provider,
            self.target_dir.as_path(),
            &make_routing_table_record_key(),
            version,
            routing_table_record,
        );

        let replica_version_record = ReplicaVersionRecord {
            binary_url: self.initial_replica_download_url.to_string(),
            sha256_hex: self.initial_replica_hash.unwrap_or_default(),
            node_manager_binary_url: self
                .initial_nodemanager_url
                .map(|url| url.to_string())
                .unwrap_or_default(),
            node_manager_sha256_hex: self.initial_nodemanager_sha256_hex.unwrap_or_default(),
            release_package_url: self
                .initial_release_package_url
                .map(|url| url.to_string())
                .unwrap_or_default(),
            release_package_sha256_hex: self.initial_release_package_sha256_hex.unwrap_or_default(),
        };

        let blessed_replica_versions_record = BlessedReplicaVersions {
            blessed_version_ids: vec![self.initial_replica_version_id.to_string()],
        };

        write_registry_entry(
            &data_provider,
            self.target_dir.as_path(),
            make_replica_version_key(self.initial_replica_version_id).as_ref(),
            version,
            replica_version_record,
        );

        write_registry_entry(
            &data_provider,
            self.target_dir.as_path(),
            &make_blessed_replica_version_key(),
            version,
            blessed_replica_versions_record,
        );

        let provisional_whitelist = match self.provisional_whitelist {
            Some(list) => list,
            // The principal id below is the one corresponding to the hardcoded key in
            // ic_test_utilities::identity::TEST_IDENTITY_KEYPAIR. We don't want to add a dependency
            // to `ic_test_utilities` crate, so hardcode the corresponding principal instead.
            //
            // Note that this happens to facilitate testing by not having to set the whitelist
            // explicitly. In production settings, the whitelist ought to be set explicitly.
            None => ProvisionalWhitelist::Set(maplit::btreeset! {
                PrincipalId::from_str("5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae")?
            }),
        };
        write_registry_entry(
            &data_provider,
            self.target_dir.as_path(),
            &make_provisional_whitelist_record_key(),
            version,
            PbProvisionalWhitelist::from(provisional_whitelist),
        );

        for node_operator_entry in self.initial_registry_node_operator_entries {
            let id = node_operator_entry.principal_id;
            let node_operator_record: NodeOperatorRecord = node_operator_entry.into();
            write_registry_entry(
                &data_provider,
                self.target_dir.as_path(),
                make_node_operator_record_key(id).as_ref(),
                version,
                node_operator_record,
            );
        }

        data_provider.write_to_file(InitializedIc::registry_path_(self.target_dir.as_path()));

        // Write registry in the directory format
        let registry_store =
            LocalStoreImpl::new(self.target_dir.join(IC_REGISTRY_LOCAL_STORE_PATH));

        // Because we use the LocalStoreImpl, we know that we get the entire
        // registry in one chunk when calling `get_updates_since()`.
        let mut updates = data_provider.get_updates_since(ZERO_REGISTRY_VERSION)?;

        updates.sort_by_key(|r| r.version);
        let changelog = updates.iter().fold(
            Changelog::default(),
            |mut cl,
             RegistryTransportRecord {
                 version,
                 key,
                 value,
             }| {
                let rel_version = (*version - ZERO_REGISTRY_VERSION).get();
                if cl.len() < rel_version as usize {
                    cl.push(vec![]);
                }
                cl.last_mut().unwrap().push(KeyMutation {
                    key: key.clone(),
                    value: value.clone(),
                });
                cl
            },
        );
        changelog.into_iter().enumerate().try_for_each(|(i, cle)| {
            let v = ZERO_REGISTRY_VERSION + RegistryVersion::from(i as u64 + 1);
            registry_store.store(v, cle)
        })?;

        // Set certified time.
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Could not get system time");
        let nanos = now.as_nanos() as u64;
        registry_store
            .update_certified_time(nanos)
            .expect("Could not update certified time.");

        Ok(InitializedIc {
            target_dir: self.target_dir,
            initialized_topology,
            unassigned_nodes,
        })
    }

    /// Loads a directory NodeOperator's records from a directory. The
    /// directory must have structure:
    ///
    /// > data_centers/
    /// >   dc_A.der
    /// >   dc_B.der
    /// >   dc_C.der
    /// >   meta.json
    ///
    /// And meta.json must have structure:
    ///
    /// > { "dc_A": { "node_allowance" : 3  }
    /// > , "dc_B": { "node_allowance" : 1  }
    /// > , "dc_C": { "node_allowance" : 42 }
    /// > }
    ///
    ///
    /// If `require_node_provider_key` is `true`, each entry must additionally
    /// specify a key `node_provider` that contains the filename of a `.der`
    /// file containing the public key of the corresponding node provider.
    ///
    /// Ex:
    ///
    /// > data_centers/
    /// >   << as above >>
    /// >   provider_keys/
    /// >     np.der
    ///
    /// > "dc_A": { "node_allowance" : 3,
    /// >   "node_provider": "provider_keys/np.der",
    /// > }
    ///
    /// *Note* that in case of the provider key, the filename *must* include the
    /// extension. If the path is not absolute, the directory containing the
    /// meta.json is used as a basis.
    pub fn load_registry_node_operator_records_from_dir(
        mut self,
        der_dir: &Path,
        require_node_provider_key: bool,
    ) -> Result<Self, InitializeError> {
        let mut der_files: Vec<PathBuf> = Vec::new();

        //First we read the directory and sort out which
        //files we should read.
        for entry in fs::read_dir(der_dir)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path
                .into_os_string()
                .into_string()
                .unwrap()
                .ends_with(".der")
            {
                der_files.push(entry.path());
            }
        }

        //Now we look for the 'meta.json' file:
        let meta = Path::new(der_dir).join("meta.json");
        let meta = File::open(meta)?;
        let meta: Value = serde_json::from_reader(meta)?;

        //Now we read all the der certificates that are present in the directory
        //and push them into the node_operator_entries vector. We don't use a map
        // because there are too many '?' in there.
        let mut node_operator_entries = Vec::new();
        for fname in der_files {
            let name = fname
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_suffix(".der")
                .unwrap();

            const NODE_ALLOWANCE: &str = "node_allowance";
            const NODE_PROVIDER: &str = "node_provider";

            if let Value::Object(m) = &meta[name] {
                if !m.contains_key(NODE_ALLOWANCE) {
                    return Err(InitializeError::MissingKey {
                        key: NODE_ALLOWANCE.to_string(),
                        object: name.to_string(),
                    });
                }
                if require_node_provider_key && !m.contains_key(NODE_PROVIDER) {
                    return Err(InitializeError::MissingKey {
                        key: NODE_PROVIDER.to_string(),
                        object: name.to_string(),
                    });
                }
            } else {
                return Err(InitializeError::MissingKey {
                    key: name.to_string(),
                    object: "meta.json".to_string(),
                });
            };

            let obj = &meta[name];
            let node_allowance = match obj[NODE_ALLOWANCE].as_u64() {
                Some(node_allowance) => Ok(node_allowance),
                None => Err(InitializeError::NotU64 {
                    key: name.to_string(),
                    value: obj[NODE_ALLOWANCE].to_string(),
                }),
            }?;

            let operator_buf: Vec<u8> = fs::read(&fname)?;

            let node_provider_principal_id = if require_node_provider_key {
                let provider_path = match obj[NODE_PROVIDER].as_str() {
                    Some(fname) => {
                        let fpath = Path::new(fname);
                        let fpath = if fpath.is_relative() {
                            PathBuf::from(der_dir).join(fpath)
                        } else {
                            PathBuf::from(fname)
                        };
                        Ok(fpath)
                    }
                    None => Err(InitializeError::NotString {
                        key: name.to_string(),
                        value: obj[NODE_PROVIDER].to_string(),
                    }),
                }?;
                let provider_buf: Vec<u8> = fs::read(provider_path.as_path())?;
                let _ = pkey::PKey::public_key_from_der(&provider_buf)?;
                Some(PrincipalId::new_self_authenticating(&provider_buf))
            } else {
                None
            };

            node_operator_entries.push(NodeOperatorEntry {
                name: String::from(name),
                principal_id: PrincipalId::new_self_authenticating(&operator_buf),
                node_provider_principal_id,
                node_allowance,
                dc_id: "".into(),
                rewardable_nodes: BTreeMap::new(),
            });
        }

        self.initial_registry_node_operator_entries
            .extend(node_operator_entries);
        Ok(self)
    }
}

pub struct InitializedIc {
    pub target_dir: PathBuf,
    pub initialized_topology: InitializedTopology,
    pub unassigned_nodes: UnassignedNodes,
}

impl InitializedIc {
    pub fn registry_path(&self) -> PathBuf {
        Self::registry_path_(self.target_dir.as_path())
    }

    pub fn registry_path_<P: AsRef<Path>>(working_dir: P) -> PathBuf {
        PathBuf::from(working_dir.as_ref()).join("registry.proto")
    }
}
