use crate::driver::{
    bootstrap::{init_ic, setup_and_start_vms},
    farm::{Farm, HostFeature},
    node_software_version::NodeSoftwareVersion,
    resource::{allocate_resources, get_resource_request, ResourceGroup},
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{HasRegistryLocalStore, HasTopologySnapshot},
    test_setup::{GroupSetup, InfraProvider},
};
use crate::k8s::tnet::TNet;
use crate::util::block_on;
use anyhow::Result;
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_prep_lib::{node::NodeSecretKeyStore, subnet_configuration::SubnetRunningState};
use ic_regedit;
use ic_registry_canister_api::IPv4Config;
use ic_registry_subnet_features::{ChainKeyConfig, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::{Height, NodeId, PrincipalId};
use phantom_newtype::AmountOf;
use serde::{Deserialize, Serialize};
use slog::info;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

/// Builder object to declare a topology of an InternetComputer.
/// Used as input to the IC Manager.
#[derive(Clone, Debug, Default)]
pub struct InternetComputer {
    pub initial_version: Option<NodeSoftwareVersion>,
    pub default_vm_resources: VmResources,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
    pub subnets: Vec<Subnet>,
    pub node_operator: Option<PrincipalId>,
    pub node_provider: Option<PrincipalId>,
    pub unassigned_nodes: Vec<Node>,
    pub ssh_readonly_access_to_unassigned_nodes: Vec<String>,
    name: String,
    pub bitcoind_addr: Option<SocketAddr>,
    pub jaeger_addr: Option<SocketAddr>,
    pub socks_proxy: Option<String>,
    use_specified_ids_allocation_range: bool,
    /// Indicates whether this `InternetComputer` instance should be installed with
    /// GuestOS disk images of the latest-deployed mainnet version.
    pub with_mainnet_config: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmAllocationStrategy {
    #[serde(rename = "distributeToArbitraryHost")]
    DistributeToArbitraryHost,
    #[serde(rename = "distributeWithinSingleHost")]
    DistributeWithinSingleHost,
    #[serde(rename = "distributeAcrossDcs")]
    DistributeAcrossDcs,
}

impl InternetComputer {
    pub fn new() -> Self {
        Self {
            with_mainnet_config: false,
            ..Self::default()
        }
    }

    /// Set the VM resources (like number of virtual CPUs and memory) of all
    /// implicitly constructed subnets and nodes (like unassigned nodes
    /// added via `with_unassigned_nodes`).
    ///
    /// Setting the VM resources for explicitly constructed subnets
    /// has to be done on the subnet itself.
    pub fn with_default_vm_resources(mut self, default_vm_resources: VmResources) -> Self {
        self.default_vm_resources = default_vm_resources;
        self
    }

    pub fn with_vm_allocation(mut self, vm_allocation: VmAllocationStrategy) -> Self {
        self.vm_allocation = Some(vm_allocation);
        self
    }

    pub fn with_required_host_features(mut self, required_host_features: Vec<HostFeature>) -> Self {
        self.required_host_features = required_host_features;
        self
    }

    pub fn add_subnet(mut self, subnet: Subnet) -> Self {
        self.subnets.push(subnet);
        self
    }

    /// Adds a one-node subnet that's optimized to be "fast".
    ///
    /// The subnet is able to execute calls faster because the block time
    /// on the node is reduced.
    ///
    /// The subnet inherits the VM resources of the IC.
    pub fn add_fast_single_node_subnet(mut self, subnet_type: SubnetType) -> Self {
        let mut subnet = Subnet::fast_single_node(subnet_type);
        subnet.default_vm_resources = self.default_vm_resources;
        subnet.vm_allocation.clone_from(&self.vm_allocation);
        subnet
            .required_host_features
            .clone_from(&self.required_host_features);
        self.subnets.push(subnet);
        self
    }

    pub fn with_initial_replica(mut self, initial_replica: NodeSoftwareVersion) -> Self {
        self.initial_version = Some(initial_replica);
        self
    }

    pub fn with_node_operator(mut self, principal_id: PrincipalId) -> Self {
        self.node_operator = Some(principal_id);
        self
    }

    pub fn with_node_provider(mut self, principal_id: PrincipalId) -> Self {
        self.node_provider = Some(principal_id);
        self
    }

    /// Add the given number of unassigned nodes to the IC.
    ///
    /// The nodes inherit the VM resources of the IC.
    pub fn with_unassigned_nodes(mut self, no_of_nodes: usize) -> Self {
        for _ in 0..no_of_nodes {
            self.unassigned_nodes.push(Node::new_with_settings(
                self.default_vm_resources,
                self.vm_allocation.clone(),
                self.required_host_features.clone(),
            ));
        }
        self
    }

    /// Add unassigned node with custom settings.
    pub fn with_unassigned_node(mut self, node: Node) -> Self {
        self.unassigned_nodes.push(node);
        self
    }

    /// Add a single unassigned node with the given IPv4 configuration
    pub fn with_ipv4_enabled_unassigned_node(mut self, ipv4_config: IPv4Config) -> Self {
        self.unassigned_nodes.push(
            Node::new_with_settings(
                self.default_vm_resources,
                self.vm_allocation.clone(),
                self.required_host_features.clone(),
            )
            .with_ipv4_config(ipv4_config),
        );
        self
    }

    /// Give this particular internet computer instance a name. The name must be
    /// unique across internet computer instances created within a system
    /// environment.
    ///
    /// By default, an IC instance has no name. Thus, not calling this method is
    /// equivalent to `.with_name("")`.
    pub fn with_name<S: ToString>(mut self, name: S) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn with_bitcoind_addr(mut self, bitcoind_addr: SocketAddr) -> Self {
        self.bitcoind_addr = Some(bitcoind_addr);
        self
    }

    pub fn with_jaeger_addr(mut self, jaeger_addr: SocketAddr) -> Self {
        self.jaeger_addr = Some(jaeger_addr);
        self
    }

    pub fn use_specified_ids_allocation_range(mut self) -> Self {
        self.use_specified_ids_allocation_range = true;
        self
    }

    pub fn with_socks_proxy(mut self, socks_proxy: String) -> Self {
        self.socks_proxy = Some(socks_proxy);
        self
    }

    pub fn with_mainnet_config(mut self) -> Self {
        self.with_mainnet_config = true;
        self
    }

    pub fn setup_and_start(&mut self, env: &TestEnv) -> Result<()> {
        // propagate required host features and resource settings to all vms
        let farm = Farm::from_test_env(env, "Internet Computer");
        for subnet in self.subnets.iter_mut() {
            for node in subnet.nodes.iter_mut() {
                node.required_host_features = node
                    .required_host_features
                    .iter()
                    .chain(self.required_host_features.iter())
                    .cloned()
                    .collect();
                node.vm_resources = node.vm_resources.or(&self.default_vm_resources);
            }
        }
        for node in self.unassigned_nodes.iter_mut() {
            node.required_host_features = node
                .required_host_features
                .iter()
                .chain(self.required_host_features.iter())
                .cloned()
                .collect();
            node.vm_resources = node.vm_resources.or(&self.default_vm_resources);
        }

        let tempdir = tempfile::tempdir()?;
        self.create_secret_key_stores(tempdir.path())?;
        let group_setup = GroupSetup::read_attribute(env);
        let group_name: String = group_setup.infra_group_name;
        let res_request = get_resource_request(self, env, &group_name)?;

        if InfraProvider::read_attribute(env) == InfraProvider::K8s {
            let image_url = res_request.primary_image.url.clone();
            let tnet = TNet::read_attribute(env).image_url(image_url.as_ref());
            block_on(tnet.deploy_guestos_image()).expect("failed to deploy guestos image");
            tnet.write_attribute(env);
        }

        let res_group = allocate_resources(&farm, &res_request, env)?;
        self.propagate_ip_addrs(&res_group);
        let init_ic = init_ic(
            self,
            env,
            &env.logger(),
            self.use_specified_ids_allocation_range,
        )?;

        // save initial registry snapshot for this pot
        let local_store_path = env
            .registry_local_store_path(&self.name)
            .expect("corrupted ic-prep directory structure");
        let reg_snapshot = ic_regedit::load_registry_local_store(local_store_path)?;
        let reg_snapshot_serialized =
            serde_json::to_string_pretty(&reg_snapshot).expect("Could not pretty print value.");
        IcPrepStateDir::new(init_ic.target_dir.to_str().expect("invalid target dir"));
        std::fs::write(
            init_ic.target_dir.join("initial_registry_snapshot.json"),
            reg_snapshot_serialized,
        )
        .unwrap();
        let topology_snapshot = env.topology_snapshot_by_name(&self.name);
        // Pretty print IC Topology using the Display implementation
        info!(env.logger(), "{topology_snapshot}");
        // Emit a json log event, to be consumed by log post-processing tools.
        topology_snapshot.emit_log_event(&env.logger());
        setup_and_start_vms(&init_ic, self, env, &farm, &group_name)?;
        Ok(())
    }

    fn create_secret_key_stores(&mut self, tempdir: &Path) -> Result<()> {
        for n in self.unassigned_nodes.iter_mut() {
            let sks = NodeSecretKeyStore::new(tempdir.join(format!("node-{:p}", n)))?;
            n.secret_key_store = Some(sks);
        }
        for s in self.subnets.iter_mut() {
            for n in s.nodes.iter_mut() {
                let sks = NodeSecretKeyStore::new(tempdir.join(format!("node-{:p}", n)))?;
                n.secret_key_store = Some(sks);
            }
        }
        Ok(())
    }

    fn propagate_ip_addrs(&mut self, res_group: &ResourceGroup) {
        for n in self.unassigned_nodes.iter_mut() {
            n.ipv6 = Some(
                res_group
                    .vms
                    .get(&n.id().to_string())
                    .unwrap_or_else(|| panic!("no VM found for [node_id = {:?}]", n.id()))
                    .ipv6,
            );
        }
        for s in self.subnets.iter_mut() {
            for n in s.nodes.iter_mut() {
                n.ipv6 = Some(
                    res_group
                        .vms
                        .get(n.id().to_string().as_str())
                        .unwrap_or_else(|| panic!("no VM found for [node_id = {:?}]", n.id()))
                        .ipv6,
                );
            }
        }
    }

    pub fn has_malicious_behaviours(&self) -> bool {
        let has_malicious_nodes: bool = self
            .subnets
            .iter()
            .any(|s| s.nodes.iter().any(|n| n.malicious_behaviour.is_some()));
        let has_malicious_unassigned_nodes = self
            .unassigned_nodes
            .iter()
            .any(|n| n.malicious_behaviour.is_some());
        has_malicious_nodes || has_malicious_unassigned_nodes
    }

    pub fn get_malicious_behavior_of_node(&self, node_id: NodeId) -> Option<MaliciousBehaviour> {
        let node_filter_map = |n: &Node| {
            if n.secret_key_store.as_ref().unwrap().node_id == node_id {
                Some(n.malicious_behaviour.clone())
            } else {
                None
            }
        };
        // extract malicious nodes all subnet nodes
        let mut malicious_nodes: Vec<Option<MaliciousBehaviour>> = self
            .subnets
            .iter()
            .flat_map(|s| s.nodes.iter().filter_map(node_filter_map))
            .collect();
        // extract malicious nodes from all unassigned nodes
        malicious_nodes.extend(self.unassigned_nodes.iter().filter_map(node_filter_map));
        match malicious_nodes.len() {
            0 => None,
            1 => malicious_nodes.first().unwrap().clone(),
            _ => panic!("more than one node has id={node_id}"),
        }
    }

    pub fn get_query_stats_epoch_length_of_node(&self, node_id: NodeId) -> Option<u64> {
        self.subnets
            .iter()
            .find(|subnet| {
                subnet
                    .nodes
                    .iter()
                    .any(|node| node.secret_key_store.as_ref().unwrap().node_id == node_id)
            })
            .and_then(|subnet| subnet.query_stats_epoch_length)
    }

    pub fn get_ipv4_config_of_node(&self, node_id: NodeId) -> Option<IPv4Config> {
        let node_filter_map = |n: &Node| {
            if n.secret_key_store.as_ref().unwrap().node_id == node_id {
                Some(n.ipv4.clone())
            } else {
                None
            }
        };
        // extract ipv4-enabled nodes all subnet nodes
        let mut ipv4_enabled_nodes: Vec<Option<IPv4Config>> = self
            .subnets
            .iter()
            .flat_map(|s| s.nodes.iter().filter_map(node_filter_map))
            .collect();
        // extract malicious nodes from all unassigned nodes
        ipv4_enabled_nodes.extend(self.unassigned_nodes.iter().filter_map(node_filter_map));
        match ipv4_enabled_nodes.len() {
            0 => None,
            1 => ipv4_enabled_nodes.first().unwrap().clone(),
            _ => panic!("more than one node has id={node_id}"),
        }
    }

    pub fn get_domain_of_node(&self, node_id: NodeId) -> Option<String> {
        let node_filter_map = |n: &Node| {
            if n.secret_key_store.as_ref().unwrap().node_id == node_id {
                Some(n.domain.clone())
            } else {
                None
            }
        };
        // extract all matching nodes from all subnet nodes
        let mut nodes: Vec<Option<String>> = self
            .subnets
            .iter()
            .flat_map(|s| s.nodes.iter().filter_map(node_filter_map))
            .collect();
        // extract malicious nodes from all unassigned nodes
        nodes.extend(self.unassigned_nodes.iter().filter_map(node_filter_map));
        match nodes.len() {
            0 => None,
            1 => nodes.first().unwrap().clone(),
            _ => panic!("more than one node has id={node_id}"),
        }
    }
}

/// A builder for the initial configuration of a subnetwork.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Subnet {
    pub default_vm_resources: VmResources,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
    pub nodes: Vec<Node>,
    pub max_ingress_bytes_per_message: Option<u64>,
    pub max_ingress_messages_per_block: Option<u64>,
    pub max_block_payload_size: Option<u64>,
    #[serde(with = "humantime_serde")]
    pub unit_delay: Option<Duration>,
    #[serde(with = "humantime_serde")]
    pub initial_notary_delay: Option<Duration>,
    pub dkg_interval_length: Option<Height>,
    pub dkg_dealings_per_block: Option<usize>,
    // NOTE: Some values in this config, like the http port,
    // are overwritten in `update_and_write_node_config`.
    pub subnet_type: SubnetType,
    pub max_instructions_per_message: Option<u64>,
    pub max_instructions_per_round: Option<u64>,
    pub max_instructions_per_install_code: Option<u64>,
    pub features: Option<SubnetFeatures>,
    pub max_number_of_canisters: Option<u64>,
    pub ssh_readonly_access: Vec<String>,
    pub ssh_backup_access: Vec<String>,
    pub chain_key_config: Option<ChainKeyConfig>,
    pub running_state: SubnetRunningState,
    pub query_stats_epoch_length: Option<u64>,
    pub initial_height: u64,
}

impl Subnet {
    pub fn new(subnet_type: SubnetType) -> Self {
        Self {
            default_vm_resources: Default::default(),
            vm_allocation: Default::default(),
            required_host_features: vec![],
            nodes: vec![],
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay: None,
            initial_notary_delay: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            max_number_of_canisters: None,
            subnet_type,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            chain_key_config: None,
            running_state: SubnetRunningState::Active,
            query_stats_epoch_length: None,
            initial_height: 0,
        }
    }

    /// Set the VM resources (like number of virtual CPUs and memory) of all
    /// implicitly constructed nodes.
    ///
    /// Setting the VM resources for explicitly constructed nodes
    /// has to be via `Node::new_with_vm_resources`.
    pub fn with_default_vm_resources(mut self, default_vm_resources: VmResources) -> Self {
        self.default_vm_resources = default_vm_resources;
        self
    }

    pub fn with_vm_allocation(mut self, vm_allocation: VmAllocationStrategy) -> Self {
        self.vm_allocation = Some(vm_allocation);
        self
    }

    pub fn with_required_host_features(mut self, required_host_features: Vec<HostFeature>) -> Self {
        self.required_host_features = required_host_features;
        self
    }

    pub fn with_max_ingress_messages_per_block(
        mut self,
        max_ingress_messages_per_block: u64,
    ) -> Self {
        self.max_ingress_messages_per_block = Some(max_ingress_messages_per_block);
        self
    }

    /// An empty subnet that's optimized to be "fast".
    ///
    /// The subnet is able to execute calls faster because the block time
    /// on its nodes is reduced.
    ///
    /// See also `fast_single_node`.
    pub fn fast(subnet_type: SubnetType, no_of_nodes: usize) -> Self {
        assert!(
            0 < no_of_nodes,
            "cannot create subner with {} nodes",
            no_of_nodes
        );
        Self::new(subnet_type)
            // Shorter block time.
            .with_unit_delay(Duration::from_millis(200))
            .with_initial_notary_delay(Duration::from_millis(500))
            .add_nodes(no_of_nodes)
    }

    /// A one-node subnet that's optimized to be "fast".
    pub fn fast_single_node(subnet_type: SubnetType) -> Self {
        Self::fast(subnet_type, 1)
    }

    /// A (many-node) subnet that's optimized to be "slow" so that its nodes can
    /// be run on a single machine without issues.
    ///
    /// Running many replicas on one machine means that those replicas will
    /// compete for the resources on that machine. The consensus delays
    /// essentially determine how fast the blocks are proposed and how fast the
    /// proposed blocks are notarized. If enough replicas get to run their
    /// notarizer before it is time for the next blockmaker to propose, that
    /// single block gets notarized and eventually finalized. If the system is
    /// so loaded that it is already time for the second blockmaker to propose a
    /// block before the first block gets notarized, this adds to the load of
    /// the system and points to the fact that consensus is struggling to make
    /// easy progress with the given parameters. We call this situation
    /// starvation of consensus. When the delays are increased, the amount of
    /// work that consensus attempts to make in any given time interval is
    /// decreased. This gives the first block more time to be notarized by
    /// enough replicas and possibly avoids the additional load of
    /// making/checking/notarizing multiple blocks per height. A slower
    /// consensus is therefore preferable while running multiple replicas on a
    /// single machine.
    pub fn slow(subnet_type: SubnetType) -> Self {
        Self::new(subnet_type)
            // Shorter block time.
            .with_unit_delay(Duration::from_millis(1000))
            .with_initial_notary_delay(Duration::from_millis(5000))
    }

    /// Add the given number of nodes to the subnet.
    ///
    /// The nodes will inherit the VM resources of the subnet.
    pub fn add_nodes(self, no_of_nodes: usize) -> Self {
        (0..no_of_nodes).fold(self, |subnet, _| {
            let default_vm_resources = subnet.default_vm_resources;
            let vm_allocation = subnet.vm_allocation.clone();
            let required_host_features = subnet.required_host_features.clone();
            subnet.add_node(Node::new_with_settings(
                default_vm_resources,
                vm_allocation,
                required_host_features,
            ))
        })
    }

    pub fn add_node(mut self, node: Node) -> Self {
        self.nodes.push(node);
        self
    }

    pub fn with_max_ingress_message_size(mut self, limit: u64) -> Self {
        self.max_ingress_bytes_per_message = Some(limit);
        self
    }

    pub fn with_max_block_payload_size(mut self, limit: u64) -> Self {
        self.max_block_payload_size = Some(limit);
        self
    }

    pub fn with_unit_delay(mut self, unit_delay: Duration) -> Self {
        self.unit_delay = Some(unit_delay);
        self
    }

    pub fn with_initial_notary_delay(mut self, initial_notary_delay: Duration) -> Self {
        self.initial_notary_delay = Some(initial_notary_delay);
        self
    }

    pub fn with_dkg_interval_length(mut self, dkg_interval_length: Height) -> Self {
        self.dkg_interval_length = Some(dkg_interval_length);
        self
    }

    pub fn with_features(mut self, features: SubnetFeatures) -> Self {
        self.features = Some(features);
        self
    }

    pub fn with_max_number_of_canisters(mut self, max_number_of_canisters: u64) -> Self {
        self.max_number_of_canisters = Some(max_number_of_canisters);
        self
    }

    pub fn with_chain_key_config(mut self, chain_key_config: ChainKeyConfig) -> Self {
        self.chain_key_config = Some(chain_key_config);
        self
    }

    pub fn with_query_stats_epoch_length(mut self, length: u64) -> Self {
        self.query_stats_epoch_length = Some(length);
        self
    }

    pub fn halted(mut self) -> Self {
        self.running_state = SubnetRunningState::Halted;
        self
    }

    pub fn with_initial_height(mut self, initial_height: u64) -> Self {
        self.initial_height = initial_height;
        self
    }

    pub fn with_random_height(mut self) -> Self {
        use rand::Rng;
        self.initial_height = rand::thread_rng().gen();
        self
    }

    pub fn add_malicious_nodes(
        self,
        no_of_nodes: usize,
        malicious_behaviour: MaliciousBehaviour,
    ) -> Self {
        (0..no_of_nodes).fold(self, |subnet, _| {
            let default_vm_resources = subnet.default_vm_resources;
            let vm_allocation = subnet.vm_allocation.clone();
            let required_host_features = subnet.required_host_features.clone();
            subnet.add_node(
                Node::new_with_settings(
                    default_vm_resources,
                    vm_allocation,
                    required_host_features,
                )
                .with_malicious_behaviour(malicious_behaviour.clone()),
            )
        })
    }

    pub fn add_node_with_ipv4(self, ipv4_config: IPv4Config) -> Self {
        let default_vm_resources = self.default_vm_resources;
        let vm_allocation = self.vm_allocation.clone();
        let required_host_features = self.required_host_features.clone();
        self.add_node(
            Node::new_with_settings(default_vm_resources, vm_allocation, required_host_features)
                .with_ipv4_config(ipv4_config),
        )
    }

    /// provides a small summary of this subnet topology and config to be used
    /// as a part of a test environment identifier.
    pub fn summary(&self) -> String {
        let ns = self.nodes.len();
        let mut s = DefaultHasher::new();
        format!("{:?}", self).hash(&mut s);
        let config_hash = format!("{:x}", s.finish());
        format!("S{:02}{}", ns, &config_hash[0..3])
    }
}

impl Default for Subnet {
    fn default() -> Self {
        Self {
            default_vm_resources: Default::default(),
            vm_allocation: Default::default(),
            required_host_features: vec![],
            nodes: vec![],
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay: Some(Duration::from_millis(200)),
            initial_notary_delay: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            subnet_type: SubnetType::System,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            max_number_of_canisters: None,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            chain_key_config: None,
            running_state: SubnetRunningState::Active,
            query_stats_epoch_length: None,
            initial_height: 0,
        }
    }
}

pub type NrOfVCPUs = AmountOf<VCPUs, u64>;
pub type AmountOfMemoryKiB = AmountOf<MemoryKiB, u64>;
pub type ImageSizeGiB = AmountOf<SizeGiB, u64>;

pub enum VCPUs {}
pub enum MemoryKiB {}
pub enum SizeGiB {}

/// Resources that the VM will use like number of virtual CPUs and memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct VmResources {
    pub vcpus: Option<NrOfVCPUs>,
    pub memory_kibibytes: Option<AmountOfMemoryKiB>,
    pub boot_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
}

impl VmResources {
    /// Applies Option::or to all individual fields `self` and `other`.
    pub fn or(&self, other: &VmResources) -> Self {
        Self {
            vcpus: self.vcpus.or(other.vcpus),
            memory_kibibytes: self.memory_kibibytes.or(other.memory_kibibytes),
            boot_image_minimal_size_gibibytes: self
                .boot_image_minimal_size_gibibytes
                .or(other.boot_image_minimal_size_gibibytes),
        }
    }
}

/// A builder for the initial configuration of a node.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct Node {
    pub vm_resources: VmResources,
    pub vm_allocation: Option<VmAllocationStrategy>,
    pub required_host_features: Vec<HostFeature>,
    pub secret_key_store: Option<NodeSecretKeyStore>,
    pub ipv6: Option<Ipv6Addr>,
    pub malicious_behaviour: Option<MaliciousBehaviour>,
    pub ipv4: Option<IPv4Config>,
    pub domain: Option<String>,
}

impl Node {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with_settings(
        vm_resources: VmResources,
        vm_allocation: Option<VmAllocationStrategy>,
        required_host_features: Vec<HostFeature>,
    ) -> Self {
        let mut node = Node::new();
        node.vm_resources = vm_resources;
        node.vm_allocation = vm_allocation;
        node.required_host_features = required_host_features;
        node
    }

    pub fn id(&self) -> NodeId {
        self.secret_key_store
            .clone()
            .expect("no secret key store")
            .node_id
    }

    pub fn with_malicious_behaviour(mut self, malicious_behaviour: MaliciousBehaviour) -> Self {
        self.malicious_behaviour = Some(malicious_behaviour);
        self
    }

    pub fn with_ipv4_config(mut self, ipv4_config: IPv4Config) -> Self {
        self.ipv4 = Some(ipv4_config);
        self
    }

    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }
}
