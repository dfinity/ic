//! # The Test Environment API
//!
//! The goal of this module is to provide the user with an extensible,
//! consistent and ergonomic API to access the Test Environment. The Test
//! Env is a file-system directory structure that contains all
//! information about the environment within which the test is executed.
//!
//! In particular, the Test Env contains the registry local store of
//! the Internet Computer under test. The user can access the topology of the
//! Internet Computer through the [TopologySnapshot].
//!
//! ## How to use the topology API
//!
//! The most common usage pattern is as follows:
//!
//! 1. Take a "snapshot" of the topology.
//! 2. Select a node that you want to interact with.
//! 3. Use the agent to install or interact with canisters;
//!
//! ### Take a snapshot of the topology
//!
//! The reason it is called a topology *snapshot* is because it reflects the
//! topology at a fixed registry version. A call to `topology_snapshot()`
//! returns a snapshot at the newest _locally_ available registry version.
//!
//! ```text
//! let topology_snapshot = env.topology_snapshot();
//! ```
//!
//! It is possible to create multiple IC within a test environment. To
//! differentiate IC instance, they can be given a name. For example, a topology
//! snapshot for an Internet Computer instance named `ic1` can be retrieved as
//! follows:
//!
//! ```text
//! let topology_snapshot = env.topology_snapshot_by_name("ic1");
//! ```
//!
//! **Note**: Calling this function does *not* update the local store.
//!
//! ### Selecting a node
//!
//! The topology API has a hierarchical structure that follows, well, the
//! topology of the Internet Computer. The method `subnets()` returns an
//! iterator of `SubnetSnapshot`-objects which--as its name suggest--represents
//! a subnet at the registry version of the underlying topology snapshot.
//! Similar applies to the method `nodes()` on the subnet snapshot.
//!
//! For example, selecting the first node on the first subnet:
//!
//! ```text
//! let node = topology_snapshot
//!     .subnets()
//!     .flat_map(|s| s.nodes())
//!     .next()
//!     .unwrap();
//! ```
//!
//! ### Interacting with a Node
//!
//! As the trait [HasPublicApiUrl] is implemented for [IcNodeSnapshot]. At its
//! core, this trait provides a method `get_public_api_url() -> Url`. In
//! addition, some utility methods are provided.
//!
//! The most common way to interact with the public API is using the `agent-rs`
//! library. For "isolated" interactions, one can use the utility method
//! `with_default_agent()`. For example, the following installs a
//! UniversalCanister on the subnet that the node belongs to and returns its
//! principal id.
//!
//! ```text
//! let ucan_id = node.with_default_agent(|agent| async move {
//!     let ucan = UniversalCanister::new(&agent).await;
//!     ucan.canister_id()
//! });
//! ```
//!
//! For example, at a later point, this can be used again to interact with the
//! already installed canister:
//!
//! ```text
//! let ucan_id = node.with_default_agent(move |agent| async move {
//!     let ucan = UniversalCanister::from_canister_id(&agent, ucan_id).await;
//!     // etc.
//! });
//! ```
//!
//! If one wants to retain the agent for later use, one should use the
//! `build_default_agent()` method:
//!
//! ```text
//! let agent = node.build_default_agent();
//! ```
//! Node VMs can be killed, started, or rebooted as follows:
//!
//! ```text
//! node.vm().kill();
//! node.vm().start();
//! node.vm().reboot();
//! ```
//!
//! ## Design Principles
//!
//! (Design Principle  I) Sync by default.
//!
//! Just like rust itself, the API is synchronous (as opposed to async) by
//! default.
//!
//! (Design Principle II) Everything is sync'ed to the file system.
//!
//! The API is just an explorer of the data stored in the file system context.
//! For example, if the user wants to fetch an updated version of the IC's
//! topology, the newest version of the registry must be sync'ed to disk. This
//! way, the local store can be stored away with the test artifacts and used for
//! debugging.
//!
//! (Design Principle II) Be explicit--not smart.
//!
//! It is better to get the user to do the right thing a 100% of the time,
//! rather to provide a convenient API that works only 99% of the time.
//!
//! For example, one of the major challenges when exposing the topology is
//! ensuring read-after-write consistency: After executing a proposal that
//! changes the topology, ideally the local registry is updated to reflect that
//! change. However, when contacting any node on the root subnet, there is no
//! guarantee that that node has caught up with the updated registry version.
//! Even worse, the test might be running a scenario that has the node shut
//! down.
//!
//! Thus, instead of randomly selecting a node to fetch registry updates, it is
//! better to let the user select a node.
//!

use super::cli::{
    bail_if_sha256_invalid, parse_journalbeat_hosts, parse_replica_log_debug_overrides,
};
use super::config::NODES_INFO;
use super::driver_setup::{DEFAULT_FARM_BASE_URL, SSH_AUTHORIZED_PRIV_KEYS_DIR};
use super::test_setup::GroupSetup;
use crate::driver::farm::{Farm, GroupSpec};
use crate::driver::new::constants;
use crate::driver::test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute};
use crate::util::{create_agent, delay};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use canister_test::{RemoteTestRuntime, Runtime};
use ic_agent::export::Principal;
use ic_agent::{Agent, AgentError};
use ic_base_types::PrincipalId;
use ic_canister_client::Agent as InternalAgent;
use ic_canister_client::Sender;
use ic_fondue::ic_manager::handle::READY_RESPONSE_TIMEOUT;
use ic_fondue::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID};
use ic_nns_init::read_initial_mutations_from_local_store_dir;
use ic_nns_test_utils::{common::NnsInitPayloadsBuilder, itest_helpers::NnsCanisters};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_protobuf::registry::{node::v1 as pb_node, subnet::v1 as pb_subnet};
use ic_registry_client_helpers::{
    node::NodeRegistry, routing_table::RoutingTableRegistry, subnet::SubnetListRegistry,
    subnet::SubnetRegistry,
};
use ic_registry_local_registry::LocalRegistry;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use ic_types::{NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use ic_utils::interfaces::ManagementCanister;
use icp_ledger::{LedgerCanisterInitPayload, Tokens};
use slog::{info, warn, Logger};
use ssh2::Session;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{convert::TryFrom, net::IpAddr, str::FromStr, sync::Arc};
use tokio::runtime::Runtime as Rt;
use url::Url;

pub const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(500);
pub const SSH_RETRY_TIMEOUT: Duration = Duration::from_secs(500);
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);
const REGISTRY_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

pub type NodesInfo = HashMap<NodeId, Option<MaliciousBehaviour>>;

/// An immutable snapshot of the Internet Computer topology valid at a
/// particular registry version.
#[derive(Clone)]
pub struct TopologySnapshot {
    registry_version: RegistryVersion,
    local_registry: Arc<LocalRegistry>,
    ic_name: String,
    env: TestEnv,
}

impl TopologySnapshot {
    pub fn subnets(&self) -> Box<dyn Iterator<Item = SubnetSnapshot>> {
        let registry_version = self.local_registry.get_latest_version();
        Box::new(
            self.local_registry
                .get_subnet_ids(registry_version)
                .unwrap_result()
                .into_iter()
                .map(|subnet_id| SubnetSnapshot {
                    subnet_id,
                    registry_version,
                    local_registry: self.local_registry.clone(),
                    env: self.env.clone(),
                    ic_name: self.ic_name.clone(),
                })
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    pub fn subnet_canister_ranges(&self, sub: SubnetId) -> Vec<CanisterIdRange> {
        let registry_version = self.local_registry.get_latest_version();
        self.local_registry
            .get_subnet_canister_ranges(registry_version, sub)
            .expect("Could not deserialize optional routing table from local registry.")
            .expect("Optional routing table is None in local registry.")
    }

    pub fn unassigned_nodes(&self) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
        let registry_version = self.local_registry.get_latest_version();
        let assigned_nodes: HashSet<_> = self
            .local_registry
            .get_subnet_ids(registry_version)
            .unwrap_result()
            .into_iter()
            .flat_map(|subnet_id| {
                self.local_registry
                    .get_node_ids_on_subnet(subnet_id, registry_version)
                    .unwrap_result()
            })
            .collect();

        Box::new(
            self.local_registry
                .get_node_ids(registry_version)
                .unwrap()
                .into_iter()
                .filter(|node_id| !assigned_nodes.contains(node_id))
                .map(|node_id| IcNodeSnapshot {
                    node_id,
                    registry_version,
                    local_registry: self.local_registry.clone(),
                    env: self.env.clone(),
                    ic_name: self.ic_name.clone(),
                })
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    /// The subnet id of the root subnet.
    ///
    /// This method panics if in the underlying registry, the root subnet id is
    /// not set.
    pub fn root_subnet_id(&self) -> SubnetId {
        self.local_registry
            .get_root_subnet_id(self.registry_version)
            .expect("failed to fetch root subnet id from registry")
            .expect("root subnet id is not set")
    }

    pub fn root_subnet(&self) -> SubnetSnapshot {
        let subnet_id = self.root_subnet_id();
        SubnetSnapshot {
            subnet_id,
            registry_version: self.registry_version,
            local_registry: self.local_registry.clone(),
            env: self.env.clone(),
            ic_name: self.ic_name.clone(),
        }
    }

    /// This method blocks and repeatedly fetches updates from the registry
    /// canister until the latest available registry version is newer than the
    /// registry version of this snapshot.
    ///
    /// The registry version of the returned snapshot is the newest available
    /// registry version.
    ///
    /// # Known Limitations
    ///
    /// As the test driver does not implement timeouts on the test level, this
    /// method blocks for a duration of 180 seconds at maximum.
    pub async fn block_for_newer_registry_version(&self) -> Result<TopologySnapshot> {
        let minimum_version = self.local_registry.get_latest_version() + RegistryVersion::from(1);
        self.block_for_min_registry_version(minimum_version).await
    }

    /// This method blocks and repeatedly fetches updates from the registry
    /// canister until the latest available registry version is higher or equal
    /// to `min_version`.
    ///
    /// The registry version of the returned snapshot is the newest available
    /// registry version.
    ///
    /// Note that this method will immediately return if `min_version` is
    /// less than or equal to the latest available version.
    ///
    /// # Known Limitations
    ///
    /// As the test driver does not implement timeouts on the test level, this
    /// method blocks for a duration of 180 seconds at maximum.
    pub async fn block_for_min_registry_version(
        &self,
        min_version: RegistryVersion,
    ) -> Result<TopologySnapshot> {
        let duration = Duration::from_secs(180);
        let backoff = Duration::from_secs(2);
        let mut latest_version = self.local_registry.get_latest_version();
        if min_version > latest_version {
            latest_version = retry_async(&self.env.logger(), duration, backoff, || async move {
                self.local_registry.sync_with_nns().await?;
                let latest_version = self.local_registry.get_latest_version();
                if latest_version >= min_version {
                    Ok(latest_version)
                } else {
                    bail!(
                        "latest_version: {}, expected minimum version: {}",
                        latest_version,
                        min_version
                    )
                }
            })
            .await?;
        }
        Ok(Self {
            registry_version: latest_version,
            local_registry: self.local_registry.clone(),
            ic_name: self.ic_name.clone(),
            env: self.env.clone(),
        })
    }
}

#[derive(Clone)]
pub struct SubnetSnapshot {
    pub subnet_id: SubnetId,
    ic_name: String,
    registry_version: RegistryVersion,
    local_registry: Arc<LocalRegistry>,
    env: TestEnv,
}

impl SubnetSnapshot {
    pub fn subnet_type(&self) -> SubnetType {
        let subnet_record = self.raw_subnet_record();
        SubnetType::try_from(subnet_record.subnet_type)
            .expect("Could not transform from protobuf subnet type")
    }

    pub fn raw_subnet_record(&self) -> pb_subnet::SubnetRecord {
        self.local_registry
            .get_subnet_record(self.subnet_id, self.registry_version)
            .unwrap_result()
    }
}

#[derive(Clone)]
pub struct IcNodeSnapshot {
    pub ic_name: String,
    pub node_id: NodeId,
    registry_version: RegistryVersion,
    local_registry: Arc<LocalRegistry>,
    env: TestEnv,
}

impl IcNodeSnapshot {
    pub fn is_malicious(&self) -> bool {
        self.malicious_behavior().is_some()
    }

    pub fn malicious_behavior(&self) -> Option<MaliciousBehaviour> {
        let nodes_info: NodesInfo = self
            .env
            .read_json_object(NODES_INFO)
            .expect("Couldn't read info of the nodes from a file.");
        nodes_info
            .get(&self.node_id)
            .unwrap_or_else(|| {
                panic!(
                    "Node with id={} is not found in the {} file.",
                    self.node_id, NODES_INFO
                );
            })
            .clone()
    }

    fn raw_node_record(&self) -> pb_node::NodeRecord {
        self.local_registry
            .get_transport_info(self.node_id, self.registry_version)
            .unwrap_result()
    }

    fn http_endpoint_to_url(http: &pb_node::ConnectionEndpoint) -> Url {
        let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
            Ok(v) if v.is_ipv6() => format!("[{}]", v),
            Ok(v) => v.to_string(),
            Err(_) => http.ip_addr.clone(),
        };

        let url = format!("http://{}:{}/", host_str, http.port);
        Url::parse(&url).expect("Could not parse Url")
    }

    pub fn get_ip_addr(&self) -> IpAddr {
        let node_record = self.raw_node_record();
        let connection_endpoint = node_record.http.expect("Node doesn't have URL");
        IpAddr::from_str(&connection_endpoint.ip_addr).expect("Missing IP address in the node")
    }

    /// Is it accessible via ssh with the `admin` user.
    pub fn can_login_as_admin_via_ssh(&self) -> Result<bool> {
        let sess = self.get_ssh_session(ADMIN)?;
        let mut channel = sess.channel_session()?;
        channel.exec("echo ready")?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        Ok(s.trim() == "ready")
    }

    /// Waits until the [can_login_as_admin_via_ssh] returns `true`.
    pub fn await_can_login_as_admin_via_ssh(&self) -> Result<()> {
        retry(self.env.logger(), READY_WAIT_TIMEOUT, RETRY_BACKOFF, || {
            self.can_login_as_admin_via_ssh().and_then(|s| {
                if !s {
                    bail!("Not ready!")
                } else {
                    Ok(())
                }
            })
        })
    }

    pub fn effective_canister_id(&self) -> PrincipalId {
        let registry_version = self.local_registry.get_latest_version();
        let subnet_id: Option<SubnetId> = self
            .local_registry
            .get_subnet_ids(registry_version)
            .unwrap_result()
            .into_iter()
            .find(|subnet_id| {
                self.local_registry
                    .get_node_ids_on_subnet(*subnet_id, registry_version)
                    .unwrap_result()
                    .contains(&self.node_id)
            });
        match subnet_id {
            Some(subnet_id) => {
                let canister_ranges = self
                    .local_registry
                    .get_subnet_canister_ranges(registry_version, subnet_id)
                    .expect("Could not deserialize optional routing table from local registry.")
                    .expect("Optional routing table is None in local registry.");
                match canister_ranges.get(0) {
                    Some(range) => range.start.get(),
                    None => PrincipalId::default(),
                }
            }
            None => PrincipalId::default(),
        }
    }

    /// Load wasm binary from the artifacts directory (see [HasArtifacts]) and
    /// install it on the target node.
    ///
    /// # Panics
    ///
    /// This function panics if the canister `name` could not be loaded, is not
    /// a wasm module or the installation fails.
    pub fn create_and_install_canister_with_arg(
        &self,
        name: &str,
        arg: Option<Vec<u8>>,
    ) -> Principal {
        let canister_bytes = self.test_env().load_wasm(name);
        let effective_canister_id = self.effective_canister_id();

        self.with_default_agent(move |agent| async move {
            // Create a canister.
            let mgr = ManagementCanister::create(&agent);
            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(effective_canister_id)
                .call_and_wait(delay())
                .await
                .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
                .0;

            let mut install_code = mgr.install_code(&canister_id, &canister_bytes);
            if let Some(arg) = arg {
                install_code = install_code.with_raw_arg(arg)
            }
            install_code
                .call_and_wait(delay())
                .await
                .map_err(|err| format!("Couldn't install canister: {}", err))?;
            Ok::<_, String>(canister_id)
        })
        .expect("Could not install canister")
    }
}

pub trait HasTopologySnapshot {
    fn topology_snapshot(&self) -> TopologySnapshot;
    fn topology_snapshot_by_name(&self, name: &str) -> TopologySnapshot;

    fn create_topology_snapshot<S: ToString, P: AsRef<Path>>(
        name: S,
        local_store_path: P,
        env: TestEnv,
    ) -> TopologySnapshot {
        let local_registry = Arc::new(
            LocalRegistry::new(local_store_path, REGISTRY_QUERY_TIMEOUT)
                .expect("Could not create local registry"),
        );
        let registry_version = local_registry.get_latest_version();
        TopologySnapshot {
            local_registry,
            registry_version,
            ic_name: name.to_string(),
            env,
        }
    }
}

impl HasTopologySnapshot for TestEnv {
    fn topology_snapshot(&self) -> TopologySnapshot {
        let local_store_path = self
            .prep_dir("")
            .expect("No no name Internet Computer")
            .registry_local_store_path();
        Self::create_topology_snapshot("", local_store_path, self.clone())
    }

    fn topology_snapshot_by_name(&self, name: &str) -> TopologySnapshot {
        let local_store_path = self
            .prep_dir(name)
            .unwrap_or_else(|| panic!("No snapshot for internet computer: {:?}", name))
            .registry_local_store_path();
        Self::create_topology_snapshot(name, local_store_path, self.clone())
    }
}

pub trait HasRegistryLocalStore {
    fn registry_local_store_path(&self, name: &str) -> Option<PathBuf>;
}

impl HasRegistryLocalStore for TestEnv {
    fn registry_local_store_path(&self, name: &str) -> Option<PathBuf> {
        self.prep_dir(name).map(|d| d.registry_local_store_path())
    }
}

pub trait HasIcDependencies {
    fn get_farm_url(&self) -> Result<Url>;
    fn get_journalbeat_hosts(&self) -> Result<Vec<String>>;
    fn get_initial_replica_version(&self) -> Result<ReplicaVersion>;
    fn get_replica_log_debug_overrides(&self) -> Result<Vec<String>>;
    fn get_ic_os_img_url(&self) -> Result<Url>;
    fn get_ic_os_img_sha256(&self) -> Result<String>;
    fn get_malicious_ic_os_img_url(&self) -> Result<Url>;
    fn get_malicious_ic_os_img_sha256(&self) -> Result<String>;
    fn get_ic_os_update_img_url(&self) -> Result<Url>;
    fn get_ic_os_update_img_sha256(&self) -> Result<String>;
    fn get_malicious_ic_os_update_img_url(&self) -> Result<Url>;
    fn get_malicious_ic_os_update_img_sha256(&self) -> Result<String>;
    fn get_boundary_node_snp_img_url(&self) -> Result<Url>;
    fn get_boundary_node_snp_img_sha256(&self) -> Result<String>;
    fn get_boundary_node_img_url(&self) -> Result<Url>;
    fn get_boundary_node_img_sha256(&self) -> Result<String>;
    fn get_canister_http_test_ca_cert(&self) -> Result<String>;
    fn get_canister_http_test_ca_key(&self) -> Result<String>;
}

impl<T: HasDependencies> HasIcDependencies for T {
    fn get_farm_url(&self) -> Result<Url> {
        let dep_rel_path = "farm_base_url";
        let url = self
            .read_dependency_to_string(dep_rel_path)
            .unwrap_or_else(|_| DEFAULT_FARM_BASE_URL.to_string());
        Ok(Url::parse(&url)?)
    }

    fn get_journalbeat_hosts(&self) -> Result<Vec<String>> {
        let dep_rel_path = "journalbeat_hosts";
        let hosts = self.read_dependency_to_string(dep_rel_path).unwrap_or_else(|_| "elasticsearch-node-0.testnet.dfinity.systems:443,elasticsearch-node-1.testnet.dfinity.systems:443,elasticsearch-node-2.testnet.dfinity.systems:443".to_string());
        parse_journalbeat_hosts(Some(hosts))
    }

    fn get_initial_replica_version(&self) -> Result<ReplicaVersion> {
        let dep_rel_path = "bazel/version.txt";
        let replica_ver = self.read_dependency_to_string(dep_rel_path)?;
        Ok(ReplicaVersion::try_from(replica_ver)?)
    }

    fn get_replica_log_debug_overrides(&self) -> Result<Vec<String>> {
        let dep_rel_path = "replica_log_debug_overrides";
        let log_debug_overrides = self.read_dependency_to_string(dep_rel_path).ok();
        parse_replica_log_debug_overrides(log_debug_overrides)
    }

    fn get_ic_os_img_url(&self) -> Result<Url> {
        let dep_rel_path = "ic-os/guestos/dev/upload_disk-img_disk-img.tar.zst.proxy-cache-url";
        let url = self.read_dependency_to_string(dep_rel_path)?;
        Ok(Url::parse(&url)?)
    }

    fn get_ic_os_img_sha256(&self) -> Result<String> {
        let dep_rel_path = "ic-os/guestos/dev/disk-img.tar.zst.sha256";
        let sha256 = self.read_dependency_to_string(dep_rel_path)?;
        bail_if_sha256_invalid(&sha256, "ic_os_img_sha256")?;
        Ok(sha256)
    }

    fn get_malicious_ic_os_img_url(&self) -> Result<Url> {
        let dep_rel_path =
            "ic-os/guestos/dev-malicious/upload_disk-img_disk-img.tar.zst.proxy-cache-url";
        let url = self.read_dependency_to_string(dep_rel_path)?;
        Ok(Url::parse(&url)?)
    }

    fn get_malicious_ic_os_img_sha256(&self) -> Result<String> {
        let dep_rel_path = "ic-os/guestos/dev-malicious/disk-img.tar.zst.sha256";
        let sha256 = self.read_dependency_to_string(dep_rel_path)?;
        bail_if_sha256_invalid(&sha256, "malicious_ic_os_img_sha256")?;
        Ok(sha256)
    }

    fn get_ic_os_update_img_url(&self) -> Result<Url> {
        let dep_rel_path = "ic-os/guestos/dev/upload_update-img_upgrade.tar.zst.proxy-cache-url";
        let url = self.read_dependency_to_string(dep_rel_path)?;
        Ok(Url::parse(&url)?)
    }

    fn get_ic_os_update_img_sha256(&self) -> Result<String> {
        let dep_rel_path = "ic-os/guestos/dev/upgrade.tar.zst.sha256";
        let sha256 = self.read_dependency_to_string(dep_rel_path)?;
        bail_if_sha256_invalid(&sha256, "ic_os_update_img_sha256")?;
        Ok(sha256)
    }

    fn get_malicious_ic_os_update_img_url(&self) -> Result<Url> {
        let dep_rel_path =
            "ic-os/guestos/dev-malicious/upload_update-img_upgrade.tar.zst.proxy-cache-url";
        let url = self.read_dependency_to_string(dep_rel_path)?;
        Ok(Url::parse(&url)?)
    }

    fn get_malicious_ic_os_update_img_sha256(&self) -> Result<String> {
        let dep_rel_path = "ic-os/guestos/dev-malicious/upgrade.tar.zst.sha256";
        let sha256 = self.read_dependency_to_string(dep_rel_path)?;
        bail_if_sha256_invalid(&sha256, "malicious_ic_os_update_img_sha256")?;
        Ok(sha256)
    }

    fn get_boundary_node_snp_img_url(&self) -> Result<Url> {
        let dep_rel_path = "ic-os/boundary-guestos/boundary_node_snp_img_url";
        let result = self.read_dependency_to_string(dep_rel_path)?;
        Ok(Url::parse(&result)?)
    }

    fn get_boundary_node_snp_img_sha256(&self) -> Result<String> {
        let dep_rel_path = "ic-os/boundary-guestos/boundary_node_snp_img_sha256";
        let sha256 = self.read_dependency_to_string(dep_rel_path)?;
        bail_if_sha256_invalid(&sha256, "boundary_node_snp_img_sha256")?;
        Ok(sha256)
    }

    fn get_boundary_node_img_url(&self) -> Result<Url> {
        let dep_rel_path = "ic-os/boundary-guestos/boundary_node_img_url";
        let url = self.read_dependency_to_string(dep_rel_path)?;
        Ok(Url::parse(&url)?)
    }

    fn get_boundary_node_img_sha256(&self) -> Result<String> {
        let dep_rel_path = "ic-os/boundary-guestos/boundary_node_img_sha256";
        let sha256 = self.read_dependency_to_string(dep_rel_path)?;
        bail_if_sha256_invalid(&sha256, "boundary_node_img_sha256")?;
        Ok(sha256)
    }

    fn get_canister_http_test_ca_cert(&self) -> Result<String> {
        let dep_rel_path = "ic-os/guestos/dev/certs/canister_http_test_ca.cert";
        self.read_dependency_to_string(dep_rel_path)
    }
    fn get_canister_http_test_ca_key(&self) -> Result<String> {
        let dep_rel_path = "ic-os/guestos/dev/certs/canister_http_test_ca.key";
        self.read_dependency_to_string(dep_rel_path)
    }
}

pub trait HasGroupSetup {
    fn ensure_group_setup_created(&self);
}

impl HasGroupSetup for TestEnv {
    fn ensure_group_setup_created(&self) {
        let is_group_setup_existing = self.get_json_path(GroupSetup::attribute_name()).exists();
        // This `if` is executed only for Bazel runs.
        if !is_group_setup_existing {
            let log = self.logger();
            info!(log, "Creating GroupSetup.");
            let group_setup = GroupSetup::from_bazel_env();
            group_setup.write_attribute(self);
            info!(log, "SystemTestGroup.prepare_group");
            let farm_base_url = Url::parse(constants::DEFAULT_FARM_BASE_URL).expect("can't fail");
            let farm = Farm::new(farm_base_url, self.logger());
            let group_spec = GroupSpec {
                vm_allocation: None,
                required_host_features: vec![],
                preferred_network: None,
            };
            farm.create_group(
                &group_setup.farm_group_name,
                group_setup.group_timeout,
                group_spec,
            )
            .unwrap();
        }
    }
}

/// Construct `IcHandle` for backwards compatibility with the older test API.
pub trait IcHandleConstructor {
    fn ic_handle(&self) -> Result<IcHandle>;
}

impl IcHandleConstructor for TestEnv {
    fn ic_handle(&self) -> Result<IcHandle> {
        let pot_setup = GroupSetup::read_attribute(self);
        let farm_base_url = self.get_farm_url()?;
        let ts = self.topology_snapshot();

        let mut nodes = vec![];
        for s in ts.subnets() {
            for n in s.nodes() {
                nodes.push((n, Some(s.clone())));
            }
        }
        for n in ts.unassigned_nodes() {
            nodes.push((n, None));
        }

        let mut public_api_endpoints = vec![];
        let started_at = Instant::now();
        let root_subnet_id = ts
            .local_registry
            .get_root_subnet_id(ts.registry_version)
            .unwrap_result();
        for (n, s) in nodes {
            public_api_endpoints.push(IcEndpoint {
                node_id: n.node_id,
                url: n.get_public_url(),
                metrics_url: n.get_metrics_url(),
                subnet: s.clone().map(|s| IcSubnet {
                    id: s.subnet_id,
                    type_of: s.subnet_type(),
                    canister_ranges: ts.subnet_canister_ranges(s.subnet_id),
                }),
                started_at,
                runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                    group_name: pot_setup.farm_group_name.clone(),
                    vm_name: n.node_id.to_string(),
                    url: farm_base_url.clone(),
                }),
                is_root_subnet: s.map_or(false, |s| s.subnet_id == root_subnet_id),
            });
        }

        let prep_dir = match self.prep_dir("") {
            Some(p) => p,
            None => bail!("No prep dir specified for no-name IC"),
        };
        Ok(IcHandle {
            public_api_endpoints,
            malicious_public_api_endpoints: vec![],
            ic_prep_working_dir: Some(prep_dir),
        })
    }
}

/// All test env objects are associated with the test env itself and thus should
/// implement this trait.
pub trait HasTestEnv {
    /// Returns a TestEnv associated with a given object.
    fn test_env(&self) -> TestEnv;
}

impl HasTestEnv for TestEnv {
    fn test_env(&self) -> TestEnv {
        self.clone()
    }
}

impl HasTestEnv for IcNodeSnapshot {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasTestEnv for SubnetSnapshot {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasTestEnv for TopologySnapshot {
    fn test_env(&self) -> TestEnv {
        self.env.clone()
    }
}

/// Returns the name of the Internet Computer instance that this object is
/// associated with.
///
/// In case of the no-name Internet Computer the empty string is returned.
pub trait HasIcName: HasTestEnv {
    fn ic_name(&self) -> String;
}

impl HasIcName for TopologySnapshot {
    fn ic_name(&self) -> String {
        self.ic_name.clone()
    }
}

impl HasIcName for SubnetSnapshot {
    fn ic_name(&self) -> String {
        self.ic_name.clone()
    }
}

impl HasIcName for IcNodeSnapshot {
    fn ic_name(&self) -> String {
        self.ic_name.clone()
    }
}

pub trait HasDependencies {
    fn get_dependency_path<P: AsRef<Path>>(&self, p: P) -> PathBuf;

    fn read_dependency_to_string<P: AsRef<Path>>(&self, p: P) -> Result<String> {
        let dep_path = self.get_dependency_path(p);
        if dep_path.exists() {
            let result = fs::read_to_string(&dep_path)
                .unwrap_or_else(|e| panic!("Couldn't read content of the {dep_path:?} file: {e:?}"))
                .trim_end()
                .to_string();
            Ok(result)
        } else {
            Err(anyhow!("Couldn't find dependency {dep_path:?}"))
        }
    }
}

impl<T: HasTestEnv> HasDependencies for T {
    fn get_dependency_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        self.test_env().get_path("dependencies").join(p)
    }
}

pub trait HasWasm {
    /// Convenience method that loads a wasm-module from the dependencies
    /// directory.
    ///
    /// # Panics
    ///
    /// * if `get_artifacs(p)` panics.
    /// * if a .wat-module cannot be compiled
    /// * if a .wasm-module does not start with the expected magic bytes
    fn load_wasm<P: AsRef<Path>>(&self, p: P) -> Vec<u8>;
}

impl<T: HasDependencies> HasWasm for T {
    fn load_wasm<P: AsRef<Path>>(&self, p: P) -> Vec<u8> {
        let mut wasm_bytes = std::fs::read(self.get_dependency_path(&p))
            .unwrap_or_else(|_| panic!("Could not read WASM from {:?}", p.as_ref()));

        if p.as_ref().extension().unwrap() == "wat" {
            wasm_bytes = wabt::wat2wasm(wasm_bytes).expect("Could not compile wat to wasm");
        }

        if !wasm_bytes.starts_with(WASM_MAGIC_BYTES) {
            panic!("Invalid magic bytes for wasm module: {:?}", p.as_ref());
        }

        wasm_bytes
    }
}

pub trait SshSession {
    /// Return an SSH session to the machine referenced from self authenticating with the given user.
    fn get_ssh_session(&self, user: &str) -> Result<Session>;

    /// Try a number of times to establish an SSH session to the machine referenced from self authenticating with the given user.
    fn block_on_ssh_session(&self, user: &str) -> Result<Session>;

    fn block_on_bash_script(&self, user: &str, script: &str) -> Result<String> {
        let session = self.block_on_ssh_session(user)?;
        self.block_on_bash_script_from_session(&session, script)
    }

    fn block_on_bash_script_from_session(&self, session: &Session, script: &str) -> Result<String> {
        let mut channel = session.channel_session()?;
        channel.exec("bash").unwrap();

        channel.write_all(script.as_bytes())?;
        channel.flush()?;
        channel.send_eof()?;
        let mut out = String::new();
        channel.read_to_string(&mut out)?;
        if channel.exit_status()? != 0 {
            bail!("block_on_bash_script: exit != 0");
        }
        Ok(out)
    }
}

pub trait RetrieveIpv4Addr {
    /// Try a number of times to retrieve the IPv4 address from the machine referenced from self.
    fn block_on_ipv4(&self) -> Result<Ipv4Addr>;
}

impl HasVmName for IcNodeSnapshot {
    fn vm_name(&self) -> String {
        self.node_id.to_string()
    }
}

pub trait HasVmName {
    /// Returns a name of an associated VM.
    fn vm_name(&self) -> String;
}

pub trait HasMetricsUrl {
    fn get_metrics_url(&self) -> Option<Url>;
}

impl HasMetricsUrl for IcNodeSnapshot {
    fn get_metrics_url(&self) -> Option<Url> {
        let node_record = self.raw_node_record();
        let metrics_endpoint = node_record.prometheus_metrics.first().cloned();
        metrics_endpoint.map(|me| IcNodeSnapshot::http_endpoint_to_url(&me))
    }
}

/// Any entity (boundary node or IC node) that exposes a public API over http
/// implements this trait.
#[async_trait]
pub trait HasPublicApiUrl: HasTestEnv + Send + Sync {
    fn get_public_url(&self) -> Url;

    /// The ip address the domain in `get_public_url` should resolve to
    fn get_public_addr(&self) -> SocketAddr;

    /// Should return `true` to signal that invalid TLS certs will be used
    fn uses_snake_oil_certs(&self) -> bool {
        false
    }

    fn status(&self) -> Result<HttpStatusResponse> {
        let url = self.get_public_url();
        let addr = self.get_public_addr();
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(self.uses_snake_oil_certs())
            .timeout(READY_RESPONSE_TIMEOUT);
        let client = if let Some(domain) = url.domain() {
            client.resolve(domain, addr)
        } else {
            client
        };
        let response = client
            .build()
            .expect("cannot build a reqwest client")
            .get(url.join("api/v2/status").expect("failed to join URLs"))
            .send()?;

        let status = response.status();
        let body = response
            .bytes()
            .expect("failed to convert a response to bytes")
            .to_vec();
        if status.is_client_error() || status.is_server_error() {
            bail!(
                "status check failed with {status}: `{}`",
                String::from_utf8_lossy(&body)
            );
        }

        let cbor_response = serde_cbor::from_slice(&body).expect("response is not encoded as cbor");
        Ok(
            serde_cbor::value::from_value::<HttpStatusResponse>(cbor_response)
                .expect("failed to deserialize a response to HttpStatusResponse"),
        )
    }

    /// The status-endpoint reports `healthy`.
    fn status_is_healthy(&self) -> Result<bool> {
        match self.status() {
            Ok(s) if s.replica_health_status.is_some() => {
                Ok(Some(ReplicaHealthStatus::Healthy) == s.replica_health_status)
            }
            Ok(_) => {
                warn!(
                    self.test_env().logger(),
                    "Health status not set in status response!"
                );
                Ok(false)
            }
            Err(e) => {
                warn!(
                    self.test_env().logger(),
                    "Could not fetch status response: {}", e
                );
                Err(e)
            }
        }
    }

    /// Waits until the is_healthy() returns true
    fn await_status_is_healthy(&self) -> Result<()> {
        retry(
            self.test_env().logger(),
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || {
                self.status_is_healthy()
                    .and_then(|s| if !s { bail!("Not ready!") } else { Ok(()) })
            },
        )
    }

    /// Waits until the is_healthy() returns an error
    fn await_status_is_unavailable(&self) -> Result<()> {
        retry(
            self.test_env().logger(),
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || match self.status_is_healthy() {
                Err(_) => Ok(()),
                Ok(_) => Err(anyhow!("Status is still available")),
            },
        )
    }

    fn build_default_agent(&self) -> Agent {
        let rt = Rt::new().expect("Could not create runtime");
        rt.block_on(async move { self.build_default_agent_async().await })
    }

    fn with_default_agent<F, Fut, R>(&self, op: F) -> R
    where
        F: FnOnce(Agent) -> Fut + 'static,
        Fut: Future<Output = R>,
    {
        let rt = Rt::new().expect("Could not create runtime");
        rt.block_on(async move {
            let agent = self.build_default_agent_async().await;
            op(agent).await
        })
    }

    async fn build_default_agent_async(&self) -> Agent {
        self.try_build_default_agent_async()
            .await
            .expect("Could not create agent")
    }

    async fn try_build_default_agent_async(&self) -> Result<Agent, AgentError>;
}

#[async_trait]
impl HasPublicApiUrl for IcNodeSnapshot {
    fn get_public_url(&self) -> Url {
        let node_record = self.raw_node_record();
        IcNodeSnapshot::http_endpoint_to_url(&node_record.http.expect("Node doesn't have URL"))
    }

    fn get_public_addr(&self) -> SocketAddr {
        let node_record = self.raw_node_record();
        let connection_endpoint = node_record.http.expect("Node doesn't have URL");
        SocketAddr::new(
            IpAddr::from_str(&connection_endpoint.ip_addr).expect("Missing IP address in the node"),
            connection_endpoint.port as u16,
        )
    }

    async fn try_build_default_agent_async(&self) -> Result<Agent, AgentError> {
        let url = self.get_public_url().to_string();
        create_agent(&url).await
    }
}

pub trait NnsInstallationExt {
    /// Installs the NNS canisters on the subnet this node belongs to. The NNS
    /// is installed with test neurons enabled which simplify voting on
    /// proposals in testing.
    fn install_nns_canisters(&self) -> Result<()>;
}

impl<T> NnsInstallationExt for T
where
    T: HasIcName + HasPublicApiUrl,
{
    fn install_nns_canisters(&self) -> Result<()> {
        let test_env = self.test_env();
        test_env.set_nns_canisters_env_vars()?;
        let log = test_env.logger();
        let ic_name = self.ic_name();
        let url = self.get_public_url();
        let prep_dir = match test_env.prep_dir(&ic_name) {
            Some(v) => v,
            None => bail!("Prep Dir for IC {:?} does not exist.", ic_name),
        };
        info!(log, "Wait for node reporting healthy status");
        self.await_status_is_healthy().unwrap();
        install_nns_canisters(&log, url, &prep_dir, true);
        Ok(())
    }
}

pub trait NnsCanisterEnvVars {
    fn set_nns_canisters_env_vars(&self) -> Result<()>;
}

impl NnsCanisterEnvVars for TestEnv {
    fn set_nns_canisters_env_vars(&self) -> Result<()> {
        self.set_canister_env_vars("rs/tests/nns-canisters")
    }
}

pub trait CanisterEnvVars {
    fn set_canister_env_vars<P: AsRef<Path>>(&self, dirname: P) -> Result<()>;
}

impl<T: HasDependencies> CanisterEnvVars for T {
    fn set_canister_env_vars<P: AsRef<Path>>(&self, dirname: P) -> Result<()> {
        let dir = self.get_dependency_path(dirname);
        for entry in (std::fs::read_dir(dir.clone())?).flatten() {
            let file_name = entry.file_name();
            let canister_name = file_name
                .to_str()
                .expect("Couldn't convert file path to canister name!");
            let env_name = format!("{}_WASM_PATH", canister_name)
                .replace('-', "_")
                .to_uppercase();
            let path = std::fs::read_link(dir.join(file_name))?;
            std::env::set_var(env_name, path);
        }
        Ok(())
    }
}

pub trait HasRegistryVersion {
    fn get_registry_version(&self) -> RegistryVersion;
}

impl HasRegistryVersion for TopologySnapshot {
    fn get_registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

impl HasRegistryVersion for SubnetSnapshot {
    fn get_registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

impl HasRegistryVersion for IcNodeSnapshot {
    fn get_registry_version(&self) -> RegistryVersion {
        self.registry_version
    }
}

/// A node container is implemented for structures in the topology that contain
/// nodes.
pub trait IcNodeContainer {
    /// Returns an iterator of IC nodes. Note that, this might include
    /// unassigned nodes if called on [TopologySnapshot], for example.
    fn nodes(&self) -> Box<dyn Iterator<Item = IcNodeSnapshot>>;

    fn await_all_nodes_healthy(&self) -> Result<()>;
}

impl IcNodeContainer for SubnetSnapshot {
    fn nodes(&self) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
        let registry_version = self.registry_version;
        let node_ids = self
            .local_registry
            .get_node_ids_on_subnet(self.subnet_id, registry_version)
            .unwrap_result();

        Box::new(
            node_ids
                .into_iter()
                .map(|node_id| IcNodeSnapshot {
                    node_id,
                    ic_name: self.ic_name.clone(),
                    registry_version,
                    local_registry: self.local_registry.clone(),
                    env: self.env.clone(),
                })
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn await_all_nodes_healthy(&self) -> Result<()> {
        let mut jhs = vec![];
        for node in self.nodes() {
            jhs.push(std::thread::spawn(move || node.await_status_is_healthy()));
        }
        #[allow(clippy::needless_collect)]
        let res: Vec<_> = jhs.into_iter().map(|j| j.join().unwrap()).collect();
        res.into_iter().try_for_each(|x| x)
    }
}

/* ### VM Control ### */

pub trait VmControl {
    fn kill(&self);
    fn reboot(&self);
    fn start(&self);
}

pub struct FarmHostedVm {
    farm: Farm,
    group_name: String,
    vm_name: String,
}

/// VmControl enables a user to interact with VMs, i.e. change their state.
/// All functions belonging to this trait crash if a respective operation is for any reason
/// unsuccessful.
impl VmControl for FarmHostedVm {
    fn kill(&self) {
        self.farm
            .destroy_vm(&self.group_name, &self.vm_name)
            .expect("could not kill VM")
    }

    fn reboot(&self) {
        self.farm
            .reboot_vm(&self.group_name, &self.vm_name)
            .expect("could not reboot VM")
    }

    fn start(&self) {
        self.farm
            .start_vm(&self.group_name, &self.vm_name)
            .expect("could not start VM")
    }
}

pub trait HasVm {
    /// Returns a handle used for controlling a VM, i.e. starting, stopping and rebooting.
    fn vm(&self) -> Box<dyn VmControl>;
}

impl<T> HasVm for T
where
    T: HasTestEnv + HasVmName,
{
    /// Returns a handle used for controlling a VM, i.e. starting, stopping and rebooting.
    fn vm(&self) -> Box<dyn VmControl> {
        let env = self.test_env();
        let pot_setup = GroupSetup::read_attribute(&env);
        let farm_base_url = env.get_farm_url().unwrap();
        let farm = Farm::new(farm_base_url, env.logger());
        Box::new(FarmHostedVm {
            farm,
            group_name: pot_setup.farm_group_name,
            vm_name: self.vm_name(),
        })
    }
}

pub const ADMIN: &str = "admin";
// Name of the network interfaces on the Node.
pub const DEVICE_NAME: &str = "enp1s0";

pub fn get_ssh_session_from_env(env: &TestEnv, user: &str, ip: IpAddr) -> Result<Session> {
    let tcp = TcpStream::connect((ip, 22))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    let priv_key_path = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR).join(user);
    sess.userauth_pubkey_file(user, None, priv_key_path.as_path(), None)?;
    Ok(sess)
}

impl SshSession for IcNodeSnapshot {
    fn get_ssh_session(&self, user: &str) -> Result<Session> {
        let node_record = self.raw_node_record();
        let connection_endpoint = node_record.http.unwrap();
        let ip_addr = IpAddr::from_str(&connection_endpoint.ip_addr)?;
        get_ssh_session_from_env(&self.env, user, ip_addr)
    }

    fn block_on_ssh_session(&self, user: &str) -> Result<Session> {
        retry(self.env.logger(), SSH_RETRY_TIMEOUT, RETRY_BACKOFF, || {
            self.get_ssh_session(user)
        })
    }
}

/* ### Auxiliary functions & helpers ### */

pub fn retry<F, R>(log: slog::Logger, timeout: Duration, backoff: Duration, mut f: F) -> Result<R>
where
    F: FnMut() -> Result<R>,
{
    let mut attempt = 1;
    let start = Instant::now();
    info!(
        log,
        "Retrying for a maximum of {:?} with a linear backoff of {:?}", timeout, backoff
    );
    loop {
        match f() {
            Ok(v) => break Ok(v),
            Err(e) => {
                if start.elapsed() > timeout {
                    let err_msg = e.to_string();
                    break Err(e.context(format!("Timed out! Last error: {}", err_msg)));
                }
                info!(log, "Attempt {} failed. Error: {:?}", attempt, e);
                std::thread::sleep(backoff);
                attempt += 1;
            }
        }
    }
}

pub async fn retry_async<F, Fut, R>(
    log: &slog::Logger,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> Result<R>
where
    Fut: Future<Output = Result<R>>,
    F: Fn() -> Fut,
{
    let mut attempt = 1;
    let start = Instant::now();
    info!(
        log,
        "Retrying for a maximum of {:?} with a linear backoff of {:?}", timeout, backoff
    );
    loop {
        match f().await {
            Ok(v) => break Ok(v),
            Err(e) => {
                if start.elapsed() > timeout {
                    let err_msg = e.to_string();
                    break Err(e.context(format!("Timed out! Last error: {}", err_msg)));
                }
                info!(log, "Attempt {} failed. Error: {:?}", attempt, e);
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

pub fn secs(sec: u64) -> Duration {
    Duration::from_secs(sec)
}

impl<T> RegistryResultHelper<T> for RegistryClientResult<T> {
    fn unwrap_result(self) -> T {
        self.expect("registry error!")
            .expect("registry value not present")
    }
}

trait RegistryResultHelper<T> {
    fn unwrap_result(self) -> T;
}

/// Installs the NNS canisters on the node given by `url` using the initial
/// registry created by `ic-prep`, stored under `registry_local_store`.
pub fn install_nns_canisters(
    logger: &Logger,
    url: Url,
    ic_prep_state_dir: &IcPrepStateDir,
    nns_test_neurons_present: bool,
) {
    let rt = Rt::new().expect("Could not create tokio runtime.");
    info!(
        logger,
        "Compiling/installing NNS canisters (might take a while)."
    );
    rt.block_on(async move {
        let mut init_payloads = NnsInitPayloadsBuilder::new();
        if nns_test_neurons_present {
            let mut ledger_balances = HashMap::new();
            ledger_balances.insert(
                LIFELINE_CANISTER_ID.get().into(),
                Tokens::from_tokens(10000).unwrap(),
            );
            ledger_balances.insert(
                (*TEST_USER1_PRINCIPAL).into(),
                Tokens::from_tokens(200000).unwrap(),
            );
            info!(logger, "Initial ledger: {:?}", ledger_balances);
            let mut ledger_init_payload = LedgerCanisterInitPayload::builder()
                .minting_account(GOVERNANCE_CANISTER_ID.get().into())
                .initial_values(ledger_balances)
                .build()
                .unwrap();
            ledger_init_payload
                .send_whitelist
                .insert(CYCLES_MINTING_CANISTER_ID);
            init_payloads
                .with_test_neurons()
                .with_ledger_init_state(ledger_init_payload);
        }
        let registry_local_store = ic_prep_state_dir.registry_local_store_path();
        let initial_mutations = read_initial_mutations_from_local_store_dir(&registry_local_store);
        init_payloads.with_initial_mutations(initial_mutations);

        let agent = InternalAgent::new(
            url,
            Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
        );
        let runtime = Runtime::Remote(RemoteTestRuntime { agent });

        NnsCanisters::set_up(&runtime, init_payloads.build()).await;
    });
}

/// A short wasm module that is a legal canister binary.
pub(crate) const WASM_MAGIC_BYTES: &[u8] = &[0, 97, 115, 109];

pub fn prepare_group(group_setup: &GroupSetup, logger: Logger) -> Result<()> {
    println!("SystemTestGroup.prepare_group");

    let farm_base_url = Url::parse(constants::DEFAULT_FARM_BASE_URL).expect("can't fail");
    let farm = Farm::new(farm_base_url, logger);

    let group_spec = GroupSpec {
        vm_allocation: None,
        required_host_features: vec![],
        preferred_network: None,
    };

    Ok(farm.create_group(
        &group_setup.farm_group_name,
        group_setup.group_timeout,
        group_spec,
    )?)
}

pub fn finalize_group(group_setup: &GroupSetup, logger: Logger) -> Result<()> {
    println!("SystemTestGroup.finalize_group");

    let farm_base_url = Url::parse(constants::DEFAULT_FARM_BASE_URL).expect("can't fail");
    let farm = Farm::new(farm_base_url, logger);

    Ok(farm.delete_group(&group_setup.farm_group_name)?)
}
