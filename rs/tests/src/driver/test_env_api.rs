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
use super::driver_setup::{IcSetup, SSH_AUTHORIZED_PRIV_KEYS_DIR};
use super::test_setup::PotSetup;
use crate::driver::farm::Farm;
use crate::driver::test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute};
use crate::util::{create_agent, delay};
use anyhow::{bail, Result};
use canister_test::{RemoteTestRuntime, Runtime};
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_canister_client::Agent as InternalAgent;
use ic_canister_client::Sender;
use ic_fondue::ic_manager::handle::READY_RESPONSE_TIMEOUT;
use ic_fondue::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID};
use ic_nns_init::read_initial_mutations_from_local_store_dir;
use ic_nns_test_keys::TEST_USER1_PRINCIPAL;
use ic_nns_test_utils::itest_helpers::{NnsCanisters, NnsInitPayloadsBuilder};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_protobuf::registry::{node::v1 as pb_node, subnet::v1 as pb_subnet};
use ic_registry_client::local_registry::LocalRegistry;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use ic_types::{NodeId, RegistryVersion, SubnetId};
use ic_utils::interfaces::ManagementCanister;
use ledger_canister::{LedgerCanisterInitPayload, Tokens};
use slog::{info, warn, Logger};
use ssh2::Session;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{convert::TryFrom, net::IpAddr, str::FromStr, sync::Arc};
use tokio::runtime::Runtime as Rt;
use url::Url;

pub const RETRY_TIMEOUT: Duration = Duration::from_secs(120);
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);
const REGISTRY_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

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
        use ic_registry_client_helpers::subnet::SubnetListRegistry;
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

    pub fn unassigned_nodes(&self) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
        use ic_registry_client_helpers::subnet::{SubnetListRegistry, SubnetRegistry};

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
        use ic_registry_client_helpers::subnet::SubnetRegistry;
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
    pub fn block_for_newer_registry_version(&self) -> Result<TopologySnapshot> {
        let minimum_version = self.local_registry.get_latest_version() + RegistryVersion::from(1);
        self.block_for_min_registry_version(minimum_version)
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
    pub fn block_for_min_registry_version(
        &self,
        min_version: RegistryVersion,
    ) -> Result<TopologySnapshot> {
        let duration = Duration::from_secs(180);
        let backoff = Duration::from_secs(2);
        let mut latest_version = self.local_registry.get_latest_version();
        if min_version > latest_version {
            latest_version = retry(self.env.logger(), duration, backoff, || {
                self.local_registry.sync_with_nns()?;
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
            })?;
        }
        Ok(Self {
            registry_version: latest_version,
            local_registry: self.local_registry.clone(),
            ic_name: "".to_string(),
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
        use ic_registry_client_helpers::subnet::SubnetRegistry;

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

/// Construct `IcHandle` for backwards compatibility with the older test API.
pub trait IcHandleConstructor {
    fn ic_handle(&self) -> Result<IcHandle>;
}

impl IcHandleConstructor for TestEnv {
    fn ic_handle(&self) -> Result<IcHandle> {
        use ic_registry_client_helpers::subnet::SubnetRegistry;
        let pot_setup = PotSetup::read_attribute(self);
        let ic_setup = IcSetup::read_attribute(self);
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
                }),
                started_at,
                runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                    group_name: pot_setup.farm_group_name.clone(),
                    vm_name: n.node_id.to_string(),
                    url: ic_setup.farm_base_url.clone(),
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

pub trait HasArtifacts {
    /// Returns the path to an artifact named `p` that is situated relative to a
    /// global directory containing artifacts that were provided to the test
    /// driver. Note that the directory is possibly shared and should be
    /// treated as *read only*.
    ///
    /// # Panics
    ///
    /// This method panics if ...
    ///
    /// * ... the driver was not provided with a path to an artifacts directory.
    /// * ... the given path is not relative.
    /// * ... the given path does not point to a file.
    fn get_artifact_path<P: AsRef<Path>>(&self, p: P) -> PathBuf;

    /// Returns the content of an artifact named `p` that is situated relative
    /// to a global directory containing artifacts that were provided to the
    /// test driver. Note that the directory is possibly shared and should be
    /// treated as *read only*.
    ///
    /// # Panics
    ///
    /// This method panics if ...
    ///
    /// * ... the driver was not provided with a path to an artifacts directory.
    /// * ... the given path is not relative.
    /// * ... the given path does not point to a file.
    /// * ... an I/O-Error occurred when reading the file.
    fn get_artifact<P: AsRef<Path>>(&self, p: P) -> Vec<u8>;

    /// Convenience method that loads a wasm-module from the artifacts
    /// directory.
    ///
    /// # Panics
    ///
    /// * if `get_artifacs(p)` panics.
    /// * if a .wat-module cannot be compiled
    /// * if a .wasm-module does not start with the expected magic bytes
    fn load_wasm<P: AsRef<Path>>(&self, p: P) -> Vec<u8> {
        let mut wasm_bytes = self.get_artifact(&p);

        if p.as_ref().extension().unwrap() == "wat" {
            wasm_bytes = wabt::wat2wasm(wasm_bytes).expect("Could not compile wat to wasm");
        }

        if !wasm_bytes.starts_with(WASM_MAGIC_BYTES) {
            panic!("Invalid magic bytes for wasm module: {:?}", p.as_ref());
        }

        wasm_bytes
    }
}

impl<T> HasArtifacts for T
where
    T: HasTestEnv,
{
    fn get_artifact_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        let artifact_path = PotSetup::read_attribute(&self.test_env())
            .artifact_path
            .expect("Artifact path is not set.");
        artifact_path.join(p)
    }

    fn get_artifact<P: AsRef<Path>>(&self, p: P) -> Vec<u8> {
        std::fs::read(self.get_artifact_path(p)).expect("Could not read artifact")
    }
}

pub trait SshSession {
    /// Return an SSH session to the machine referenced from self authenticating with the given user.
    fn get_ssh_session(&self, user: &str) -> Result<Session>;

    /// Try a number of times to establish an SSH session to the machine referenced from self authenticating with the given user.
    fn block_on_ssh_session(&self, user: &str) -> Result<Session>;
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
pub trait HasPublicApiUrl {
    fn get_public_url(&self) -> Url;

    fn status(&self) -> Result<HttpStatusResponse>;

    /// The status-endpoint reports `healthy`.
    fn status_is_healthy(&self) -> Result<bool>;

    /// Waits until the is_healthy() returns true
    fn await_status_is_healthy(&self) -> Result<()>;

    fn with_default_agent<F, Fut, R>(&self, op: F) -> R
    where
        F: FnOnce(Agent) -> Fut + 'static,
        Fut: Future<Output = R>;

    /// Load wasm binary from the artifacts directory (see [HasArtifacts]) and
    /// install it on the target node.
    ///
    /// # Panics
    ///
    /// This function panics if the canister `name` could not be loaded, is not
    /// a wasm module or the installation fails.
    fn create_and_install_canister_with_arg(&self, name: &str, arg: Option<Vec<u8>>) -> Principal;

    fn build_default_agent(&self) -> Agent;
}

impl HasPublicApiUrl for IcNodeSnapshot {
    fn get_public_url(&self) -> Url {
        let node_record = self.raw_node_record();
        IcNodeSnapshot::http_endpoint_to_url(&node_record.http.unwrap())
    }

    fn status(&self) -> Result<HttpStatusResponse> {
        let response = reqwest::blocking::Client::builder()
            .timeout(READY_RESPONSE_TIMEOUT)
            .build()
            .expect("cannot build a reqwest client")
            .get(
                self.get_public_url()
                    .join("api/v2/status")
                    .expect("failed to join URLs"),
            )
            .send()?;

        let cbor_response = serde_cbor::from_slice(
            &response
                .bytes()
                .expect("failed to convert a response to bytes")
                .to_vec(),
        )
        .expect("response is not encoded as cbor");
        Ok(
            serde_cbor::value::from_value::<HttpStatusResponse>(cbor_response)
                .expect("failed to deserialize a response to HttpStatusResponse"),
        )
    }

    fn status_is_healthy(&self) -> Result<bool> {
        match self.status() {
            Ok(s) if s.replica_health_status.is_some() => {
                Ok(Some(ReplicaHealthStatus::Healthy) == s.replica_health_status)
            }
            Ok(_) => {
                warn!(
                    self.env.logger(),
                    "Health status not set in status response!"
                );
                Ok(false)
            }
            Err(e) => {
                warn!(self.env.logger(), "Could not fetch status response: {}", e);
                Err(e)
            }
        }
    }

    fn await_status_is_healthy(&self) -> Result<()> {
        retry(self.env.logger(), RETRY_TIMEOUT, RETRY_BACKOFF, || {
            self.status_is_healthy()
                .and_then(|s| if !s { bail!("Not ready!") } else { Ok(()) })
        })
    }

    fn with_default_agent<F, Fut, R>(&self, op: F) -> R
    where
        F: FnOnce(Agent) -> Fut + 'static,
        Fut: Future<Output = R>,
    {
        let url = self.get_public_url().to_string();
        let rt = Rt::new().expect("Could not create runtime");
        rt.block_on(async move {
            let agent = create_agent(&url).await.expect("Could not create agent");
            op(agent).await
        })
    }

    fn create_and_install_canister_with_arg(&self, name: &str, arg: Option<Vec<u8>>) -> Principal {
        let canister_bytes = self.test_env().load_wasm(name);

        self.with_default_agent(|agent| async move {
            // Create a canister.
            let mgr = ManagementCanister::create(&agent);
            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
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

    fn build_default_agent(&self) -> Agent {
        let url = self.get_public_url().to_string();
        let rt = Rt::new().expect("Could not create runtime");
        rt.block_on(async move { create_agent(&url).await.expect("Could not create agent") })
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
        let log = test_env.logger();
        let ic_name = self.ic_name();
        let url = self.get_public_url();
        let prep_dir = match test_env.prep_dir(&ic_name) {
            Some(v) => v,
            None => bail!("Prep Dir for IC {:?} does not exist.", ic_name),
        };
        install_nns_canisters(&log, url, &prep_dir, true);
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
        use ic_registry_client_helpers::subnet::SubnetRegistry;

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

/* ### HTTP File Store API ### */
pub trait HasHttpFileStore {
    fn http_file_store(&self) -> Box<dyn HttpFileStore>;
}

impl HasHttpFileStore for TestEnv {
    fn http_file_store(&self) -> Box<dyn HttpFileStore> {
        let ic_setup = IcSetup::read_attribute(self);
        let farm = Farm::new(ic_setup.farm_base_url, self.logger());
        Box::new(FarmFileStore { farm })
    }
}

pub struct FarmFileStore {
    farm: Farm,
}

pub trait HttpFileStore {
    fn upload(&self, path: PathBuf) -> anyhow::Result<Box<dyn HttpFileHandle>>;
}

impl HttpFileStore for FarmFileStore {
    fn upload(&self, path: PathBuf) -> anyhow::Result<Box<dyn HttpFileHandle>> {
        let name = path
            .file_name()
            .expect("cannot fetch file_name")
            .to_str()
            .expect("cannot convert file_name to str");
        let id = self.farm.upload_file(&path, name)?;
        Ok(Box::new(FarmFileHandle {
            farm: self.farm.clone(),
            url: self
                .farm
                .base_url
                .join(&format!("file/{}", id))
                .expect("cannot join urls"),
        }))
    }
}

pub struct FarmFileHandle {
    farm: Farm,
    url: Url,
}

pub trait HttpFileHandle {
    fn download(&self, sink: Box<dyn std::io::Write>) -> anyhow::Result<()>;
    fn url(&self) -> Url;
}

impl HttpFileHandle for FarmFileHandle {
    fn download(&self, sink: Box<dyn std::io::Write>) -> anyhow::Result<()> {
        self.farm.download_file(self.url.clone(), sink)?;
        Ok(())
    }
    fn url(&self) -> Url {
        self.url.clone()
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
        let pot_setup = PotSetup::read_attribute(&env);
        let ic_setup = IcSetup::read_attribute(&env);
        let farm = Farm::new(ic_setup.farm_base_url, env.logger.clone());
        Box::new(FarmHostedVm {
            farm,
            group_name: pot_setup.farm_group_name,
            vm_name: self.vm_name(),
        })
    }
}

pub const ADMIN: &str = "admin";

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
        retry(self.env.logger(), RETRY_TIMEOUT, RETRY_BACKOFF, || {
            self.get_ssh_session(user)
        })
    }
}

/* ### Auxiliary functions & helpers ### */

pub fn retry<F, R>(log: slog::Logger, timeout: Duration, backoff: Duration, f: F) -> Result<R>
where
    F: Fn() -> Result<R>,
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
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
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
