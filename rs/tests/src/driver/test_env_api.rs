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
//!
//! Upcoming: Implementation of VM operations as a separate trait implemented by
//! NodeSnapshot.
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
use crate::util::create_agent;
use anyhow::{bail, Result};
use ic_agent::Agent;
use ic_fondue::ic_manager::handle::READY_RESPONSE_TIMEOUT;
use ic_fondue::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::{node::v1 as pb_node, subnet::v1 as pb_subnet};
use ic_registry_client::local_registry::LocalRegistry;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use ic_types::{NodeId, RegistryVersion, SubnetId};
use slog::{info, warn};
use ssh2::Session;
use std::collections::HashSet;
use std::future::Future;
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{convert::TryFrom, net::IpAddr, str::FromStr, sync::Arc};
use tokio::runtime::Runtime as Rt;
use url::Url;

pub const RETRY_TIMEOUT: Duration = Duration::from_secs(120);
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);

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

pub trait DefaultIC {
    fn topology_snapshot(&self) -> TopologySnapshot;
    fn topology_snapshot_by_name(&self, name: &str) -> TopologySnapshot;
}

impl DefaultIC for TestEnv {
    fn topology_snapshot(&self) -> TopologySnapshot {
        let local_store_path = self
            .prep_dir("")
            .expect("No no name Internet Computer")
            .registry_local_store_path();
        create_topology_snapshot(local_store_path, self.clone())
    }

    fn topology_snapshot_by_name(&self, name: &str) -> TopologySnapshot {
        let local_store_path = self
            .prep_dir(name)
            .unwrap_or_else(|| panic!("No snapshot for internet computer: {:?}", name))
            .registry_local_store_path();
        create_topology_snapshot(local_store_path, self.clone())
    }
}

fn create_topology_snapshot<P: AsRef<Path>>(local_store_path: P, env: TestEnv) -> TopologySnapshot {
    let local_registry = Arc::new(
        LocalRegistry::new(local_store_path, REGISTRY_QUERY_TIMEOUT)
            .expect("Could not create local registry"),
    );
    let registry_version = local_registry.get_latest_version();
    TopologySnapshot {
        local_registry,
        registry_version,
        env,
    }
}

const REGISTRY_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// An immutable snapshot of the Internet Computer topology valid at a
/// particular registry version.
#[derive(Clone)]
pub struct TopologySnapshot {
    registry_version: RegistryVersion,
    local_registry: Arc<LocalRegistry>,
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
                })
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    pub fn root_subnet_id(&self) -> Option<SubnetId> {
        use ic_registry_client_helpers::subnet::SubnetRegistry;
        self.local_registry
            .get_root_subnet_id(self.registry_version)
            .expect("failed to fetch root subnet id from registry")
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
            env: self.env.clone(),
        })
    }
}

#[derive(Clone)]
pub struct SubnetSnapshot {
    pub subnet_id: SubnetId,
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
    pub node_id: NodeId,
    registry_version: RegistryVersion,
    local_registry: Arc<LocalRegistry>,
    env: TestEnv,
}

impl HasTestEnv for IcNodeSnapshot {
    fn env(&self) -> TestEnv {
        self.env.clone()
    }
}

impl HasVmName for IcNodeSnapshot {
    fn vm_name(&self) -> String {
        self.node_id.to_string()
    }
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

pub trait HasTestEnv {
    /// Returns a TestEnv associated with a given object.
    fn env(&self) -> TestEnv;
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

    fn build_default_agent(&self) -> Agent {
        let url = self.get_public_url().to_string();
        let rt = Rt::new().expect("Could not create runtime");
        rt.block_on(async move { create_agent(&url).await.expect("Could not create agent") })
    }
}

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

pub trait HasIpAddr {
    fn get_ip_addr(&self) -> IpAddr;
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

impl<T> RegistryResultHelper<T> for RegistryClientResult<T> {
    fn unwrap_result(self) -> T {
        self.expect("registry error!")
            .expect("registry value not present")
    }
}

trait RegistryResultHelper<T> {
    fn unwrap_result(self) -> T;
}

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

pub trait HttpFileStore {
    fn upload(&self, path: PathBuf) -> anyhow::Result<Box<dyn HttpFileHandle>>;
}

pub trait HttpFileHandle {
    fn download(&self, sink: Box<dyn std::io::Write>) -> anyhow::Result<()>;
    fn url(&self) -> Url;
}

pub struct FarmFileHandle {
    farm: Farm,
    url: Url,
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

pub struct FarmFileStore {
    farm: Farm,
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
        let env = self.env();
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

pub trait SshSession {
    /// Return an SSH session to the machine referenced from self authenticating with the given user.
    fn get_ssh_session(&self, user: &str) -> Result<Session>;

    /// Try a number of times to establish an SSH session to the machine referenced from self authenticating with the given user.
    fn block_on_ssh_session(&self, user: &str) -> Result<Session>;
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

pub trait RetrieveIpv4Addr {
    /// Try a number of times to retrieve the IPv4 address from the machine referenced from self.  
    fn block_on_ipv4(&self) -> Result<Ipv4Addr>;
}
