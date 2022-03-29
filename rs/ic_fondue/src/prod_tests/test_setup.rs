use crate::ic_manager::handle::READY_RESPONSE_TIMEOUT;
use crate::ic_manager::{FarmInfo, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
use crate::prod_tests::cli::AuthorizedSshAccount;
use crate::prod_tests::driver_setup::{AUTHORIZED_SSH_ACCOUNTS, FARM_BASE_URL, FARM_GROUP_NAME};
use crate::prod_tests::test_env::TestEnv;
use anyhow::{bail, Result};
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_protobuf::registry::{node::v1 as pb_node, subnet::v1 as pb_subnet};
use ic_registry_client::local_registry::LocalRegistry;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use ic_types::{NodeId, RegistryVersion, SubnetId};
use slog::{info, warn};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use std::{convert::TryFrom, net::IpAddr, str::FromStr, sync::Arc};
use url::Url;

pub const RETRY_TIMEOUT: Duration = Duration::from_secs(120);
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);

pub trait IcHandleConstructor {
    fn ic_handle(&self) -> Result<IcHandle>;
}

impl IcHandleConstructor for TestEnv {
    fn ic_handle(&self) -> Result<IcHandle> {
        use ic_registry_client_helpers::subnet::SubnetRegistry;
        let group_name: String = self.read_object(FARM_GROUP_NAME)?;
        let farm_url: Url = self.read_object(FARM_BASE_URL)?;
        let ssh_key_pairs: Vec<AuthorizedSshAccount> = self.read_object(AUTHORIZED_SSH_ACCOUNTS)?;
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
                ssh_key_pairs: ssh_key_pairs.clone(),
                runtime_descriptor: RuntimeDescriptor::Vm(FarmInfo {
                    group_name: group_name.clone(),
                    vm_name: n.node_id.to_string(),
                    url: farm_url.clone(),
                }),
                is_root_subnet: s.map_or(false, |s| s.subnet_id == root_subnet_id),
            });
        }
        Ok(IcHandle {
            public_api_endpoints,
            malicious_public_api_endpoints: vec![],
            ic_prep_working_dir: Some(IcPrepStateDir {
                prep_dir: self.base_path(),
            }),
        })
    }
}

pub trait DefaultIC {
    fn topology_snapshot(&self) -> TopologySnapshot;
}

impl DefaultIC for TestEnv {
    fn topology_snapshot(&self) -> TopologySnapshot {
        let local_store_path = self.get_path("ic_registry_local_store");
        let local_registry = Arc::new(
            LocalRegistry::new(local_store_path, REGISTRY_QUERY_TIMEOUT)
                .expect("Could not create local registry"),
        );
        let registry_version = local_registry.get_latest_version();
        TopologySnapshot {
            local_registry,
            registry_version,
            env: self.clone(),
        }
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
}

#[derive(Clone)]
pub struct SubnetSnapshot {
    subnet_id: SubnetId,
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
    node_id: NodeId,
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

/// A node container is implemented for structures in the topology that contain
/// nodes.
pub trait IcNodeContainer {
    /// Returns an iterator of IC nodes. Note that, this might include
    /// unassigned nodes if called on [TopologySnapshot], for example.
    fn nodes(&self) -> Box<dyn Iterator<Item = IcNodeSnapshot>>;
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
