#![allow(clippy::disallowed_types)]
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
//!     let ucan = UniversalCanister::new_with_retries(&agent, effective_canister_id, &logger).await;
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

use super::{
    config::NODES_INFO,
    driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR,
    farm::{DnsRecord, PlaynetCertificate},
    test_setup::{GroupSetup, InfraProvider},
};
use crate::{
    driver::{
        boundary_node::BoundaryNodeVm,
        constants::{self, kibana_link, GROUP_TTL, SSH_USERNAME},
        farm::{Farm, GroupSpec},
        log_events,
        test_env::{HasIcPrepDir, SshKeyGen, TestEnv, TestEnvAttribute},
    },
    k8s::{
        tnet::TNet,
        virtualmachine::{destroy_vm, restart_vm, start_vm},
    },
    retry_with_msg, retry_with_msg_async,
    util::{block_on, create_agent},
};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use canister_test::{RemoteTestRuntime, Runtime};
use ic_agent::{export::Principal, Agent, AgentError};
use ic_base_types::PrincipalId;
use ic_canister_client::{Agent as InternalAgent, Sender};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::Neuron;
use ic_nns_init::read_initial_mutations_from_local_store_dir;
use ic_nns_test_utils::{common::NnsInitPayloadsBuilder, itest_helpers::NnsCanisters};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_protobuf::registry::{
    node::v1 as pb_node,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    subnet::v1 as pb_subnet,
};
use ic_registry_client_helpers::{
    api_boundary_node::ApiBoundaryNodeRegistry,
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_keys::REPLICA_VERSION_KEY_PREFIX;
use ic_registry_local_registry::LocalRegistry;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    malicious_behaviour::MaliciousBehaviour,
    messages::{HttpStatusResponse, ReplicaHealthStatus},
    NodeId, RegistryVersion, ReplicaVersion, SubnetId,
};
use ic_utils::interfaces::ManagementCanister;
use icp_ledger::{AccountIdentifier, LedgerCanisterInitPayload, Tokens};
use itertools::Itertools;
use prost::Message;
use regex::Regex;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, warn, Logger};
use ssh2::Session;
use std::{
    cmp::max,
    collections::{HashMap, HashSet},
    convert::TryFrom,
    ffi::OsStr,
    fs,
    future::Future,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{runtime::Runtime as Rt, sync::Mutex as TokioMutex};
use url::Url;

pub const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(500);
pub const SSH_RETRY_TIMEOUT: Duration = Duration::from_secs(500);
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);
const REGISTRY_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(6);
// It usually takes below 60 secs to install nns canisters.
const NNS_CANISTER_INSTALL_TIMEOUT: Duration = std::time::Duration::from_secs(160);
// Be mindful when modifying this constant, as the event can be consumed by other parties.
const IC_TOPOLOGY_EVENT_NAME: &str = "ic_topology_created_event";
const INFRA_GROUP_CREATED_EVENT_NAME: &str = "infra_group_name_created_event";
const KIBANA_URL_CREATED_EVENT_NAME: &str = "kibana_url_created_event";
pub type NodesInfo = HashMap<NodeId, Option<MaliciousBehaviour>>;

pub fn bail_if_sha256_invalid(sha256: &str, opt_name: &str) -> Result<()> {
    let l = sha256.len();
    if !(l == 64 && sha256.chars().all(|c| c.is_ascii_hexdigit())) {
        bail!("option '{}': invalid sha256 value: {:?}", opt_name, sha256);
    }
    Ok(())
}

/// Checks whether the input string as the form [hostname:port{,hostname:port}]
pub fn parse_elasticsearch_hosts(s: Option<String>) -> Result<Vec<String>> {
    const HOST_START: &str = r"^(([[:alnum:]]|[[:alnum:]][[:alnum:]\-]*[[:alnum:]])\.)*";
    const HOST_STOP: &str = r"([[:alnum:]]|[[:alnum:]][[:alnum:]\-]*[[:alnum:]])";
    const PORT: &str = r#":[[:digit:]]{2,5}$"#;
    let s = match s {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    let rgx = format!("{}{}{}", HOST_START, HOST_STOP, PORT);
    let rgx = Regex::new(&rgx).unwrap();
    let mut res = vec![];
    for target in s.trim().split(',') {
        if !rgx.is_match(target) {
            bail!("Invalid filebeat host: '{}'", s);
        }
        res.push(target.to_string());
    }
    Ok(res)
}

/// An immutable snapshot of the Internet Computer topology valid at a
/// particular registry version.
#[derive(Clone)]
pub struct TopologySnapshot {
    registry_version: RegistryVersion,
    local_registry: Arc<LocalRegistry>,
    ic_name: String,
    env: TestEnv,
}

impl std::fmt::Display for TopologySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "\n============================================== IC TopologySnapshot, registry version {} ==============================================",
            self.registry_version
        )
        .unwrap();
        let max_length_ipv6: usize = max(
            self.subnets()
                .flat_map(|s| s.nodes())
                .map(|n| n.get_ip_addr().to_string().len())
                .max()
                .unwrap_or(0),
            self.unassigned_nodes()
                .map(|s| s.get_ip_addr().to_string().len())
                .max()
                .unwrap_or(0),
        );
        self.subnets().enumerate().for_each(|(idx, s)| {
            writeln!(
                f,
                "Subnet id={}, index={}, type={:?}",
                s.subnet_id,
                idx,
                s.subnet_type(),
            )
            .unwrap();
            s.nodes().enumerate().for_each(|(idx, n)| {
                writeln!(
                    f,
                    "\tNode id={}, ipv6={:<width$}, index={}",
                    n.node_id,
                    n.get_ip_addr(),
                    idx,
                    width = max_length_ipv6,
                )
                .unwrap();
            });
        });
        if self.api_boundary_nodes().count() > 0 {
            writeln!(f, "API boundary nodes:").unwrap();
        }
        self.api_boundary_nodes().enumerate().for_each(|(idx, n)| {
            writeln!(
                f,
                "\tNode id={}, ipv6={:<width$}, domain_name={}, index={}",
                n.node_id,
                n.get_ip_addr(),
                n.get_domain().map_or("n/a".to_string(), |domain| domain),
                idx,
                width = max_length_ipv6,
            )
            .unwrap()
        });
        if self.unassigned_nodes().count() > 0 {
            writeln!(f, "Unassigned nodes:").unwrap();
        }
        self.unassigned_nodes().enumerate().for_each(|(idx, n)| {
            writeln!(
                f,
                "\tNode id={}, ipv6={:<width$}, index={}",
                n.node_id,
                n.get_ip_addr(),
                idx,
                width = max_length_ipv6,
            )
            .unwrap()
        });
        writeln!(
            f,
            "====================================================================================================================================="
        )
        .unwrap();
        Ok(())
    }
}

impl TopologySnapshot {
    pub fn emit_log_event(&self, log: &slog::Logger) {
        #[derive(Deserialize, Serialize)]
        pub struct NodeView {
            pub id: NodeId,
            pub ipv6: IpAddr,
            pub domain: Option<String>,
        }

        #[derive(Deserialize, Serialize)]
        pub struct SubnetView {
            pub subnet_type: SubnetType,
            pub subnet_id: SubnetId,
            pub nodes: Vec<NodeView>,
        }

        #[derive(Deserialize, Serialize)]
        pub struct TopologyView {
            pub registry_version: String,
            pub subnets: Vec<SubnetView>,
            pub unassigned_nodes: Vec<NodeView>,
            pub api_boundary_nodes: Vec<NodeView>,
        }
        let subnets: Vec<_> = self
            .subnets()
            .map(|s| {
                let nodes: Vec<_> = s
                    .nodes()
                    .map(|n| NodeView {
                        id: n.node_id,
                        ipv6: n.get_ip_addr(),
                        domain: n.get_domain(),
                    })
                    .collect();
                SubnetView {
                    subnet_type: s.subnet_type(),
                    subnet_id: s.subnet_id,
                    nodes,
                }
            })
            .collect();
        let unassigned_nodes: Vec<_> = self
            .unassigned_nodes()
            .map(|n| NodeView {
                id: n.node_id,
                ipv6: n.get_ip_addr(),
                domain: n.get_domain(),
            })
            .collect();
        let api_boundary_nodes: Vec<_> = self
            .api_boundary_nodes()
            .map(|n| NodeView {
                id: n.node_id,
                ipv6: n.get_ip_addr(),
                domain: n.get_domain(),
            })
            .collect();
        let event = log_events::LogEvent::new(
            IC_TOPOLOGY_EVENT_NAME.to_string(),
            TopologyView {
                registry_version: self.registry_version.to_string(),
                subnets,
                unassigned_nodes,
                api_boundary_nodes,
            },
        );
        event.emit_log(log);
    }

    pub fn subnets(&self) -> Box<dyn Iterator<Item = SubnetSnapshot>> {
        let registry_version = self.local_registry.get_latest_version();
        Box::new(
            self.local_registry
                .get_subnet_ids(registry_version)
                .unwrap_result(registry_version, "subnet_ids")
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
            .unwrap_result(registry_version, "subnet_ids")
            .into_iter()
            .flat_map(|subnet_id| {
                self.local_registry
                    .get_node_ids_on_subnet(subnet_id, registry_version)
                    .unwrap_result(
                        registry_version,
                        &format!("node_ids_on_subnet(subnet_id={})", subnet_id),
                    )
            })
            .collect();

        let api_boundary_nodes = self
            .local_registry
            .get_api_boundary_node_ids(registry_version)
            .unwrap();

        Box::new(
            self.local_registry
                .get_node_ids(registry_version)
                .unwrap()
                .into_iter()
                .filter(|node_id| {
                    !assigned_nodes.contains(node_id) && !api_boundary_nodes.contains(node_id)
                })
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

    pub fn api_boundary_nodes(&self) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
        let registry_version = self.local_registry.get_latest_version();

        Box::new(
            self.local_registry
                .get_api_boundary_node_ids(registry_version)
                .unwrap()
                .into_iter()
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

    pub fn elected_replica_versions(&self) -> anyhow::Result<Vec<String>> {
        Ok(self
            .local_registry
            .get_key_family(
                "blessed_replica_versions",
                self.local_registry.get_latest_version(),
            )
            .map_err(anyhow::Error::from)?
            .iter()
            .filter_map(|key| {
                let r = self
                    .local_registry
                    .get_versioned_value(key, self.local_registry.get_latest_version())
                    .unwrap_or_else(|_| {
                        panic!("Failed to get entry {} for blessed replica versions", key)
                    });

                r.as_ref().map(|v| {
                    BlessedReplicaVersions::decode(v.as_slice()).expect("Invalid registry value")
                })
            })
            .collect_vec()
            .first()
            .ok_or(anyhow::anyhow!(
                "Failed to find any blessed replica versions"
            ))?
            .blessed_version_ids
            .clone())
    }

    pub fn replica_version_records(&self) -> anyhow::Result<Vec<(String, ReplicaVersionRecord)>> {
        Ok(self
            .local_registry
            .get_key_family(
                REPLICA_VERSION_KEY_PREFIX,
                self.local_registry.get_latest_version(),
            )
            .map_err(anyhow::Error::from)?
            .iter()
            .map(|key| {
                let r = self
                    .local_registry
                    .get_versioned_value(key, self.local_registry.get_latest_version())
                    .unwrap_or_else(|_| panic!("Failed to get entry for replica version {}", key));
                (
                    key[REPLICA_VERSION_KEY_PREFIX.len()..].to_string(),
                    r.as_ref()
                        .map(|v| {
                            ReplicaVersionRecord::decode(v.as_slice())
                                .expect("Invalid registry value")
                        })
                        .unwrap(),
                )
            })
            .collect_vec())
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
        let result = self.block_for_min_registry_version(minimum_version).await;
        if let Ok(ref topology) = result {
            info!(self.env.logger(), "{}", topology);
        }
        result
    }

    /// Like `block_for_newer_registry_version` but with a custom `duration` and `backoff`.
    pub async fn block_for_newer_registry_version_within_duration(
        &self,
        duration: Duration,
        backoff: Duration,
    ) -> Result<TopologySnapshot> {
        let minimum_version = self.local_registry.get_latest_version() + RegistryVersion::from(1);
        let result = self
            .block_for_min_registry_version_within_duration(minimum_version, duration, backoff)
            .await;
        if let Ok(ref topology) = result {
            info!(self.env.logger(), "{}", topology);
        }
        result
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
        self.block_for_min_registry_version_within_duration(min_version, duration, backoff)
            .await
    }

    /// Like `block_for_min_registry_version` but with a custom `duration` and `backoff`.
    pub async fn block_for_min_registry_version_within_duration(
        &self,
        min_version: RegistryVersion,
        duration: Duration,
        backoff: Duration,
    ) -> Result<TopologySnapshot> {
        let mut latest_version = self.local_registry.get_latest_version();
        if min_version > latest_version {
            latest_version = retry_with_msg_async!(
                format!(
                    "check if latest registry version >= {}",
                    min_version.to_string()
                ),
                &self.env.logger(),
                duration,
                backoff,
                || async move {
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
                }
            )
            .await?;
        }
        Ok(Self {
            registry_version: latest_version,
            local_registry: self.local_registry.clone(),
            ic_name: self.ic_name.clone(),
            env: self.env.clone(),
        })
    }

    /// This method blocks and repeatedly fetches updates from the registry
    /// canister until the latest (locally) available registry version
    /// matches the (globally) latest registry version from the NNS.
    ///
    /// This globally newest registry version is the registry version of the
    /// returned snapshot.
    ///
    /// # Known Limitations
    ///
    /// As the test driver does not implement timeouts on the test level, this
    /// method blocks for a duration of 720 seconds at maximum.
    pub async fn block_for_newest_mainnet_registry_version(&self) -> Result<TopologySnapshot> {
        let duration = Duration::from_secs(720);
        let backoff = Duration::from_secs(2);
        let prev_version: Arc<TokioMutex<RegistryVersion>> =
            Arc::new(TokioMutex::new(self.local_registry.get_latest_version()));
        let version = retry_with_msg_async!(
            "block_for_newest_mainnet_registry_version",
            &self.env.logger(),
            duration,
            backoff,
            || {
                let prev_version = prev_version.clone();
                async move {
                    let mut prev_version = prev_version.lock().await;
                    self.local_registry.sync_with_nns().await?;
                    let version = self.local_registry.get_latest_version();
                    info!(
                        &self.env.logger(),
                        "previous registry version: {}; obtained from NNS: {}",
                        prev_version,
                        version.clone()
                    );
                    if version == *prev_version {
                        info!(
                            &self.env.logger(),
                            "registry version obtained from NNS saturated at {}",
                            version.clone()
                        );
                        Ok(version)
                    } else {
                        *prev_version = version;
                        bail!(
                            "latest registry version obtained from NNS: {}; saturating ...",
                            version
                        )
                    }
                }
            }
        )
        .await?;
        Ok(Self {
            registry_version: version,
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

    pub fn subnet_canister_ranges(&self) -> Vec<CanisterIdRange> {
        self.local_registry
            .get_subnet_canister_ranges(self.registry_version, self.subnet_id)
            .expect("Could not deserialize optional routing table from local registry.")
            .expect("Optional routing table is None in local registry.")
    }

    pub fn raw_subnet_record(&self) -> pb_subnet::SubnetRecord {
        self.local_registry
            .get_subnet_record(self.subnet_id, self.registry_version)
            .unwrap_result(
                self.registry_version,
                &format!("subnet_record(subnet_id={})", self.subnet_id),
            )
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
            .get_node_record(self.node_id, self.registry_version)
            .unwrap_result(
                self.registry_version,
                &format!("node_record(node_id={})", self.node_id),
            )
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

    pub fn get_ipv4_configuration(&self) -> Option<pb_node::IPv4InterfaceConfig> {
        let node_record = self.raw_node_record();
        node_record.public_ipv4_config
    }

    pub fn get_domain(&self) -> Option<String> {
        let node_record = self.raw_node_record();
        node_record.domain
    }

    /// Is it accessible via ssh with the `admin` user.
    /// Waits until connection is ready.
    pub fn await_can_login_as_admin_via_ssh(&self) -> Result<()> {
        let sess = self.block_on_ssh_session()?;
        let mut channel = sess.channel_session()?;
        channel.exec("echo ready")?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        if s.trim() == "ready" {
            Ok(())
        } else {
            bail!("Failed receive from ssh session")
        }
    }

    pub fn subnet_id(&self) -> Option<SubnetId> {
        let registry_version = self.registry_version;
        self.local_registry
            .get_subnet_ids(registry_version)
            .unwrap_result(registry_version, "subnet_ids")
            .into_iter()
            .find(|subnet_id| {
                self.local_registry
                    .get_node_ids_on_subnet(*subnet_id, registry_version)
                    .unwrap_result(
                        registry_version,
                        &format!("node_ids_on_subnet(subnet_id={})", subnet_id),
                    )
                    .contains(&self.node_id)
            })
    }

    pub fn effective_canister_id(&self) -> PrincipalId {
        match self.subnet_id() {
            Some(subnet_id) => {
                let canister_ranges = self
                    .local_registry
                    .get_subnet_canister_ranges(self.registry_version, subnet_id)
                    .expect("Could not deserialize optional routing table from local registry.")
                    .expect("Optional routing table is None in local registry.");
                match canister_ranges.first() {
                    Some(range) => range.start.get(),
                    None => {
                        warn!(
                            self.env.logger(),
                            "No canister ranges found for subnet_id={}", subnet_id
                        );
                        PrincipalId::default()
                    }
                }
            }
            None => {
                warn!(
                    self.env.logger(),
                    "Node {} is not assigned to any subnet", self.node_id
                );
                PrincipalId::default()
            }
        }
    }

    pub fn get_last_canister_id_in_allocation_ranges(&self) -> PrincipalId {
        match self.subnet_id() {
            Some(subnet_id) => {
                let canister_ranges = self
                    .local_registry
                    .get_subnet_canister_ranges(self.registry_version, subnet_id)
                    .expect("Could not deserialize optional routing table from local registry.")
                    .expect("Optional routing table is None in local registry.");
                match canister_ranges.last() {
                    Some(range) => range.end.get(),
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
        let canister_bytes = load_wasm(name);
        let effective_canister_id = self.effective_canister_id();

        self.with_default_agent(move |agent| async move {
            // Create a canister.
            let mgr = ManagementCanister::create(&agent);
            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(effective_canister_id)
                .call_and_wait()
                .await
                .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
                .0;

            let mut install_code = mgr.install_code(&canister_id, &canister_bytes);
            if let Some(arg) = arg {
                install_code = install_code.with_raw_arg(arg)
            }
            install_code
                .call_and_wait()
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
            .expect("No no-name Internet Computer")
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

pub trait GetFirstHealthyNodeSnapshot {
    fn get_first_healthy_node_snapshot_where<F: Fn(&SubnetSnapshot) -> bool>(
        &self,
        subnet_pred: F,
    ) -> IcNodeSnapshot;

    fn get_first_healthy_node_snapshot_from_nth_subnet_where<F: Fn(&SubnetSnapshot) -> bool>(
        &self,
        subnet_pred: F,
        n: usize,
    ) -> IcNodeSnapshot;

    fn get_first_healthy_node_snapshot(&self) -> IcNodeSnapshot;
    fn get_first_healthy_application_node_snapshot(&self) -> IcNodeSnapshot;
    fn get_first_healthy_system_node_snapshot(&self) -> IcNodeSnapshot;
    fn get_first_healthy_verified_application_node_snapshot(&self) -> IcNodeSnapshot;
    fn get_first_healthy_nns_node_snapshot(&self) -> IcNodeSnapshot;
    fn get_first_healthy_non_nns_node_snapshot(&self) -> IcNodeSnapshot;
    fn get_first_healthy_system_but_not_nns_node_snapshot(&self) -> IcNodeSnapshot;
}

impl<T: HasTopologySnapshot> GetFirstHealthyNodeSnapshot for T {
    fn get_first_healthy_node_snapshot_where<F: Fn(&SubnetSnapshot) -> bool>(
        &self,
        subnet_pred: F,
    ) -> IcNodeSnapshot {
        self.get_first_healthy_node_snapshot_from_nth_subnet_where(subnet_pred, 0)
    }
    fn get_first_healthy_node_snapshot_from_nth_subnet_where<F: Fn(&SubnetSnapshot) -> bool>(
        &self,
        subnet_pred: F,
        n: usize,
    ) -> IcNodeSnapshot {
        let subnet = self
            .topology_snapshot()
            .subnets()
            .filter(subnet_pred)
            .nth(n)
            .expect("Expected there to be at least one subnet that matched the predicate!");

        let random_node = subnet
            .nodes()
            .next()
            .expect("Expected there to be at least one node in the subnet!");

        random_node.await_status_is_healthy().unwrap_or_else(|e| {
            panic!(
                "Expected random node {:?} to be healthy but got error {e:?}",
                random_node.node_id
            )
        });
        random_node
    }
    fn get_first_healthy_node_snapshot(&self) -> IcNodeSnapshot {
        self.get_first_healthy_node_snapshot_where(|_| true)
    }
    fn get_first_healthy_application_node_snapshot(&self) -> IcNodeSnapshot {
        self.get_first_healthy_node_snapshot_where(|s| s.subnet_type() == SubnetType::Application)
    }
    fn get_first_healthy_system_node_snapshot(&self) -> IcNodeSnapshot {
        self.get_first_healthy_node_snapshot_where(|s| s.subnet_type() == SubnetType::System)
    }
    fn get_first_healthy_verified_application_node_snapshot(&self) -> IcNodeSnapshot {
        self.get_first_healthy_node_snapshot_where(|s| {
            s.subnet_type() == SubnetType::VerifiedApplication
        })
    }
    fn get_first_healthy_nns_node_snapshot(&self) -> IcNodeSnapshot {
        let root_subnet_id = get_root_subnet_id_from_snapshot(self);
        self.get_first_healthy_node_snapshot_where(|s| s.subnet_id == root_subnet_id)
    }
    fn get_first_healthy_non_nns_node_snapshot(&self) -> IcNodeSnapshot {
        let root_subnet_id = get_root_subnet_id_from_snapshot(self);
        self.get_first_healthy_node_snapshot_where(|s| s.subnet_id != root_subnet_id)
    }
    fn get_first_healthy_system_but_not_nns_node_snapshot(&self) -> IcNodeSnapshot {
        let root_subnet_id = get_root_subnet_id_from_snapshot(self);
        self.get_first_healthy_node_snapshot_where(|s| {
            s.subnet_type() == SubnetType::System && s.subnet_id != root_subnet_id
        })
    }
}

fn get_root_subnet_id_from_snapshot<T: HasTopologySnapshot>(env: &T) -> SubnetId {
    let ts = env.topology_snapshot();
    ts.local_registry
        .get_root_subnet_id(ts.registry_version)
        .unwrap_result(ts.registry_version, "root_subnet_id")
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
    fn get_initial_replica_version(&self) -> Result<ReplicaVersion>;
    fn get_mainnet_ic_os_img_sha256(&self) -> Result<String>;
    fn get_mainnet_ic_os_update_img_sha256(&self) -> Result<String>;
}

impl<T: HasTestEnv> HasIcDependencies for T {
    fn get_farm_url(&self) -> Result<Url> {
        let dep_rel_path = "farm_base_url";
        let url = read_dependency_to_string(dep_rel_path)
            .unwrap_or_else(|_| FarmBaseUrl::read_attribute(&self.test_env()).to_string());
        Ok(Url::parse(&url)?)
    }

    fn get_initial_replica_version(&self) -> Result<ReplicaVersion> {
        let initial_replica_version = InitialReplicaVersion::read_attribute(&self.test_env());
        Ok(initial_replica_version.version)
    }

    fn get_mainnet_ic_os_img_sha256(&self) -> Result<String> {
        let mainnet_version: String =
            read_dependency_to_string("testnet/mainnet_nns_revision.txt")?;
        fetch_sha256(format!("http://download.proxy-global.dfinity.network:8080/ic/{mainnet_version}/guest-os/disk-img"), "disk-img.tar.zst", self.test_env().logger())
    }

    fn get_mainnet_ic_os_update_img_sha256(&self) -> Result<String> {
        let mainnet_version: String =
            read_dependency_to_string("testnet/mainnet_nns_revision.txt")?;
        fetch_sha256(format!("http://download.proxy-global.dfinity.network:8080/ic/{mainnet_version}/guest-os/update-img"), "update-img.tar.zst", self.test_env().logger())
    }
}

pub fn get_elasticsearch_hosts() -> Result<Vec<String>> {
    let dep_rel_path = "elasticsearch_hosts";
    let hosts = read_dependency_to_string(dep_rel_path)
        .unwrap_or_else(|_| "elasticsearch.testnet.dfinity.network:443".to_string());
    parse_elasticsearch_hosts(Some(hosts))
}

/// Helper function to figure out SHA256 from a CAS url
pub fn get_sha256_from_cas_url(img_name: &str, url: &Url) -> Result<String> {
    // Since this is a CAS url, we assume the last URL path part is the sha256.
    let (_prefix, sha256) = url
        .path()
        .rsplit_once('/')
        .ok_or(anyhow!("failed to extract sha256 from CAS url '{url}'"))?;
    let sha256 = sha256.to_string();
    bail_if_sha256_invalid(&sha256, img_name)?;
    Ok(sha256.to_string())
}

pub fn get_ic_os_img_url() -> Result<Url> {
    let url = read_dependency_from_env_to_string("ENV_DEPS__DEV_DISK_IMG_TAR_ZST_CAS_URL")?;
    Ok(Url::parse(&url)?)
}

pub fn get_ic_os_img_sha256() -> Result<String> {
    get_sha256_from_cas_url("ic_os_img_sha256", &get_ic_os_img_url()?)
}

pub fn get_malicious_ic_os_img_url() -> Result<Url> {
    let url =
        read_dependency_from_env_to_string("ENV_DEPS__DEV_MALICIOUS_DISK_IMG_TAR_ZST_CAS_URL")?;
    Ok(Url::parse(&url)?)
}

pub fn get_malicious_ic_os_img_sha256() -> Result<String> {
    get_sha256_from_cas_url("ic_os_img_sha256", &get_malicious_ic_os_img_url()?)
}

pub fn get_ic_os_update_img_url() -> Result<Url> {
    let url = read_dependency_from_env_to_string("ENV_DEPS__DEV_UPDATE_IMG_TAR_ZST_CAS_URL")?;
    Ok(Url::parse(&url)?)
}

pub fn get_ic_os_update_img_sha256() -> Result<String> {
    get_sha256_from_cas_url("ic_os_update_img_sha256", &get_ic_os_update_img_url()?)
}

pub fn get_ic_os_update_img_test_url() -> Result<Url> {
    let url = read_dependency_from_env_to_string("ENV_DEPS__DEV_UPDATE_IMG_TEST_TAR_ZST_CAS_URL")?;
    Ok(Url::parse(&url)?)
}

pub fn get_ic_os_update_img_test_sha256() -> Result<String> {
    get_sha256_from_cas_url("ic_os_update_img_sha256", &get_ic_os_update_img_test_url()?)
}

pub fn get_malicious_ic_os_update_img_url() -> Result<Url> {
    let url =
        read_dependency_from_env_to_string("ENV_DEPS__DEV_MALICIOUS_UPDATE_IMG_TAR_ZST_CAS_URL")?;
    Ok(Url::parse(&url)?)
}

pub fn get_malicious_ic_os_update_img_sha256() -> Result<String> {
    get_sha256_from_cas_url(
        "ic_os_update_img_sha256",
        &get_malicious_ic_os_update_img_url()?,
    )
}

pub fn get_boundary_node_img_url() -> Result<Url> {
    let dep_rel_path = "ic-os/boundary-guestos/envs/dev/disk-img.tar.zst.cas-url";
    let url = read_dependency_to_string(dep_rel_path)?;
    Ok(Url::parse(&url)?)
}

pub fn get_boundary_node_img_sha256() -> Result<String> {
    let dep_rel_path = "ic-os/boundary-guestos/envs/dev/disk-img.tar.zst.sha256";
    let sha256 = read_dependency_to_string(dep_rel_path)?;
    bail_if_sha256_invalid(&sha256, "boundary_node_img_sha256")?;
    Ok(sha256)
}

pub fn get_mainnet_ic_os_img_url() -> Result<Url> {
    let mainnet_version: String = read_dependency_to_string("testnet/mainnet_nns_revision.txt")?;
    let url = format!("http://download.proxy-global.dfinity.network:8080/ic/{mainnet_version}/guest-os/disk-img/disk-img.tar.zst");
    Ok(Url::parse(&url)?)
}

pub fn get_mainnet_ic_os_update_img_url() -> Result<Url> {
    let mainnet_version = read_dependency_to_string("testnet/mainnet_nns_revision.txt")?;
    let url = format!("http://download.proxy-global.dfinity.network:8080/ic/{mainnet_version}/guest-os/update-img/update-img.tar.zst");
    Ok(Url::parse(&url)?)
}

pub fn get_hostos_update_img_test_url() -> Result<Url> {
    let url =
        read_dependency_from_env_to_string("ENV_DEPS__DEV_HOSTOS_UPDATE_IMG_TEST_TAR_ZST_CAS_URL")?;
    Ok(Url::parse(&url)?)
}

pub fn get_hostos_update_img_test_sha256() -> Result<String> {
    get_sha256_from_cas_url(
        "hostos_update_img_sha256",
        &get_hostos_update_img_test_url()?,
    )
}

pub const FETCH_SHA256SUMS_RETRY_TIMEOUT: Duration = Duration::from_secs(120);
pub const FETCH_SHA256SUMS_RETRY_BACKOFF: Duration = Duration::from_secs(5);

fn fetch_sha256(base_url: String, file: &str, logger: Logger) -> Result<String> {
    let url = &format!("{base_url}/SHA256SUMS");
    let response = retry_with_msg!(
        format!("GET {url}"),
        logger.clone(),
        FETCH_SHA256SUMS_RETRY_TIMEOUT,
        FETCH_SHA256SUMS_RETRY_BACKOFF,
        || reqwest::blocking::get(url).map_err(|e| anyhow!("{:?}", e))
    )?;

    if !response.status().is_success() {
        error!(
            logger,
            "Failed to fetch sha256. Remote address: {:?}, Headers: {:?}",
            response.remote_addr(),
            response.headers()
        );
        return Err(anyhow!("Failed to fetch sha256"));
    }
    let body = response.text()?;

    // body should look like:
    // 7348b0f4b0267da7424306efddd57e26dc5a858cd642d64afaeaa592c4974af8 *disk-img.tar.zst

    let lines = body
        .split('\n')
        .filter(|line| line.ends_with(file))
        .collect::<Vec<&str>>();
    let line = lines.first().unwrap();
    let parts = line.split(' ').collect::<Vec<&str>>();
    let sha256 = parts.first().unwrap();
    bail_if_sha256_invalid(sha256, &format!("{base_url}/{file}"))?;
    Ok(sha256.to_string())
}

pub trait HasGroupSetup {
    fn create_group_setup(&self, group_base_name: String, no_group_ttl: bool);
}

impl HasGroupSetup for TestEnv {
    fn create_group_setup(&self, group_base_name: String, no_group_ttl: bool) {
        let log = self.logger();
        if self.get_json_path(GroupSetup::attribute_name()).exists() {
            let group_setup = GroupSetup::read_attribute(self);
            info!(
                log,
                "Group {} already set up.", group_setup.infra_group_name
            );
        } else {
            // GROUP_TTL should be enough for the setup task to allocate the group on InfraProvider
            // Afterwards, the group's TTL should be bumped via a keepalive task
            let timeout = if no_group_ttl { None } else { Some(GROUP_TTL) };
            let group_setup = GroupSetup::new(group_base_name.clone(), timeout);
            match InfraProvider::read_attribute(self) {
                InfraProvider::Farm => {
                    let farm_base_url = FarmBaseUrl::read_attribute(self);
                    let farm = Farm::new(farm_base_url.into(), self.logger());
                    let group_spec = GroupSpec {
                        vm_allocation: None,
                        required_host_features: vec![],
                        preferred_network: None,
                        metadata: None,
                    };
                    farm.create_group(
                        &group_setup.group_base_name,
                        &group_setup.infra_group_name,
                        group_setup.group_timeout,
                        group_spec,
                    )
                    .unwrap();
                }
                InfraProvider::K8s => {
                    let mut tnet =
                        TNet::new(&group_base_name.replace('_', "-")).expect("new tnet failed");
                    block_on(tnet.create()).expect("failed creating tnet");
                    tnet.write_attribute(self);
                }
            };
            group_setup.write_attribute(self);
            self.ssh_keygen().expect("ssh key generation failed");
            emit_group_event(&log, &group_setup.infra_group_name);
            emit_kibana_url_event(&log, &kibana_link(&group_setup.infra_group_name));
        }
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

pub fn get_dependency_path<P: AsRef<Path>>(p: P) -> PathBuf {
    let runfiles =
        std::env::var("RUNFILES").expect("Expected environment variable RUNFILES to be defined!");
    Path::new(&runfiles).join(p)
}

/// Return the (actual) path of the (runfiles-relative) artifact in environment variable `v`.
pub fn get_dependency_path_from_env(v: &str) -> PathBuf {
    let runfiles =
        std::env::var("RUNFILES").expect("Expected environment variable RUNFILES to be defined!");

    let path_from_env =
        std::env::var(v).unwrap_or_else(|_| panic!("Environment variable {} not set", v));

    Path::new(&runfiles).join(path_from_env)
}

pub fn read_dependency_to_string<P: AsRef<Path>>(p: P) -> Result<String> {
    let dep_path = get_dependency_path(p);
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

pub fn read_dependency_from_env_to_string(v: &str) -> Result<String> {
    let path_from_env =
        std::env::var(v).unwrap_or_else(|_| panic!("Environment variable {} not set", v));
    read_dependency_to_string(path_from_env)
}

pub fn load_wasm<P: AsRef<Path>>(p: P) -> Vec<u8> {
    let mut wasm_bytes = std::fs::read(get_dependency_path(&p))
        .unwrap_or_else(|e| panic!("Could not read WASM from {:?}: {e:?}", p.as_ref()));

    if p.as_ref().extension().unwrap() == "wat" {
        wasm_bytes = wat::parse_bytes(&wasm_bytes)
            .expect("Could not compile wat to wasm")
            .to_vec();
    }

    if wasm_bytes.is_empty() {
        panic!("WASM read from {:?} was empty", p.as_ref());
    }

    if !(wasm_bytes.starts_with(WASM_MAGIC_BYTES)
        || wasm_bytes.starts_with(GZIPPED_WASM_MAGIC_BYTES))
    {
        let ff: [u8; 4] = wasm_bytes[..4]
            .try_into()
            .expect("fewer than 4 bytes in wasm");
        panic!(
            "Invalid magic bytes for wasm module: {:?} (first four bytes read as {ff:?})",
            p.as_ref()
        );
    }
    wasm_bytes
}

pub trait SshSession {
    /// Return an SSH session to the machine referenced from self authenticating with the given user.
    fn get_ssh_session(&self) -> Result<Session>;

    /// Try a number of times to establish an SSH session to the machine referenced from self authenticating with the given user.
    fn block_on_ssh_session(&self) -> Result<Session>;

    fn block_on_bash_script(&self, script: &str) -> Result<String> {
        let session = self.block_on_ssh_session()?;
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
        let mut err = String::new();
        channel.stderr().read_to_string(&mut err)?;
        let exit_status = channel.exit_status()?;
        if exit_status != 0 {
            bail!("block_on_bash_script: exit_status = {exit_status:?}. Output: {out} Err: {err}");
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
        node_record.http.map(|me| {
            let mut url = IcNodeSnapshot::http_endpoint_to_url(&me);
            let _ = url.set_port(Some(9090));
            url
        })
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

    fn uses_dns(&self) -> bool {
        false
    }

    fn status(&self) -> Result<HttpStatusResponse> {
        let url = self.get_public_url();
        let addr = self.get_public_addr();
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(self.uses_snake_oil_certs())
            .timeout(READY_RESPONSE_TIMEOUT);
        let client = match (self.uses_dns(), url.domain()) {
            (false, Some(domain)) => client.resolve(domain, addr),
            _ => client,
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
                let healthy = Some(ReplicaHealthStatus::Healthy) == s.replica_health_status;
                if !healthy {
                    info!(
                        self.test_env().logger(),
                        "Replica not yet healthy, status: {}",
                        s.replica_health_status
                            .map(|s| s.as_ref().to_string())
                            .unwrap_or("unknown".to_string())
                    );
                }
                Ok(healthy)
            }
            Ok(_) => {
                warn!(
                    self.test_env().logger(),
                    "Health status not set in status response!"
                );
                Ok(false)
            }
            Err(e) => Err(e), // return the error, don't log it too.
        }
    }

    /// Waits until the is_healthy() returns true
    fn await_status_is_healthy(&self) -> Result<()> {
        retry_with_msg!(
            &format!("await_status_is_healthy of {}", self.get_public_url()),
            self.test_env().logger(),
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || {
                self.status_is_healthy()
                    .and_then(|s| if !s { bail!("Not ready!") } else { Ok(()) })
            }
        )
    }

    /// Waits until the is_healthy() returns an error three times in a row
    fn await_status_is_unavailable(&self) -> Result<()> {
        let mut count = 0;
        retry_with_msg!(
            &format!("await_status_is_unavailable of {}", self.get_public_url()),
            self.test_env().logger(),
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || match self.status_is_healthy() {
                Err(_) => {
                    count += 1;
                    if count >= 3 {
                        Ok(())
                    } else {
                        Err(anyhow!("Status was unavailable {count} times in a row."))
                    }
                }
                Ok(_) => {
                    count = 0;
                    Err(anyhow!("Status is still available"))
                }
            }
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

#[derive(Default)]
pub struct NnsCustomizations {
    /// Summarizes the custom parameters that a newly installed NNS should have.
    pub ledger_balances: Option<HashMap<AccountIdentifier, Tokens>>,
    pub neurons: Option<Vec<Neuron>>,
    pub install_at_ids: bool,
}

pub struct NnsInstallationBuilder {
    customizations: NnsCustomizations,
    installation_timeout: Duration,
}

impl Default for NnsInstallationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NnsInstallationBuilder {
    pub fn new() -> Self {
        Self {
            customizations: NnsCustomizations::default(),
            installation_timeout: NNS_CANISTER_INSTALL_TIMEOUT,
        }
    }

    pub fn with_overall_timeout(mut self, duration: Duration) -> Self {
        self.installation_timeout = duration;
        self
    }

    pub fn at_ids(mut self) -> Self {
        self.customizations.install_at_ids = true;
        self
    }

    pub fn with_customizations(mut self, customizations: NnsCustomizations) -> Self {
        self.customizations = customizations;
        self
    }

    pub fn install(&self, node: &IcNodeSnapshot, test_env: &TestEnv) -> Result<()> {
        let log = test_env.logger();
        let ic_name = node.ic_name();
        let url = node.get_public_url();
        let prep_dir = match test_env.prep_dir(&ic_name) {
            Some(v) => v,
            None => bail!("Prep Dir for IC {:?} does not exist.", ic_name),
        };
        info!(log, "Wait for node reporting healthy status");
        node.await_status_is_healthy().unwrap();

        let install_future = install_nns_canisters(
            &log,
            url,
            &prep_dir,
            true,
            self.customizations.install_at_ids,
            self.customizations.ledger_balances.clone(),
            self.customizations.neurons.clone(),
        );
        block_on(async {
            let timeout_result =
                tokio::time::timeout(self.installation_timeout, install_future).await;
            if timeout_result.is_err() {
                panic!(
                    "nns canisters were not installed within timeout of {} sec",
                    self.installation_timeout.as_secs()
                );
            }
        });
        Ok(())
    }
}

/// Set environment variable `env_name` to `file_path`
/// or to wherever `file_path` points to in case it's a symlink.
pub fn set_var_to_path<K: AsRef<OsStr>>(env_name: K, file_path: PathBuf) {
    let path = if file_path.is_symlink() {
        std::fs::read_link(file_path).unwrap()
    } else {
        file_path
    };
    std::env::set_var(env_name, path);
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
            .unwrap_result(
                registry_version,
                &format!("node_ids_on_subnet(subnet_id={})", self.subnet_id),
            );

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

pub struct HostedVm {
    farm: Farm,
    group_name: String,
    vm_name: String,
    k8s: bool,
}

/// VmControl enables a user to interact with VMs, i.e. change their state.
/// All functions belonging to this trait crash if a respective operation is for any reason
/// unsuccessful.
impl VmControl for HostedVm {
    fn kill(&self) {
        if self.k8s {
            block_on(destroy_vm(&self.vm_name)).expect("could not kill VM");
        } else {
            self.farm
                .destroy_vm(&self.group_name, &self.vm_name)
                .expect("could not kill VM");
        }
    }

    fn reboot(&self) {
        if self.k8s {
            block_on(restart_vm(&self.vm_name)).expect("could not reboot VM");
        } else {
            self.farm
                .reboot_vm(&self.group_name, &self.vm_name)
                .expect("could not reboot VM");
        }
    }

    fn start(&self) {
        if self.k8s {
            block_on(start_vm(&self.vm_name)).expect("could not start VM");
        } else {
            self.farm
                .start_vm(&self.group_name, &self.vm_name)
                .expect("could not start VM");
        }
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
        let farm_base_url = self.get_farm_url().unwrap();
        let farm = Farm::new(farm_base_url, env.logger());

        let mut vm_name = self.vm_name();
        let mut k8s = false;
        if InfraProvider::read_attribute(&env) == InfraProvider::K8s {
            k8s = true;
            let tnet = TNet::read_attribute(&env);
            let tnet_node = tnet
                .nodes
                .iter()
                .find(|n| n.node_id.clone().expect("node_id missing") == vm_name.clone())
                .expect("tnet doesn't have this node")
                .clone();
            vm_name = tnet_node.name.expect("nameless node");
        }

        Box::new(HostedVm {
            farm,
            group_name: pot_setup.infra_group_name,
            vm_name,
            k8s,
        })
    }
}

pub fn get_ssh_session_from_env(env: &TestEnv, ip: IpAddr) -> Result<Session> {
    let tcp = TcpStream::connect((ip, 22))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    let priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    sess.userauth_pubkey_file(SSH_USERNAME, None, priv_key_path.as_path(), None)?;
    Ok(sess)
}

impl SshSession for IcNodeSnapshot {
    fn get_ssh_session(&self) -> Result<Session> {
        let node_record = self.raw_node_record();
        let connection_endpoint = node_record.http.unwrap();
        let ip_addr = IpAddr::from_str(&connection_endpoint.ip_addr)?;
        get_ssh_session_from_env(&self.env, ip_addr)
    }

    fn block_on_ssh_session(&self) -> Result<Session> {
        let node_record = self.raw_node_record();
        let connection_endpoint = node_record.http.unwrap();
        let ip_addr = IpAddr::from_str(&connection_endpoint.ip_addr)?;
        retry_with_msg!(
            format!("get_ssh_session to {}", ip_addr.to_string()),
            self.env.logger(),
            SSH_RETRY_TIMEOUT,
            RETRY_BACKOFF,
            || { self.get_ssh_session() }
        )
    }
}

/* ### Auxiliary functions & helpers ### */

/// Try executing the given closure of type `FnMut() -> Result<R>` but retry in case it returns an `Err`.
/// Don't use `panic!` in your closure if you need it to be retried. Return an `Err` instead.
/// The macro will also log the given message before attempting to execute the closure, every time it's being retried and when it succceeds.
/// The log messages will include the source file path and code location of the macro call site.
#[macro_export]
macro_rules! retry_with_msg {
    ($msg:expr, $log:expr, $timeout:expr, $backoff:expr, $f:expr) => {
        $crate::driver::test_env_api::retry(
            format!("{} [{}:{}]", $msg, file!(), line!()),
            $log,
            $timeout,
            $backoff,
            $f,
        )
    };
}

pub fn retry<S: AsRef<str>, F, R>(
    msg: S,
    log: slog::Logger,
    timeout: Duration,
    backoff: Duration,
    mut f: F,
) -> Result<R>
where
    F: FnMut() -> Result<R>,
{
    let msg = msg.as_ref();
    let mut attempt = 1;
    let start = Instant::now();
    debug!(
        log,
        "Func=\"{msg}\" is being retried for the maximum of {timeout:?} with a linear backoff of {backoff:?}"
    );
    loop {
        match f() {
            Ok(v) => {
                debug!(
                    log,
                    "Func=\"{msg}\" succeeded after {:?} on attempt {attempt}",
                    start.elapsed()
                );
                break Ok(v);
            }
            Err(err) => {
                let err_msg = err.to_string();
                if start.elapsed() > timeout {
                    break Err(err.context(format!(
                        "Func=\"{msg}\" timed out after {:?} on attempt {attempt}. Last error: {err_msg}", start.elapsed()
                    )));
                }
                debug!(
                    log,
                    "Func=\"{msg}\" failed on attempt {attempt}. Error: {}",
                    trunc_error(err_msg)
                );
                std::thread::sleep(backoff);
                attempt += 1;
            }
        }
    }
}

fn trunc_error(err_str: String) -> String {
    let mut short_e = err_str.replace('\n', "\\n ");
    short_e.truncate(200);
    short_e.push_str("...");
    short_e
}

/// Try executing the given closure of type `Fn() -> Fut` where `Fut: Future<Output = Result<R>>` but retry in case the future returns an `Err`.
/// Don't use `panic!` in your closure if you need it to be retried. Return an `Err` instead.
/// The macro will also log the given message before attempting to execute the closure, every time it's being retried and when it succceeds.
/// The log messages will include the source file path and code location of the macro call site.
#[macro_export]
macro_rules! retry_with_msg_async {
    ($msg:expr, $log:expr, $timeout:expr, $backoff:expr, $f:expr) => {
        $crate::driver::test_env_api::retry_async(
            format!("{} [{}:{}]", $msg, file!(), line!()),
            $log,
            $timeout,
            $backoff,
            $f,
        )
    };
}

pub async fn retry_async<S: AsRef<str>, F, Fut, R>(
    msg: S,
    log: &slog::Logger,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> Result<R>
where
    Fut: Future<Output = Result<R>>,
    F: Fn() -> Fut,
{
    let msg = msg.as_ref();
    let mut attempt = 1;
    let start = Instant::now();
    debug!(
        log,
        "Func=\"{msg}\" is being retried for the maximum of {timeout:?} with a constant backoff of {backoff:?}"
    );
    loop {
        match f().await {
            Ok(v) => {
                debug!(
                    log,
                    "Func=\"{msg}\" succeeded after {:?} on attempt {attempt}",
                    start.elapsed()
                );
                break Ok(v);
            }
            Err(err) => {
                let err_msg = err.to_string();
                if start.elapsed() > timeout {
                    break Err(err.context(format!(
                        "Func=\"{msg}\" timed out after {:?} on attempt {attempt}. Last error: {err_msg}",
                        start.elapsed(),
                    )));
                }
                debug!(
                    log,
                    "Func=\"{msg}\" failed on attempt {attempt}. Error: {}",
                    trunc_error(err_msg)
                );
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
    fn unwrap_result(self, registry_version: RegistryVersion, key_name: &str) -> T {
        match self {
            Ok(value) => value.unwrap_or_else(|| {
                panic!(
                    "registry (v.{}) does not have value for key `{}`",
                    registry_version, key_name
                )
            }),
            Err(err) => {
                panic!("registry (v.{}) error: {}", registry_version, err)
            }
        }
    }
}

trait RegistryResultHelper<T> {
    fn unwrap_result(self, registry_version: RegistryVersion, key_name: &str) -> T;
}

/// How many ICP should TEST_USER1 have after ICP ledger initialization.
///
/// The starting balance of one user should be sufficient for most test scenarios but less than `Tokens::MAX` as that is the upper bound on the sum of all minted tokens.
pub const TEST_USER1_STARTING_TOKENS: Tokens = Tokens::from_e8s(u64::MAX / 2);

/// Installs the NNS canister versions provided by `canister_wasm_strategy`, with `customizations`, on the node given by `url` using the initial registry created by `ic-prep`, stored under `registry_local_store`.
pub async fn install_nns_canisters(
    logger: &Logger,
    url: Url,
    ic_prep_state_dir: &IcPrepStateDir,
    nns_test_neurons_present: bool,
    install_at_ids: bool,
    ledger_balances: Option<HashMap<AccountIdentifier, Tokens>>,
    neurons: Option<Vec<Neuron>>,
) {
    info!(
        logger,
        "Compiling/installing NNS canisters (might take a while)."
    );
    let mut init_payloads = NnsInitPayloadsBuilder::new();
    if nns_test_neurons_present {
        let mut ledger_balances = ledger_balances.unwrap_or_default();
        let neurons = neurons.unwrap_or_default();
        ledger_balances.insert(
            LIFELINE_CANISTER_ID.get().into(),
            Tokens::from_tokens(10_000).unwrap(),
        );
        ledger_balances.insert((*TEST_USER1_PRINCIPAL).into(), TEST_USER1_STARTING_TOKENS);
        if ledger_balances.len() > 100 {
            let first_100_ledger_balances: HashMap<AccountIdentifier, Tokens> = ledger_balances
                .iter()
                .take(100)
                .map(|(x, y)| (*x, *y))
                .collect();
            info!(
                logger,
                "Initial ledger (showing the first 100 entries out of {}): {:?}",
                ledger_balances.len(),
                first_100_ledger_balances
            );
        } else {
            info!(logger, "Initial ledger: {:?}", ledger_balances);
        }

        let ledger_init_payload = LedgerCanisterInitPayload::builder()
            .minting_account(GOVERNANCE_CANISTER_ID.get().into())
            .initial_values(ledger_balances)
            .send_whitelist(HashSet::from([CYCLES_MINTING_CANISTER_ID]))
            .build()
            .unwrap();

        init_payloads
            .with_test_neurons()
            .with_additional_neurons(neurons)
            .with_ledger_init_state(ledger_init_payload);
    }
    let registry_local_store = ic_prep_state_dir.registry_local_store_path();
    let initial_mutations = read_initial_mutations_from_local_store_dir(&registry_local_store);
    init_payloads.with_initial_mutations(initial_mutations);

    let agent = InternalAgent::new(
        url,
        Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
    );
    let runtime = Runtime::Remote(RemoteTestRuntime {
        agent,
        effective_canister_id: REGISTRY_CANISTER_ID.into(),
    });

    if install_at_ids {
        NnsCanisters::set_up_at_ids(&runtime, init_payloads.build()).await;
    } else {
        NnsCanisters::set_up(&runtime, init_payloads.build()).await;
    }
}

/// A short wasm module that is a legal canister binary.
pub(crate) const WASM_MAGIC_BYTES: &[u8] = &[0, 97, 115, 109];

/// See https://ic-interface-spec.netlify.app/#canister-module-format
pub(crate) const GZIPPED_WASM_MAGIC_BYTES: &[u8] = &[31, 139, 8, 0];

pub trait CreateDnsRecords {
    /// Creates DNS records under the suffix: `.<group-name>.farm.dfinity.systems`.
    /// The records will be garbage collected some time after the group has expired.
    /// The suffix will be returned from this function such that the FQDNs can be constructed.
    fn create_dns_records(&self, dns_records: Vec<DnsRecord>) -> String;
}

impl<T> CreateDnsRecords for T
where
    T: HasTestEnv,
{
    fn create_dns_records(&self, dns_records: Vec<DnsRecord>) -> String {
        let env = self.test_env();
        let log = env.logger();
        let farm_base_url = self.get_farm_url().unwrap();
        let farm = Farm::new(farm_base_url, log);
        let group_setup = GroupSetup::read_attribute(&env);
        let group_name = group_setup.infra_group_name;
        farm.create_dns_records(&group_name, dns_records)
            .expect("Failed to create DNS records")
    }
}

pub trait CreatePlaynetDnsRecords {
    /// Creates DNS records under the suffix: `.ic{ix}.farm.dfinity.systems`
    /// where `ix` is the index of the acquired playnet.
    ///
    /// The records will be garbage collected some time after the group has expired.
    /// The suffix will be returned from this function such that the FQDNs can be constructed.
    fn create_playnet_dns_records(&self, dns_records: Vec<DnsRecord>) -> String;
}

impl<T> CreatePlaynetDnsRecords for T
where
    T: HasTestEnv,
{
    fn create_playnet_dns_records(&self, dns_records: Vec<DnsRecord>) -> String {
        let env = self.test_env();
        let log = env.logger();
        if InfraProvider::read_attribute(&env) == InfraProvider::Farm {
            let farm_base_url = self.get_farm_url().unwrap();
            let farm = Farm::new(farm_base_url, log);
            let group_setup = GroupSetup::read_attribute(&env);
            let group_name = group_setup.infra_group_name;
            farm.create_playnet_dns_records(&group_name, dns_records)
                .expect("Failed to create playnet DNS records")
        } else {
            let tnet = TNet::read_attribute(&env);
            block_on(tnet.create_playnet_dns_records(dns_records))
                .expect("Failed to acquire a certificate for a playnet")
        }
    }
}

pub trait AcquirePlaynetCertificate {
    /// Get a certificate signed by Let's Encrypt from farm
    /// for the domain `*.farm.dfinity.systems`.
    fn acquire_playnet_certificate(&self) -> PlaynetCertificate;
}

impl<T> AcquirePlaynetCertificate for T
where
    T: HasTestEnv,
{
    fn acquire_playnet_certificate(&self) -> PlaynetCertificate {
        let env = self.test_env();
        let log = env.logger();
        if InfraProvider::read_attribute(&env) == InfraProvider::Farm {
            let farm_base_url = self.get_farm_url().unwrap();
            let farm = Farm::new(farm_base_url, log);
            let group_setup = GroupSetup::read_attribute(&env);
            let group_name = group_setup.infra_group_name;
            farm.acquire_playnet_certificate(&group_name)
                .expect("Failed to acquire a certificate for a playnet")
        } else {
            let tnet = TNet::from_env(&env);
            block_on(tnet.acquire_playnet_certificate())
                .expect("Failed to acquire a certificate for a playnet")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FarmBaseUrl {
    url: Url,
}

impl FarmBaseUrl {
    pub fn new_or_default(url: Option<Url>) -> Self {
        let url = match url {
            Some(url) => url,
            None => Url::parse(constants::DEFAULT_FARM_BASE_URL).unwrap(),
        };
        Self { url }
    }
}

impl std::fmt::Display for FarmBaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl From<FarmBaseUrl> for Url {
    fn from(value: FarmBaseUrl) -> Self {
        value.url
    }
}

impl TestEnvAttribute for FarmBaseUrl {
    fn attribute_name() -> String {
        "farm_url".to_string()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InitialReplicaVersion {
    pub version: ReplicaVersion,
}

impl TestEnvAttribute for InitialReplicaVersion {
    fn attribute_name() -> String {
        "initial_replica_version".to_string()
    }
}

pub fn await_boundary_node_healthy(env: &TestEnv, boundary_node_name: &str) {
    let boundary_node = env
        .get_deployed_boundary_node(boundary_node_name)
        .unwrap()
        .get_snapshot()
        .unwrap();
    boundary_node
        .await_status_is_healthy()
        .expect("BN did not come up!");
}

pub fn emit_group_event(log: &slog::Logger, group: &str) {
    #[derive(Deserialize, Serialize)]
    pub struct GroupName {
        message: String,
        group: String,
    }
    let event = log_events::LogEvent::new(
        INFRA_GROUP_CREATED_EVENT_NAME.to_string(),
        GroupName {
            message: "Created new InfraProvider group".to_string(),
            group: group.to_string(),
        },
    );
    event.emit_log(log);
}

pub fn emit_kibana_url_event(log: &slog::Logger, kibana_url: &str) {
    #[derive(Deserialize, Serialize)]
    pub struct KibanaUrl {
        message: String,
        url: String,
    }
    let event = log_events::LogEvent::new(
        KIBANA_URL_CREATED_EVENT_NAME.to_string(),
        KibanaUrl {
            message: "Replica logs will appear in Kibana".to_string(),
            url: kibana_url.to_string(),
        },
    );
    event.emit_log(log);
}
