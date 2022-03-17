//! <h1>Overview</h1>
//!
//! The peer-to-peer (P2P) component implements a gossiping mechanism for
//! subnets and creates and validates ingress message payloads for the
//! *Consensus* layer. It contains the following sub-components:

//!
//! * *Gossip*: Disseminate artifacts to other nodes in the same subnet. This is
//!   achieved by an advertise-request-response mechanism, taking priorities
//!   into account.
//! * *Artifact Manager*: Store artifacts to be used by this and other nodes in
//!  the same subnet in the artifact pool. The artifact manager interacts with
//! *Gossip* and its application components:
//!     * *Consensus*
//!     * *Distributed Key Generation*
//!     * *Certification*
//!     * *Ingress Manager*
//!     * *State Sync*
//! * *Ingress Manager*: Processes ingress messages, providing the following
//!   functionality:
//!     * Check ingress message validity of messages received from other nodes
//!       and broadcast valid ingress messages
//!     * Select ingress message to form *Consensus* payloads
//!     * Validate such payloads

//! <h1>Bounded-time/Eventual Delivery</h1>
//!
//! * P2P guarantees that, up to a certain maximum volume, valid artifacts reach
//!   all nodes subject to constraints due to prioritisation and the
//!   applications' validation policies. More precisely, *Gossip* guarantees the
//!   delivery of artifacts of a bounded aggregate size within bounded
//!   time/eventually under certain network assumptions and provided that the
//!   rules and validity conditions specified by the application components are
//!   satisfied. Thus, valid artifacts that are of high priority for all nodes
//!   will reach all honest nodes in bounded time/eventually, despite attacks
//!   (under certain network assumptions). In other words, the priority function
//!   ensures that relevant valid artifacts reach enough nodes in the subnet,
//!   while artifacts that violate the policy or are of low priority may not
//!   reach all other nodes in the subnet.
//! * Eventual delivery differs from eventual consistency. Consistency models
//!   describe the contract between users and a system offering reading and
//!   writing to replicated state. Informally, eventual consistency guarantees
//!   that if no write occurs for a long time, all replicas return the same
//!   value for reads. *Consensus* does **not** require eventual consistency for
//!   the artifact pool: the priority function can drop adverts without
//!   requesting the artifact and different (valid) artifacts with the same
//!   identifier may exist in the system and *Consensus* often only needs at
//!   most one of them. Moreover, the offered guarantees are subject to
//!   bandwidth restrictions on all honest peers.

//! <h1>Performance</h1>
//!
//! * Low number of open connections: An overlay topology defines which nodes
//!   exchange artifacts directly with each other. Together with the
//!   bounded-time/eventual delivery guarantee mentioned above, the topology
//!   ensures that enough honest nodes receive artifacts to make progress. Since
//!   the overlay topology describes which connections are established and
//!   maintained, it enables the broadcast protocol to trade off bandwidth
//!   consumption with latency.
//! * High throughput and predictability: Bandwidth must not be wasted on
//!   sending/receiving the same artifact twice. The behavior under load must be
//!   predictable (memory/bandwidth/CPU guarantees for different peers and for
//!   different components using gossip).
//! * Prioritization: Different artifacts are transferred with different
//!   priorities, and priorities change over time.

//! <h1>Ingress Manager</h1>
//!
//! * Validity: ingress messages are broadcast to other peers only if they are
//!   valid.
//! * At-most-once semantics: an ingress message is selected to be in a
//!   *Consensus* payload at most once before its expiry time and only if it is
//!   valid (even if a node restarts).

//! <h1>Dependencies</h1>
//! P2P relies on the following components:
//!
//! * *Transport* for node-to-node communication.
//! * *HTTP handler* to submit validated ingress messages.
//! * *Consensus* to pass the Internet Computer time as well as finalized
//!   payloads and non-finalized payloads since the last executed height in the
//!   chain.
//! * *Registry* to look up subnet IDs, node IDs, and configuration values.
//! * *Crypto* to verify signatures in the *Ingress Manager*.
//! * *Ingress History Reader* to prevent duplicate Ingress Messages in blocks

//! <h1>Component Diagram</h1>
//!
//! The following diagram depicts the interfaces between the P2P components and
//! other components. The interaction with the *Registry* is omitted for
//! simplicity's sake as all components rely on it.
//!
//! <div>
//! <img src="../../../../../docs/assets/p2p.png" height="960"
//! width="540"/> </div> <hr/>

use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::{
    artifact_manager::ArtifactManager, consensus_pool::ConsensusPoolCache,
    registry::RegistryClient, transport::Transport,
};
use ic_interfaces_p2p::IngressIngestionService;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_transport::transport::create_transport;
use ic_types::{
    malicious_flags::MaliciousFlags,
    transport::{FlowTag, TransportConfig},
    NodeId, SubnetId,
};
use serde::{Deserialize, Serialize};
use std::{
    error,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::Arc,
    time::Duration,
};
use tower::{util::BoxService, ServiceBuilder};

mod artifact_download_list;
mod download_management;
mod download_prioritization;
mod event_handler;
mod gossip_protocol;
mod malicious_gossip;
mod metrics;

pub use event_handler::{
    AdvertSubscriber, IngressEventHandler, P2PTickerThreadJoiner as P2PThreadJoiner,
};

/// Custom P2P result type returning a P2P error in case of error.
pub(crate) type P2PResult<T> = std::result::Result<T, P2PError>;

pub(crate) mod utils {
    //! The utils module provides a mapping from a gossip message to the
    //! corresponding flow tag.
    use crate::gossip_protocol::GossipMessage;
    use ic_types::transport::FlowTag;

    /// The FlowMapper struct holds a vector of flow tags.
    pub(crate) struct FlowMapper {
        flow_tags: Vec<FlowTag>,
    }

    impl FlowMapper {
        /// The function creates a new FlowMapper instance.
        pub(crate) fn new(flow_tags: Vec<FlowTag>) -> Self {
            assert_eq!(flow_tags.len(), 1);
            Self { flow_tags }
        }

        /// The function returns the flow tag of the flow the message maps to.
        pub(crate) fn map(&self, _msg: &GossipMessage) -> FlowTag {
            self.flow_tags[0]
        }
    }
}

/// Max number of ingress message we can buffer until the P2P layer is ready to
/// accept them.
// The latency SLO for 'call' requests is set for 2s. Given the rate limiter of
// 100 per second this buffer should not be bigger than 200. We are conservite
// setting it to 100.
const MAX_BUFFERED_INGRESS_MESSAGES: usize = 100;
/// Max number of inflight requests into P2P. Note each each requests requires a
/// dedicated thread to execute on so this number should be relatively small.
// Do not increase the number until we get to the root cause of NET-743.
const MAX_INFLIGHT_INGRESS_MESSAGES: usize = 1;
/// Max ingress messages per second that can go into P2P.
// There is some internal contention inside P2P (NET-743). We achieve lower
// throughput if we process messages one after the other.
const MAX_INGRESS_MESSAGES_PER_SECOND: u64 = 100;

#[allow(clippy::too_many_arguments)]
pub fn start_p2p(
    metrics_registry: MetricsRegistry,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    node_id: NodeId,
    subnet_id: SubnetId,
    transport_config: TransportConfig,
    gossip_config: GossipConfig,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    transport: Option<Arc<dyn Transport>>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    artifact_manager: Arc<dyn ArtifactManager>,
    ingress_throttler: event_handler::IngressThrottler,
    malicious_flags: MaliciousFlags,
    advert_subscriber: &AdvertSubscriber,
) -> (IngressIngestionService, P2PThreadJoiner) {
    let transport = transport.unwrap_or_else(|| {
        create_transport(
            node_id,
            transport_config.clone(),
            registry_client.get_latest_version(),
            metrics_registry.clone(),
            tls_handshake,
            rt_handle.clone(),
            log.clone(),
        )
    });

    let event_handler = Arc::new(event_handler::AsyncTransportEventHandlerImpl::new(
        node_id,
        log.clone(),
        &metrics_registry,
        event_handler::ChannelConfig::from(gossip_config),
    ));
    transport
        .register_client(event_handler.clone())
        .expect("transport registration failed");

    let p2p_flow_tags = transport_config
        .p2p_flows
        .iter()
        .map(|flow_config| FlowTag::from(flow_config.flow_tag))
        .collect();
    let gossip = Arc::new(gossip_protocol::GossipImpl::new(
        node_id,
        subnet_id,
        consensus_pool_cache,
        registry_client.clone(),
        artifact_manager.clone(),
        transport.clone(),
        p2p_flow_tags,
        log.clone(),
        &metrics_registry,
        malicious_flags,
    ));
    event_handler.start(gossip.clone());
    advert_subscriber.start(gossip.clone());

    let p2p_thread_joiner = P2PThreadJoiner::new(log, gossip.clone());

    let ingress_event_handler =
        BoxService::new(IngressEventHandler::new(ingress_throttler, gossip, node_id));

    let ingress_ingestion_service = BoxService::new(
        ServiceBuilder::new()
            .concurrency_limit(MAX_INFLIGHT_INGRESS_MESSAGES)
            .rate_limit(MAX_INGRESS_MESSAGES_PER_SECOND, Duration::from_secs(1))
            .service(ingress_event_handler),
    );
    let ingress_ingestion_service = ServiceBuilder::new()
        .buffer(MAX_BUFFERED_INGRESS_MESSAGES)
        .service(ingress_ingestion_service);
    (ingress_ingestion_service, p2p_thread_joiner)
}

pub(crate) mod advert_utils {
    use crate::gossip_protocol::{GossipAdvertAction, GossipAdvertSendRequest, Percentage};
    use ic_logger::replica_logger::ReplicaLogger;
    use ic_logger::{error, warn};
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::GossipAdvertConfig;
    use ic_types::artifact::AdvertClass;
    use ic_types::p2p::GossipAdvert;
    use prometheus::IntCounterVec;

    /// Maps the P2P client advert send requests to the internal format,
    /// based on the config
    #[derive(Clone)]
    pub(crate) struct AdvertRequestBuilder {
        pub(crate) advert_config: Option<GossipAdvertConfig>,
        adverts_by_class: IntCounterVec,
    }

    impl AdvertRequestBuilder {
        pub(crate) fn new(
            mut advert_config: Option<GossipAdvertConfig>,
            metrics_registry: &MetricsRegistry,
            log: ReplicaLogger,
        ) -> Self {
            warn!(
                log,
                "AdvertRequestBuilder::new(): advert_config = {:?}", advert_config
            );

            if let Some(config) = &advert_config {
                if let Err(e) = validate_advert_config(config) {
                    error!(log, "AdvertRequestBuilder::new(): invalid config = {:?}", e);
                    // Disable the feature on invalid config
                    advert_config.take();
                }
            }

            Self {
                advert_config,
                adverts_by_class: metrics_registry.int_counter_vec(
                    "gossip_adverts_by_class",
                    "Number of adverts from clients, by advert class",
                    &["type"],
                ),
            }
        }

        /// Maps the client advert send request to the internal format
        pub(crate) fn build(
            &self,
            advert: GossipAdvert,
            advert_class: AdvertClass,
        ) -> Option<GossipAdvertSendRequest> {
            self.adverts_by_class
                .with_label_values(&[advert_class.as_str()])
                .inc();

            let config = match &self.advert_config {
                Some(config) => config,
                None => {
                    // Feature disabled, send to all peers
                    return Some(GossipAdvertSendRequest {
                        advert,
                        action: GossipAdvertAction::SendToAllPeers,
                    });
                }
            };

            let action = match advert_class {
                AdvertClass::Critical => Some(GossipAdvertAction::SendToAllPeers),
                AdvertClass::BestEffort => Some(GossipAdvertAction::SendToRandomSubset(
                    Percentage::from(config.best_effort_percentage),
                )),
                AdvertClass::None => None,
            };
            action.map(|action| GossipAdvertSendRequest { advert, action })
        }
    }

    pub(crate) fn validate_advert_config(config: &GossipAdvertConfig) -> Result<(), String> {
        if config.best_effort_percentage == 0 || config.best_effort_percentage > 100 {
            return Err(format!(
                "Invalid best effort percentage: {}",
                config.best_effort_percentage
            ));
        }

        Ok(())
    }
}

/// Fetch the Gossip configuration from the registry.
pub fn fetch_gossip_config(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> GossipConfig {
    if let Ok(Some(Some(gossip_config))) =
        registry_client.get_gossip_config(subnet_id, registry_client.get_latest_version())
    {
        gossip_config
    } else {
        ic_types::p2p::build_default_gossip_config()
    }
}

/// Generic P2P Error codes.
///
/// Some error codes are serialized over the wire to convey
/// protocol results. Some results are also used for internal
/// operation, i.e., they are not represented in the on-wire protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum P2PErrorCode {
    /// The requested entity artifact/chunk/server/client was not found
    NotFound = 1,
    /// An artifact (chunk) was received that already exists.
    Exists,
    /// An internal operation failed.
    Failed,
    /// The operation cannot be performed at this time.
    Busy,
    /// P2P initialization failed.
    InitFailed,
    /// Send/receive failed because the channel was disconnected.
    ChannelShutDown,
}

/// Wrapper over a P2P error code.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct P2PError {
    /// The P2P error code.
    p2p_error_code: P2PErrorCode,
}

/// Implement the `Display` trait to print/display P2P error codes.
impl Display for P2PError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "P2PErrorCode: {:?}", self.p2p_error_code)
    }
}

/// Implement the `Error` trait to wrap P2P errors.
impl error::Error for P2PError {
    /// The function returns `None` as the underlying cause is not tracked.
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// A P2P error code can be converted into a P2P result.
impl<T> From<P2PErrorCode> for P2PResult<T> {
    /// The function converts a P2P error code to a P2P result.
    fn from(p2p_error_code: P2PErrorCode) -> P2PResult<T> {
        Err(P2PError { p2p_error_code })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::advert_utils::{validate_advert_config, AdvertRequestBuilder};
    use crate::download_prioritization::test::make_gossip_advert;
    use crate::gossip_protocol::{GossipAdvertAction, GossipAdvertSendRequest, Percentage};
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::GossipAdvertConfig;
    use ic_test_utilities::p2p::p2p_test_setup_logger;
    use ic_types::artifact::AdvertClass;

    #[test]
    fn test_advert_config_validation() {
        assert!(validate_advert_config(&GossipAdvertConfig {
            best_effort_percentage: 10,
        })
        .is_ok());
        assert!(validate_advert_config(&GossipAdvertConfig {
            best_effort_percentage: 90,
        })
        .is_ok());
        assert!(validate_advert_config(&GossipAdvertConfig {
            best_effort_percentage: 100,
        })
        .is_ok());

        assert_eq!(
            validate_advert_config(&GossipAdvertConfig {
                best_effort_percentage: 0,
            })
            .err()
            .unwrap(),
            "Invalid best effort percentage: 0"
        );
        assert_eq!(
            validate_advert_config(&GossipAdvertConfig {
                best_effort_percentage: 110,
            })
            .err()
            .unwrap(),
            "Invalid best effort percentage: 110"
        );
    }

    #[test]
    fn test_advert_optimization_disabled() {
        let builder = AdvertRequestBuilder::new(
            None,
            &MetricsRegistry::new(),
            p2p_test_setup_logger().root.clone().into(),
        );
        let result = builder.build(make_gossip_advert(10), AdvertClass::Critical);
        let expected = GossipAdvertSendRequest {
            advert: make_gossip_advert(10),
            action: GossipAdvertAction::SendToAllPeers,
        };
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_advert_optimization_enabled() {
        let builder = AdvertRequestBuilder::new(
            Some(GossipAdvertConfig {
                best_effort_percentage: 25,
            }),
            &MetricsRegistry::new(),
            p2p_test_setup_logger().root.clone().into(),
        );

        // AdvertClass::Critical
        {
            let result = builder.build(make_gossip_advert(10), AdvertClass::Critical);
            let expected = GossipAdvertSendRequest {
                advert: make_gossip_advert(10),
                action: GossipAdvertAction::SendToAllPeers,
            };
            assert_eq!(result.unwrap(), expected);
        }

        // AdvertClass::BestEffort
        {
            let result = builder.build(make_gossip_advert(10), AdvertClass::BestEffort);
            let expected = GossipAdvertSendRequest {
                advert: make_gossip_advert(10),
                action: GossipAdvertAction::SendToRandomSubset(Percentage::from(25)),
            };
            assert_eq!(result.unwrap(), expected);
        }

        // AdvertClass::None
        {
            let result = builder.build(make_gossip_advert(10), AdvertClass::None);
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_advert_invalid_config() {
        let builder = AdvertRequestBuilder::new(
            Some(GossipAdvertConfig {
                best_effort_percentage: 125,
            }),
            &MetricsRegistry::new(),
            p2p_test_setup_logger().root.clone().into(),
        );
        assert!(builder.advert_config.is_none());
    }
}
