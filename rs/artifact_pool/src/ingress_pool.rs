/// Ingress Pool provides storage for all ingress messages in artifact_pool
/// Logically it can be viewed as part of the artifact pool
/// But we keep it separated for code readability
use crate::{
    HasTimestamp,
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED, PoolMetrics},
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::{
    ingress_pool::{
        ChangeAction, IngressPool, IngressPoolObject, IngressPoolThrottler, Mutations, PoolSection,
        UnvalidatedIngressArtifact, ValidatedIngressArtifact,
    },
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool, UnvalidatedArtifact,
        ValidatedPoolReader,
    },
};
use ic_logger::{ReplicaLogger, debug};
use ic_metrics::MetricsRegistry;
use ic_types::{
    CountBytes, NodeId, Time,
    artifact::IngressMessageId,
    messages::{EXPECTED_MESSAGE_ID_LENGTH, MessageId, SignedIngress},
};
use prometheus::IntCounter;
use std::collections::BTreeMap;

mod peer_counter;

use peer_counter::PeerCounters;

const INGRESS_MESSAGE_ARTIFACT_TYPE: &str = "ingress_message";

#[derive(Clone)]
struct IngressPoolSection<T: AsRef<IngressPoolObject>> {
    /// Do not insert or remove elements in this map directly. Use this struct's
    /// associated functions [`insert`], [`remove`] and [`purge_below`].
    artifacts: BTreeMap<IngressMessageId, T>,
    metrics: PoolMetrics,
    /// Note: `peer_counters` is updated incrementally as a side-effect of insert, remove
    /// and purge invocations. Never modify the artifacts map directly! Use the
    /// associated functions [`insert`], [`remove`] and [`purge_below`]
    peer_counters: PeerCounters,
}

impl<T: AsRef<IngressPoolObject>> IngressPoolSection<T> {
    fn new(log: ReplicaLogger, metrics: PoolMetrics) -> IngressPoolSection<T> {
        IngressPoolSection {
            peer_counters: PeerCounters::new(log),
            artifacts: BTreeMap::new(),
            metrics,
        }
    }

    /// Adds the `artifact` to the pool.
    /// Note: the function doesn't check if the pool's limits are already exceeded, it's the
    /// caller's responsibility to check the limits before calling `insert`. Currently, this check
    /// happens in `on_state_change` function in `ingress_handler.rs`.
    fn insert(&mut self, message_id: IngressMessageId, artifact: T) {
        let _timer = self
            .metrics
            .op_duration
            .with_label_values(&["insert"])
            .start_timer();
        let new_artifact_size = artifact.as_ref().count_bytes();
        self.metrics
            .observe_insert(new_artifact_size, INGRESS_MESSAGE_ARTIFACT_TYPE);
        self.peer_counters.observe(artifact.as_ref());

        if let Some(previous) = self.artifacts.insert(message_id, artifact) {
            self.peer_counters.forget(previous.as_ref());

            self.metrics.observe_duplicate(
                previous.as_ref().count_bytes(),
                INGRESS_MESSAGE_ARTIFACT_TYPE,
            );
        }

        // SAFETY: Checking byte size invariant
        self.assert_section_ok();
    }

    fn remove(&mut self, message_id: &IngressMessageId) -> Option<T> {
        let _timer = self
            .metrics
            .op_duration
            .with_label_values(&["remove"])
            .start_timer();
        let removed = self.artifacts.remove(message_id);
        if let Some(artifact) = &removed {
            self.peer_counters.forget(artifact.as_ref());
            self.metrics.observe_remove(
                artifact.as_ref().count_bytes(),
                INGRESS_MESSAGE_ARTIFACT_TYPE,
            );
        }
        // SAFETY: Checking byte size invariant
        self.assert_section_ok();
        removed
    }

    // Purge below an expiry prefix (non-inclusive), and return the purged artifacts
    // as an iterator.
    fn purge_below(&mut self, expiry: Time) -> Box<dyn Iterator<Item = T> + '_> {
        let _timer = self
            .metrics
            .op_duration
            .with_label_values(&["purge_below"])
            .start_timer();
        let zero_bytes = [0; EXPECTED_MESSAGE_ID_LENGTH];
        let key = IngressMessageId::new(expiry, MessageId::from(zero_bytes));
        let mut to_remove = self.artifacts.split_off(&key);
        std::mem::swap(&mut to_remove, &mut self.artifacts);
        for artifact in to_remove.values() {
            let artifact_size = artifact.as_ref().count_bytes();
            self.peer_counters.forget(artifact.as_ref());
            self.metrics
                .observe_remove(artifact_size, INGRESS_MESSAGE_ARTIFACT_TYPE);
        }
        // SAFETY: Checking byte size invariant
        self.assert_section_ok();
        Box::new(to_remove.into_values())
    }

    /// Counts the exact bytes by iterating over the artifact btreemap, instead
    /// of returning the memoized byte_size.
    fn count_bytes_slow(&self) -> usize {
        self.artifacts
            .values()
            .map(|item| item.as_ref().count_bytes())
            .sum()
    }

    /// Helper function to concisely validate that the real byte size of the pool section
    /// (obtained by accumulating all btreemap values) is identical to count_bytes()
    fn assert_section_ok(&self) {
        debug_assert_eq!(
            self.peer_counters.count_total_bytes(),
            self.count_bytes_slow(),
            "invariant violated: byte_size == real size of btreemap"
        );
    }
}

impl<T: AsRef<IngressPoolObject> + HasTimestamp> PoolSection<T> for IngressPoolSection<T> {
    fn get(&self, message_id: &IngressMessageId) -> Option<&T> {
        self.artifacts.get(message_id)
    }

    fn get_all_by_expiry_range<'a>(
        &self,
        range: std::ops::RangeInclusive<Time>,
    ) -> Box<dyn Iterator<Item = &T> + '_> {
        let (start, end) = range.into_inner();
        if end < start {
            return Box::new(std::iter::empty());
        }
        let min_bytes = [0; EXPECTED_MESSAGE_ID_LENGTH];
        let max_bytes = [0xff; EXPECTED_MESSAGE_ID_LENGTH];
        let range = std::ops::RangeInclusive::new(
            IngressMessageId::new(start, MessageId::from(min_bytes)),
            IngressMessageId::new(end, MessageId::from(max_bytes)),
        );
        let artifacts = &self.artifacts;
        Box::new(artifacts.range(range).map(|(_, v)| v))
    }

    fn get_timestamp(&self, message_id: &IngressMessageId) -> Option<Time> {
        self.get(message_id).map(|x| x.timestamp())
    }

    fn size(&self) -> usize {
        self.artifacts.len()
    }
}

#[derive(Clone)]
pub struct IngressPoolImpl {
    validated: IngressPoolSection<ValidatedIngressArtifact>,
    unvalidated: IngressPoolSection<UnvalidatedIngressArtifact>,
    ingress_pool_max_count: usize,
    ingress_pool_max_bytes: usize,
    ingress_messages_throttled: IntCounter,
    node_id: NodeId,
    log: ReplicaLogger,
}

const POOL_INGRESS: &str = "ingress";

impl IngressPoolImpl {
    pub fn new(
        node_id: NodeId,
        config: ArtifactPoolConfig,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> IngressPoolImpl {
        IngressPoolImpl {
            ingress_pool_max_count: config.ingress_pool_max_count,
            ingress_pool_max_bytes: config.ingress_pool_max_bytes,
            ingress_messages_throttled: metrics_registry.int_counter(
                "ingress_messages_throttled",
                "Number of throttled ingress messages",
            ),
            validated: IngressPoolSection::new(
                log.clone(),
                PoolMetrics::new(metrics_registry.clone(), POOL_INGRESS, POOL_TYPE_VALIDATED),
            ),
            unvalidated: IngressPoolSection::new(
                log.clone(),
                PoolMetrics::new(metrics_registry, POOL_INGRESS, POOL_TYPE_UNVALIDATED),
            ),
            node_id,
            log,
        }
    }
}

impl IngressPool for IngressPoolImpl {
    /// Validated Ingress Pool Section
    fn validated(&self) -> &dyn PoolSection<ValidatedIngressArtifact> {
        &self.validated
    }

    /// Unvalidated Ingress Pool
    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedIngressArtifact> {
        &self.unvalidated
    }

    fn exceeds_limit(&self, peer_id: &NodeId) -> bool {
        let counters = self.unvalidated.peer_counters.get_counters(peer_id)
            + self.validated.peer_counters.get_counters(peer_id);

        counters.bytes > self.ingress_pool_max_bytes
            || counters.messages > self.ingress_pool_max_count
    }
}

impl MutablePool<SignedIngress> for IngressPoolImpl {
    type Mutations = Mutations;

    /// Insert a new ingress message in the Ingress Pool and update the
    /// peer_index
    fn insert(&mut self, artifact: UnvalidatedArtifact<SignedIngress>) {
        let peer_id = artifact.peer_id;
        let ingress_pool_obj = IngressPoolObject::new(peer_id, artifact.message);
        let timestamp = artifact.timestamp;
        let size = ingress_pool_obj.count_bytes();

        debug!(
            self.log,
            "ingress_message_insert_unvalidated";
            ingress_message.message_id => format!("{}", ingress_pool_obj.message_id)
        );

        self.unvalidated.insert(
            IngressMessageId::from(&ingress_pool_obj),
            UnvalidatedIngressArtifact {
                message: ingress_pool_obj,
                peer_id,
                timestamp,
            },
        );
        debug!(
            self.log,
            "Ingress pool: insert {} bytes into unvalidated", size
        );
    }

    /// Removes an unvalidated ingress message from the unvalidated section.
    fn remove(&mut self, id: &IngressMessageId) {
        self.unvalidated.remove(id);
    }

    /// Apply changeset to the Ingress Pool
    fn apply(&mut self, change_set: Mutations) -> ArtifactTransmits<SignedIngress> {
        let mut transmits = vec![];
        for change_action in change_set {
            match change_action {
                ChangeAction::MoveToValidated(message_id) => {
                    // Remove it from unvalidated pool and move it to the validated pool
                    match self.unvalidated.remove(&message_id) {
                        Some(unvalidated_artifact) => {
                            // Advertize the artifact only if we got the ingress message from a
                            // boundary node.
                            if unvalidated_artifact.peer_id == self.node_id {
                                transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                                    artifact: unvalidated_artifact.message.signed_ingress.clone(),
                                    is_latency_sensitive: true,
                                }));
                            }
                            self.validated.insert(
                                message_id,
                                ValidatedIngressArtifact {
                                    msg: unvalidated_artifact.message,
                                    timestamp: unvalidated_artifact.timestamp,
                                },
                            );
                        }
                        None => {
                            unreachable!(
                                "Unvalidated entry not found for MoveToValidated: {:?}",
                                message_id
                            );
                        }
                    }
                }
                ChangeAction::RemoveFromUnvalidated(message_id) => {
                    self.unvalidated.remove(&message_id);
                }
                ChangeAction::RemoveFromValidated(message_id) => {
                    if let Some(_artifact) = self.validated.remove(&message_id) {
                        transmits.push(ArtifactTransmit::Abort(message_id));
                    }
                }
                ChangeAction::PurgeBelowExpiry(expiry) => {
                    transmits.extend(
                        self.validated
                            .purge_below(expiry)
                            .map(|i| (&i.msg.signed_ingress).into())
                            .map(ArtifactTransmit::Abort),
                    );
                    let _unused = self.unvalidated.purge_below(expiry);
                }
            }
        }

        ArtifactTransmits {
            transmits,
            poll_immediately: false,
        }
    }
}

impl ValidatedPoolReader<SignedIngress> for IngressPoolImpl {
    fn get(&self, id: &IngressMessageId) -> Option<SignedIngress> {
        self.validated.get(id).map(|a| a.msg.signed_ingress.clone())
    }

    fn get_all_for_broadcast(&self) -> Box<dyn Iterator<Item = SignedIngress>> {
        Box::new(std::iter::empty())
    }
}

impl IngressPoolThrottler for IngressPoolImpl {
    fn exceeds_threshold(&self) -> bool {
        if self.exceeds_limit(&self.node_id) {
            self.ingress_messages_throttled.inc();

            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces::p2p::consensus::MutablePool;
    use ic_interfaces::time_source::TimeSource;
    use ic_limits::MAX_INGRESS_TTL;
    use ic_logger::no_op_logger;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::{ids::node_test_id, messages::SignedIngressBuilder};
    use ic_types::{artifact::IdentifiableArtifact, time::UNIX_EPOCH};
    use rand::Rng;
    use std::time::Duration;

    #[test]
    fn test_insert_in_ingress_pool() {
        with_test_replica_logger(|_log| {
            let mut ingress_pool = IngressPoolSection::new(
                no_op_logger(),
                PoolMetrics::new(MetricsRegistry::new(), POOL_INGRESS, "default"),
            );
            let ingress_msg = SignedIngressBuilder::new().build();
            let message_id = IngressMessageId::from(&ingress_msg);

            ingress_pool.insert(
                message_id,
                UnvalidatedIngressArtifact {
                    message: IngressPoolObject::new(node_test_id(0), ingress_msg),
                    peer_id: node_test_id(0),
                    timestamp: UNIX_EPOCH,
                },
            );
            assert_eq!(ingress_pool.size(), 1);
        });
    }

    #[test]
    fn test_exists() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let time_source = FastForwardTimeSource::new();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);
                let ingress_msg = SignedIngressBuilder::new().nonce(1).build();
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_msg,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                let ingress_msg = SignedIngressBuilder::new().nonce(2).build();
                let message_id = IngressMessageId::from(&ingress_msg);

                ingress_pool.validated.insert(
                    message_id.clone(),
                    ValidatedIngressArtifact {
                        msg: IngressPoolObject::new(node_test_id(0), ingress_msg),
                        timestamp: UNIX_EPOCH,
                    },
                );
                assert!(ingress_pool.validated.artifacts.contains_key(&message_id));
            })
        })
    }

    #[test]
    fn test_not_exists() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let time_source = FastForwardTimeSource::new();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);
                let ingress_msg = SignedIngressBuilder::new().nonce(1).build();
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_msg,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                let ingress_msg = SignedIngressBuilder::new().nonce(2).build();
                let message_id = IngressMessageId::from(&ingress_msg);

                ingress_pool.validated.insert(
                    message_id,
                    ValidatedIngressArtifact {
                        msg: IngressPoolObject::new(node_test_id(0), ingress_msg),
                        timestamp: UNIX_EPOCH,
                    },
                );

                // Ingress message not in the pool
                let ingress_msg = SignedIngressBuilder::new().nonce(3).build();
                assert!(
                    !ingress_pool
                        .validated
                        .artifacts
                        .contains_key(&IngressMessageId::from(&ingress_msg))
                );
            })
        })
    }

    #[test]
    fn test_insert_remove() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let time_source = FastForwardTimeSource::new();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);

                let ingress_msg = SignedIngressBuilder::new().nonce(1).build();
                let message_id = IngressMessageId::from(&ingress_msg);

                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_msg,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                assert!(ingress_pool.unvalidated.artifacts.contains_key(&message_id));

                ingress_pool.remove(&message_id);
                assert!(!ingress_pool.unvalidated.artifacts.contains_key(&message_id));
            })
        })
    }

    #[test]
    fn test_get_all_validated() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let time_source = FastForwardTimeSource::new();
                let time = time_source.get_relative_time();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);

                let max_seconds = 10;
                let range_min = 3;
                let range_max = 7;
                let step = 66; // in seconds
                let range_min = time + Duration::from_secs(range_min * step);
                let range_max = time + Duration::from_secs(range_max * step);
                let range = range_min..=range_max;
                let mut msgs_in_range = Vec::new();
                for i in 0..max_seconds {
                    let expiry = time + Duration::from_secs(i * step);
                    let ingress_msg = SignedIngressBuilder::new().expiry_time(expiry).build();
                    if range.contains(&expiry) {
                        msgs_in_range.push(ingress_msg.clone())
                    }
                    let message_id = IngressMessageId::from(&ingress_msg);
                    ingress_pool.validated.insert(
                        message_id.clone(),
                        ValidatedIngressArtifact {
                            msg: IngressPoolObject::new(node_test_id(0), ingress_msg),
                            timestamp: UNIX_EPOCH,
                        },
                    );
                }
                // empty
                let filtered_msgs = ingress_pool.get_all_for_broadcast();
                assert!(filtered_msgs.count() == 0);
            })
        })
    }

    #[test]
    fn test_timestamp() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let time_source = FastForwardTimeSource::new();
                let time_0 = time_source.get_relative_time();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);
                let ingress_msg_0 = SignedIngressBuilder::new().nonce(1).build();
                let message_id0 = IngressMessageId::from(&ingress_msg_0);

                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_msg_0.clone(),
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });

                let time_1 = time_0 + Duration::from_secs(42);
                time_source.set_time(time_1).unwrap();

                let ingress_msg_1 = SignedIngressBuilder::new().nonce(2).build();
                let message_id1 = IngressMessageId::from(&ingress_msg_1);
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_msg_1,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });

                // Check timestamp is the insertion time.
                assert_eq!(
                    ingress_pool.unvalidated.get_timestamp(&message_id0),
                    Some(time_0)
                );
                assert_eq!(
                    ingress_pool.unvalidated.get_timestamp(&message_id1),
                    Some(time_1)
                );

                let changeset = vec![
                    ChangeAction::MoveToValidated(message_id0.clone()),
                    ChangeAction::RemoveFromUnvalidated(message_id1.clone()),
                ];
                let result = ingress_pool.apply(changeset);

                // Check moved message is returned as an advert
                assert_eq!(result.transmits.len(), 1);
                assert!(
                    matches!(&result.transmits[0], ArtifactTransmit::Deliver(artifact) if
                        IdentifiableArtifact::id(&artifact.artifact) == message_id0
                    )
                );
                assert!(!result.poll_immediately);
                // Check that message is indeed in the pool
                assert_eq!(ingress_msg_0, ingress_pool.get(&message_id0).unwrap());
                // Check timestamp is carried over for msg_0.
                assert_eq!(ingress_pool.unvalidated.get_timestamp(&message_id0), None);
                assert_eq!(
                    ingress_pool.validated.get_timestamp(&message_id0),
                    Some(time_0)
                );
                // Check timestamp is removed for msg_1.
                assert_eq!(ingress_pool.unvalidated.get_timestamp(&message_id1), None);
                assert_eq!(ingress_pool.validated.get_timestamp(&message_id1), None);
            })
        })
    }

    #[test]
    fn test_purge_below() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let time_source = FastForwardTimeSource::new();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);
                let nodes = 10;
                let mut changeset = Mutations::new();
                let ingress_size = 10;
                let mut rng = rand::rng();
                let now = time_source.get_relative_time();
                let cutoff_time = now + MAX_INGRESS_TTL * 3 / 2;
                let initial_count = 1000;
                let mut non_expired_count = 0;
                for i in 0..initial_count {
                    let expiry = Duration::from_millis(
                        rng.r#gen::<u64>() % (3 * (MAX_INGRESS_TTL.as_millis() as u64)),
                    );
                    if now + expiry >= cutoff_time {
                        non_expired_count += 1;
                    }
                    let ingress = SignedIngressBuilder::new()
                        .method_payload(vec![0; ingress_size])
                        .nonce(i as u64)
                        .expiry_time(now + expiry)
                        .build();
                    let message_id = IngressMessageId::from(&ingress);
                    let peer_id = (i % nodes) as u64;
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress,
                        peer_id: node_test_id(peer_id),
                        timestamp: time_source.get_relative_time(),
                    });
                    changeset.push(ChangeAction::MoveToValidated(message_id));
                }
                assert_eq!(ingress_pool.unvalidated().size(), initial_count);
                let result = ingress_pool.apply(changeset);
                assert!(
                    !result
                        .transmits
                        .iter()
                        .any(|x| matches!(x, ArtifactTransmit::Abort(_)))
                );

                // artifacts_with_opt are only created for own node id
                assert_eq!(result.transmits.len(), initial_count / nodes);
                assert!(!result.poll_immediately);
                assert_eq!(ingress_pool.unvalidated().size(), 0);
                assert_eq!(ingress_pool.validated().size(), initial_count);

                let changeset = vec![ChangeAction::PurgeBelowExpiry(cutoff_time)];
                let result = ingress_pool.apply(changeset);
                assert!(
                    !result
                        .transmits
                        .iter()
                        .any(|x| matches!(x, ArtifactTransmit::Deliver(_)))
                );
                assert_eq!(result.transmits.len(), initial_count - non_expired_count);
                assert!(!result.poll_immediately);
                assert_eq!(ingress_pool.validated().size(), non_expired_count);
            })
        })
    }

    #[test]
    fn test_exceeds_threshold_msgcount() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|mut pool_config| {
                // 3 ingress messages, each with 153 bytes (subject to change)
                pool_config.ingress_pool_max_bytes = 153 * 5;
                pool_config.ingress_pool_max_count = 3;
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);
                assert!(!ingress_pool.exceeds_threshold());

                // MESSAGE #1
                insert_validated_artifact(&mut ingress_pool, 2);
                assert!(!ingress_pool.exceeds_threshold());
                // MESSAGE #2
                insert_validated_artifact(&mut ingress_pool, 3);
                assert!(!ingress_pool.exceeds_threshold());
                // MESSAGE #3
                insert_validated_artifact(&mut ingress_pool, 4);
                assert!(!ingress_pool.exceeds_threshold());
                // MESSAGE #4
                insert_validated_artifact(&mut ingress_pool, 5);
                assert!(ingress_pool.exceeds_threshold());
            })
        })
    }

    #[test]
    fn test_exceeds_threshold_bytes() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|mut pool_config| {
                // 3 ingress messages, each with 153 bytes (subject to change)
                pool_config.ingress_pool_max_bytes = 153 * 3;
                pool_config.ingress_pool_max_count = 5;
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);
                assert!(!ingress_pool.exceeds_threshold());

                // MESSAGE #1
                insert_validated_artifact(&mut ingress_pool, 2);
                assert!(!ingress_pool.exceeds_threshold());
                // MESSAGE #2
                insert_validated_artifact(&mut ingress_pool, 3);
                assert!(!ingress_pool.exceeds_threshold());
                // MESSAGE #3
                insert_validated_artifact(&mut ingress_pool, 4);
                assert!(!ingress_pool.exceeds_threshold());
                // MESSAGE #4
                insert_validated_artifact(&mut ingress_pool, 5);
                assert!(ingress_pool.exceeds_threshold());
            })
        })
    }

    #[test]
    fn test_throttling_disabled() {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|mut pool_config| {
                pool_config.ingress_pool_max_count = usize::MAX;
                pool_config.ingress_pool_max_bytes = usize::MAX;
                let time_source = FastForwardTimeSource::new();
                let metrics_registry = MetricsRegistry::new();
                let mut ingress_pool =
                    IngressPoolImpl::new(node_test_id(0), pool_config, metrics_registry, log);

                assert!(!ingress_pool.exceeds_threshold());

                let ingress_msg = fake_ingress_message(2);
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_msg,
                    peer_id: node_test_id(100),
                    timestamp: time_source.get_relative_time(),
                });
                assert!(!ingress_pool.exceeds_threshold());
            })
        })
    }

    fn insert_validated_artifact(ingress_pool: &mut IngressPoolImpl, nonce: u64) {
        insert_validated_artifact_with_timestamps(
            ingress_pool,
            nonce,
            UNIX_EPOCH,
            ic_types::time::expiry_time_from_now(),
        );
    }

    fn insert_validated_artifact_with_timestamps(
        ingress_pool: &mut IngressPoolImpl,
        nonce: u64,
        receive_time: Time,
        expiry_time: Time,
    ) {
        let ingress_msg = fake_ingress_message_with_expiration(nonce, expiry_time);

        let message_id = IngressMessageId::from(&ingress_msg);
        ingress_pool.validated.insert(
            message_id,
            ValidatedIngressArtifact {
                msg: IngressPoolObject::new(node_test_id(0), ingress_msg),
                timestamp: receive_time,
            },
        );
    }

    fn fake_ingress_message(nonce: u64) -> SignedIngress {
        fake_ingress_message_with_expiration(nonce, ic_types::time::expiry_time_from_now())
    }

    fn fake_ingress_message_with_expiration(nonce: u64, expiry_time: Time) -> SignedIngress {
        SignedIngressBuilder::new()
            .nonce(nonce)
            .expiry_time(expiry_time)
            .build()
    }
}
