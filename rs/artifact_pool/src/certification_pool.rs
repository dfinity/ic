use crate::height_index::HeightIndex;
use crate::metrics::{PoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED};
use crate::pool_common::HasLabel;
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_interfaces::p2p::consensus::ArtifactWithOpt;
use ic_interfaces::{
    certification::{CertificationPool, ChangeAction, Mutations},
    consensus_pool::HeightIndexedPool,
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, MutablePool, UnvalidatedArtifact, ValidatedPoolReader,
    },
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::consensus::IsShare;
use ic_types::crypto::crypto_hash;
use ic_types::NodeId;
use ic_types::{
    artifact::CertificationMessageId,
    consensus::certification::{
        Certification, CertificationMessage, CertificationMessageHash, CertificationShare,
    },
    consensus::HasHeight,
    Height,
};
use prometheus::IntCounter;
use std::collections::{BTreeMap, HashSet};

/// Certification pool contains 2 types of artifacts: partial and
/// multi-signatures of (height, hash) pairs, where hash corresponds to an
/// execution state.
pub struct CertificationPoolImpl {
    node_id: NodeId,

    unvalidated_share_index: HeightIndex<CertificationMessageHash>,
    unvalidated_cert_index: HeightIndex<CertificationMessageHash>,
    unvalidated: BTreeMap<CertificationMessageHash, CertificationMessage>,

    pub persistent_pool: Box<dyn MutablePoolSection + Send + Sync>,

    unvalidated_pool_metrics: PoolMetrics,
    validated_pool_metrics: PoolMetrics,
    invalidated_artifacts: IntCounter,

    log: ReplicaLogger,
}

const POOL_CERTIFICATION: &str = "certification";
const CERTIFICATION_ARTIFACT_TYPE: &str = "certification";
const CERTIFICATION_SHARE_ARTIFACT_TYPE: &str = "certification_share";

impl CertificationPoolImpl {
    pub fn new(
        node_id: NodeId,
        config: ArtifactPoolConfig,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        let persistent_pool = match config.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(lmdb_config) => Box::new(
                crate::lmdb_pool::PersistentHeightIndexedPool::new_certification_pool(
                    lmdb_config,
                    config.persistent_pool_read_only,
                    log.clone(),
                ),
            ) as Box<_>,
            #[cfg(target_os = "macos")]
            PersistentPoolBackend::RocksDB(config) => Box::new(
                crate::rocksdb_pool::PersistentHeightIndexedPool::new_certification_pool(
                    config,
                    log.clone(),
                ),
            ) as Box<_>,
            #[allow(unreachable_patterns)]
            cfg => {
                unimplemented!("Configuration {:?} is not supported", cfg)
            }
        };

        CertificationPoolImpl {
            node_id,
            unvalidated_share_index: HeightIndex::default(),
            unvalidated_cert_index: HeightIndex::default(),
            unvalidated: BTreeMap::default(),
            persistent_pool,
            invalidated_artifacts: metrics_registry.int_counter(
                "certification_invalidated_artifacts",
                "The number of invalidated certification artifacts",
            ),
            unvalidated_pool_metrics: PoolMetrics::new(
                metrics_registry.clone(),
                POOL_CERTIFICATION,
                POOL_TYPE_UNVALIDATED,
            ),
            validated_pool_metrics: PoolMetrics::new(
                metrics_registry,
                POOL_CERTIFICATION,
                POOL_TYPE_VALIDATED,
            ),
            log,
        }
    }

    fn validated_certifications(&self) -> Box<dyn Iterator<Item = Certification> + '_> {
        self.persistent_pool.certifications().get_all()
    }

    fn insert_validated_certification(&self, certification: Certification) {
        if let Some(existing_certification) = self
            .persistent_pool
            .certifications()
            .get_by_height(certification.height)
            .next()
        {
            if certification != existing_certification {
                panic!("Certifications are not expected to be added more than once per height.");
            }
        } else {
            self.persistent_pool
                .insert(CertificationMessage::Certification(certification))
        }
    }

    /// Removes all unvalidated artifacts below the given height
    fn remove_all_unvalidated_below(&mut self, height: Height) {
        // remove from unvalidated pool
        let range = (
            std::ops::Bound::Included(Height::from(0)),
            std::ops::Bound::Excluded(height),
        );
        self.unvalidated_share_index
            .range(range)
            .chain(self.unvalidated_cert_index.range(range))
            .for_each(|(_, ids)| {
                for id in ids {
                    self.unvalidated.remove(id);
                }
            });

        // purge indices
        self.unvalidated_share_index.remove_all_below(height);
        self.unvalidated_cert_index.remove_all_below(height);
    }

    fn update_metrics(&self) {
        // Validated artifacts metrics
        self.validated_pool_metrics
            .pool_artifacts
            .with_label_values(&[CERTIFICATION_ARTIFACT_TYPE])
            .set(self.persistent_pool.certifications().size() as i64);
        self.validated_pool_metrics
            .pool_artifacts
            .with_label_values(&[CERTIFICATION_SHARE_ARTIFACT_TYPE])
            .set(self.persistent_pool.certification_shares().size() as i64);

        // Unvalidated artifacts metrics
        self.unvalidated_pool_metrics
            .pool_artifacts
            .with_label_values(&[CERTIFICATION_ARTIFACT_TYPE])
            .set(self.unvalidated_cert_index.size() as i64);
        self.unvalidated_pool_metrics
            .pool_artifacts
            .with_label_values(&[CERTIFICATION_SHARE_ARTIFACT_TYPE])
            .set(self.unvalidated_share_index.size() as i64);
    }
}

impl MutablePool<CertificationMessage> for CertificationPoolImpl {
    type Mutations = Mutations;

    fn insert(&mut self, msg: UnvalidatedArtifact<CertificationMessage>) {
        let label = msg.message.label().to_owned();
        let hash = CertificationMessageHash::from(&msg.message);
        let size = std::mem::size_of_val(&msg.message) as f64;

        if match hash {
            CertificationMessageHash::Certification(_) => self
                .unvalidated_cert_index
                .insert(msg.message.height(), &hash),
            CertificationMessageHash::CertificationShare(_) => self
                .unvalidated_share_index
                .insert(msg.message.height(), &hash),
        } {
            self.unvalidated.insert(hash, msg.message);
            self.unvalidated_pool_metrics
                .received_artifact_bytes
                .with_label_values(&[&label])
                .observe(size);
        }
    }

    fn remove(&mut self, id: &CertificationMessageId) {
        if match id.hash {
            CertificationMessageHash::Certification(_) => self
                .unvalidated_cert_index
                .retain(id.height, |c| c != &id.hash),
            CertificationMessageHash::CertificationShare(_) => self
                .unvalidated_share_index
                .retain(id.height, |c| c != &id.hash),
        } {
            self.unvalidated.remove(&id.hash);
        }
    }

    fn apply(&mut self, change_set: Mutations) -> ArtifactTransmits<CertificationMessage> {
        let changed = !change_set.is_empty();
        let mut transmits = vec![];

        change_set.into_iter().for_each(|action| match action {
            ChangeAction::AddToValidated(msg) => {
                transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                    artifact: msg.clone(),
                    is_latency_sensitive: true,
                }));
                self.validated_pool_metrics
                    .received_artifact_bytes
                    .with_label_values(&[msg.label()])
                    .observe(std::mem::size_of_val(&msg) as f64);
                self.persistent_pool.insert(msg);
            }

            ChangeAction::MoveToValidated(msg) => {
                if !msg.is_share() {
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: msg.clone(),
                        // relayed
                        is_latency_sensitive: false,
                    }));
                }
                let label = msg.label().to_owned();

                self.remove(&CertificationMessageId::from(&msg));
                self.validated_pool_metrics
                    .received_artifact_bytes
                    .with_label_values(&[&label])
                    .observe(std::mem::size_of_val(&msg) as f64);

                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.persistent_pool
                            .insert(CertificationMessage::CertificationShare(share));
                    }
                    CertificationMessage::Certification(cert) => {
                        self.insert_validated_certification(cert);
                    }
                };
            }

            ChangeAction::RemoveFromUnvalidated(msg) => {
                self.remove(&CertificationMessageId::from(&msg));
            }

            ChangeAction::RemoveAllBelow(height) => {
                self.remove_all_unvalidated_below(height);
                transmits.extend(
                    self.persistent_pool
                        .purge_below(height)
                        .drain(..)
                        .map(ArtifactTransmit::Abort),
                );
            }

            ChangeAction::HandleInvalid(msg, reason) => {
                self.invalidated_artifacts.inc();
                warn!(
                    self.log,
                    "Invalid certification message ({:?}): {:?}", reason, msg
                );
                self.remove(&CertificationMessageId::from(&msg));
            }
        });

        if changed {
            self.update_metrics();
        }

        ArtifactTransmits {
            transmits,
            poll_immediately: changed,
        }
    }
}

/// Operations that mutate the persistent pool.
pub trait MutablePoolSection {
    /// Insert a [`CertificationMessage`] into the pool.
    fn insert(&self, message: CertificationMessage);
    /// Lookup a [`CertificationMessage`] by [`CertificationMessageId`]. Return the
    /// certification message if it exists, or None otherwise.
    fn get(&self, msg_id: &CertificationMessageId) -> Option<CertificationMessage>;
    /// Get the height indexed pool section for full [`Certification`]s.
    fn certifications(&self) -> &dyn HeightIndexedPool<Certification>;
    /// Get the height indexed pool section for [`CertificationShare`]s.
    fn certification_shares(&self) -> &dyn HeightIndexedPool<CertificationShare>;
    /// Purge all artifacts below the given [`Height`]. Return the [`CertificationMessageId`]s
    /// of the deleted artifacts.
    fn purge_below(&self, height: Height) -> Vec<CertificationMessageId>;
}

impl CertificationPool for CertificationPoolImpl {
    fn certification_at_height(&self, height: Height) -> Option<Certification> {
        self.persistent_pool
            .certifications()
            .get_by_height(height)
            .next()
    }

    fn shares_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = CertificationShare> + '_> {
        self.persistent_pool
            .certification_shares()
            .get_by_height(height)
    }

    fn validated_shares(&self) -> Box<dyn Iterator<Item = CertificationShare> + '_> {
        self.persistent_pool.certification_shares().get_all()
    }

    fn unvalidated_shares_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &CertificationShare> + '_> {
        Box::new(self.unvalidated_share_index.lookup(height).map(|id| {
            let CertificationMessage::CertificationShare(share) = self
                .unvalidated
                .get(id)
                .expect("value must exist if hash exists")
            else {
                panic!("hash is share, but value is not");
            };
            share
        }))
    }

    fn unvalidated_certifications_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &Certification> + '_> {
        Box::new(self.unvalidated_cert_index.lookup(height).map(|id| {
            let CertificationMessage::Certification(cert) = self
                .unvalidated
                .get(id)
                .expect("value must exist if hash exists")
            else {
                panic!("hash is certification, but value is not");
            };
            cert
        }))
    }

    fn all_heights_with_artifacts(&self) -> Vec<Height> {
        let mut heights: Vec<Height> = self
            .unvalidated_share_index
            .heights()
            .cloned()
            .chain(self.unvalidated_cert_index.heights().cloned())
            .chain(self.validated_shares().map(|share| share.height))
            .chain(
                self.validated_certifications()
                    .map(|certification| certification.height),
            )
            .collect();
        heights.sort_unstable();
        heights.dedup();
        heights
    }

    fn certified_heights(&self) -> HashSet<Height> {
        self.validated_certifications()
            .map(|certification| certification.height)
            .collect()
    }
}

impl ValidatedPoolReader<CertificationMessage> for CertificationPoolImpl {
    fn get(&self, id: &CertificationMessageId) -> Option<CertificationMessage> {
        match &id.hash {
            CertificationMessageHash::CertificationShare(hash) => self
                .shares_at_height(id.height)
                .find(|share| &crypto_hash(share) == hash)
                .map(CertificationMessage::CertificationShare),
            CertificationMessageHash::Certification(hash) => {
                self.certification_at_height(id.height).and_then(|cert| {
                    if &crypto_hash(&cert) == hash {
                        Some(CertificationMessage::Certification(cert))
                    } else {
                        None
                    }
                })
            }
        }
    }

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = CertificationMessage> + '_> {
        let certification_range = self.persistent_pool.certifications().height_range();
        let share_range = self.persistent_pool.certification_shares().height_range();

        let ranges = [certification_range.as_ref(), share_range.as_ref()]
            .into_iter()
            .flatten();
        let Some(min) = ranges.clone().map(|range| range.min).min() else {
            return Box::new(std::iter::empty());
        };
        let max = ranges.map(|range| range.max).max().unwrap_or(min);

        // For all heights above the minimum, return the validated certification of the subnet,
        // or the share signed by this node if we don't have the aggregate.
        let iterator = (min.get()..=max.get()).map(Height::from).flat_map(|h| {
            let mut certifications = self.persistent_pool.certifications().get_by_height(h);
            if let Some(certification) = certifications.next() {
                vec![CertificationMessage::Certification(certification)]
            } else {
                self.persistent_pool
                    .certification_shares()
                    .get_by_height(h)
                    .filter(|share| share.signed.signature.signer == self.node_id)
                    .map(CertificationMessage::CertificationShare)
                    .collect()
            }
        });

        Box::new(iterator)
    }
}

impl HasLabel for CertificationMessage {
    fn label(&self) -> &str {
        match self {
            CertificationMessage::Certification(_) => CERTIFICATION_ARTIFACT_TYPE,
            CertificationMessage::CertificationShare(_) => CERTIFICATION_SHARE_ARTIFACT_TYPE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces::certification::CertificationPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_consensus::fake::{Fake, FakeSigner};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::artifact::IdentifiableArtifact;
    use ic_types::time::UNIX_EPOCH;
    use ic_types::{
        consensus::certification::{
            Certification, CertificationContent, CertificationMessage, CertificationShare,
        },
        crypto::{
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            CryptoHash, Signed,
        },
        signature::*,
        CryptoHashOfPartialState, Height,
    };

    fn gen_content() -> CertificationContent {
        CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(Vec::new())))
    }

    fn fake_share(height: u64, node: u64) -> CertificationMessage {
        let content = gen_content();
        CertificationMessage::CertificationShare(CertificationShare {
            height: Height::from(height),
            signed: Signed {
                signature: ThresholdSignatureShare::fake(node_test_id(node)),
                content,
            },
        })
    }

    fn fake_cert(height: u64) -> CertificationMessage {
        let content = gen_content();
        let signature = ThresholdSignature::fake();
        CertificationMessage::Certification(Certification {
            height: Height::from(height),
            signed: Signed { content, signature },
        })
    }

    fn msg_to_share(msg: CertificationMessage) -> CertificationShare {
        if let CertificationMessage::CertificationShare(x) = msg {
            return x;
        }
        unreachable!("This should be only called on a share message.");
    }

    fn msg_to_cert(msg: CertificationMessage) -> Certification {
        if let CertificationMessage::Certification(x) = msg {
            return x;
        }
        unreachable!("This should be only called on a certification message.");
    }

    fn msg_to_id(msg: &CertificationMessage) -> CertificationMessageId {
        CertificationMessageId::from(msg)
    }

    fn to_unvalidated(message: CertificationMessage) -> UnvalidatedArtifact<CertificationMessage> {
        UnvalidatedArtifact::<CertificationMessage> {
            message,
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        }
    }

    #[test]
    fn test_certification_pool_insert_and_remove() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share1 = fake_share(1, 0);
            let id1 = msg_to_id(&share1);
            let share2 = fake_share(2, 1);
            let id2 = msg_to_id(&share2);
            pool.insert(to_unvalidated(share1));
            pool.insert(to_unvalidated(share2));

            let cert1 = fake_cert(1);
            let id3 = msg_to_id(&cert1);
            pool.insert(to_unvalidated(cert1.clone()));
            let mut cert2 = cert1;
            if let CertificationMessage::Certification(x) = &mut cert2 {
                x.signed.signature.signer = NiDkgId {
                    start_block_height: Height::from(10),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Local,
                };
            }
            let id4 = msg_to_id(&cert2);
            pool.insert(to_unvalidated(cert2));

            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(1)).count(),
                1
            );
            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(2)).count(),
                1
            );
            assert_eq!(
                pool.unvalidated_certifications_at_height(Height::from(1))
                    .count(),
                2
            );
            assert_eq!(
                pool.all_heights_with_artifacts(),
                vec![Height::from(1), Height::from(2)]
            );

            for id in [id1, id2, id3, id4] {
                assert!(pool.unvalidated.contains_key(&id.hash));
                pool.remove(&id);
                assert!(!pool.unvalidated.contains_key(&id.hash));
            }
        })
    }

    #[test]
    fn test_certification_pool_add_to_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share_msg = fake_share(7, 0);
            let cert_msg = fake_cert(8);
            let result = pool.apply(vec![
                ChangeAction::AddToValidated(share_msg.clone()),
                ChangeAction::AddToValidated(cert_msg.clone()),
            ]);
            assert_eq!(result.transmits.len(), 2);
            assert!(!result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Abort(_))));
            assert!(result.poll_immediately);
            assert_eq!(
                pool.certification_at_height(Height::from(8)),
                Some(msg_to_cert(cert_msg))
            );
            assert_eq!(
                pool.validated_shares().collect::<Vec<CertificationShare>>(),
                vec![msg_to_share(share_msg)]
            );
        });
    }

    #[test]
    fn test_certification_pool_move_to_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share_msg = fake_share(10, 10);
            let cert_msg = fake_cert(20);
            pool.insert(to_unvalidated(share_msg.clone()));
            pool.insert(to_unvalidated(cert_msg.clone()));
            let result = pool.apply(vec![
                ChangeAction::MoveToValidated(share_msg.clone()),
                ChangeAction::MoveToValidated(cert_msg.clone()),
            ]);
            let expected = cert_msg.id();
            assert!(
                matches!(&result.transmits[0], ArtifactTransmit::Deliver(x) if x.artifact.id() == expected)
            );
            assert_eq!(result.transmits.len(), 1);
            assert!(result.poll_immediately);
            assert_eq!(
                pool.shares_at_height(Height::from(10))
                    .collect::<Vec<CertificationShare>>(),
                vec![msg_to_share(share_msg)]
            );
            assert_eq!(
                pool.certification_at_height(Height::from(20)),
                Some(msg_to_cert(cert_msg))
            );
            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                0
            );
            assert_eq!(
                pool.unvalidated_certifications_at_height(Height::from(20))
                    .count(),
                0
            );
            // INVARIANT: The sizes the unvalidated pool and the height index must be equal
            assert_eq!(
                pool.unvalidated_share_index.size() + pool.unvalidated_cert_index.size(),
                pool.unvalidated.values().len()
            )
        });
    }

    #[test]
    fn test_certification_pool_remove_all() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share_msg = fake_share(10, 10);
            let cert_msg = fake_cert(10);
            pool.insert(to_unvalidated(share_msg.clone()));
            pool.insert(to_unvalidated(cert_msg.clone()));
            pool.apply(vec![
                ChangeAction::MoveToValidated(share_msg),
                ChangeAction::MoveToValidated(cert_msg),
            ]);
            let share_msg = fake_share(10, 30);
            let cert_msg = fake_cert(10);
            pool.insert(to_unvalidated(share_msg.clone()));
            pool.insert(to_unvalidated(cert_msg.clone()));

            assert_eq!(pool.all_heights_with_artifacts().len(), 1);
            assert_eq!(pool.shares_at_height(Height::from(10)).count(), 1);
            assert!(pool.certification_at_height(Height::from(10)).is_some());
            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                1
            );
            assert_eq!(
                pool.unvalidated_certifications_at_height(Height::from(10))
                    .count(),
                1
            );

            let result = pool.apply(vec![ChangeAction::RemoveAllBelow(Height::from(11))]);
            let mut back_off_factor = 1;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(
                    50 * (1 << back_off_factor),
                ));
                if pool.all_heights_with_artifacts().is_empty() {
                    break;
                }
                back_off_factor += 1;
                if back_off_factor > 6 {
                    panic!("Purging couldn't finish in more than 6 seconds.")
                }
            }
            assert!(!result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Deliver(_))));
            assert_eq!(result.transmits.len(), 2);
            assert!(result.poll_immediately);
            assert_eq!(pool.all_heights_with_artifacts().len(), 0);
            assert_eq!(pool.shares_at_height(Height::from(10)).count(), 0);
            assert!(pool.certification_at_height(Height::from(10)).is_none());
            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                0
            );
            assert_eq!(
                pool.unvalidated_certifications_at_height(Height::from(10))
                    .count(),
                0
            );
            // INVARIANT: The sizes the unvalidated pool and the height index must be equal
            assert_eq!(
                pool.unvalidated_share_index.size() + pool.unvalidated_cert_index.size(),
                pool.unvalidated.values().len()
            )
        });
    }

    #[test]
    fn test_certification_pool_handle_invalid() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share_msg = fake_share(10, 10);
            pool.insert(to_unvalidated(share_msg.clone()));

            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                1
            );
            let result = pool.apply(vec![ChangeAction::HandleInvalid(
                share_msg,
                "Testing the removal of invalid artifacts".to_string(),
            )]);
            assert!(result.transmits.is_empty());
            assert!(result.poll_immediately);
            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                0
            );

            let result = pool.apply(vec![]);
            assert!(!result.poll_immediately);
            // INVARIANT: The sizes the unvalidated pool and the height index must be equal
            assert_eq!(
                pool.unvalidated_share_index.size() + pool.unvalidated_cert_index.size(),
                pool.unvalidated.values().len()
            )
        });
    }

    #[test]
    fn test_certification_pool_contains_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share_msg = fake_share(7, 0);
            let cert_msg = fake_cert(8);

            assert!(!pool
                .unvalidated
                .contains_key(&CertificationMessageId::from(&share_msg).hash));
            assert!(!pool
                .unvalidated
                .contains_key(&CertificationMessageId::from(&cert_msg).hash));

            pool.insert(to_unvalidated(share_msg.clone()));

            assert!(pool
                .unvalidated
                .contains_key(&CertificationMessageId::from(&share_msg).hash));
            assert!(!pool
                .unvalidated
                .contains_key(&CertificationMessageId::from(&cert_msg).hash));
        });
    }

    #[test]
    fn test_certification_pool_contains() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool = CertificationPoolImpl::new(
                node_test_id(0),
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let share_msg = fake_share(7, 0);
            let cert_msg = fake_cert(8);

            assert!(pool
                .persistent_pool
                .get(&CertificationMessageId::from(&share_msg))
                .is_none());
            assert!(pool
                .persistent_pool
                .get(&CertificationMessageId::from(&cert_msg))
                .is_none());

            let result = pool.apply(vec![
                ChangeAction::AddToValidated(share_msg.clone()),
                ChangeAction::AddToValidated(cert_msg.clone()),
            ]);
            assert_eq!(result.transmits.len(), 2);
            assert!(!result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Abort(_))));
            assert!(result.poll_immediately);
            assert_eq!(
                pool.certification_at_height(Height::from(8)),
                Some(msg_to_cert(cert_msg.clone()))
            );
            assert_eq!(
                share_msg,
                pool.persistent_pool
                    .get(&CertificationMessageId::from(&share_msg))
                    .unwrap()
            );
            assert_eq!(
                cert_msg,
                pool.persistent_pool
                    .get(&CertificationMessageId::from(&cert_msg))
                    .unwrap()
            );
        });
    }

    #[test]
    fn test_get_all_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let node = node_test_id(3);
            let mut pool = CertificationPoolImpl::new(
                node,
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            );

            let height_offset = 5_000_000_000;

            // Create shares from 5 nodes for 20 heights, only add an aggregate on even heights.
            let mut messages = Vec::new();
            for h in 1..=20 {
                for i in 1..=5 {
                    messages.push(ChangeAction::AddToValidated(fake_share(
                        height_offset + h,
                        i,
                    )));
                }
                if h % 2 == 0 {
                    messages.push(ChangeAction::AddToValidated(fake_cert(height_offset + h)));
                }
            }

            pool.apply(messages);

            let get_signer = |m: &CertificationMessage| match m {
                CertificationMessage::CertificationShare(x) => x.signed.signature.signer,
                _ => panic!("No signer for aggregate artifacts"),
            };

            let mut heights = HashSet::new();
            pool.get_all_validated().for_each(|m| {
                if m.height().get() % 2 == 0 {
                    assert!(!m.is_share());
                }
                if m.height().get() % 2 != 0 {
                    assert!(m.is_share());
                }
                if m.is_share() {
                    assert_eq!(get_signer(&m), node);
                }
                assert!(heights.insert(m.height()));
            });
            assert_eq!(heights.len(), 20);
            assert_eq!(pool.get_all_validated().count(), 20);
        });
    }
}
