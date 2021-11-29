use crate::height_index::HeightIndex;
use crate::metrics::{PoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_crypto::crypto_hash;
use ic_interfaces::{
    certification::{CertificationPool, ChangeAction, ChangeSet, MutableCertificationPool},
    consensus_pool::HeightIndexedPool,
    gossip_pool::{CertificationGossipPool, GossipPool},
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::CertificationMessageId,
    consensus::certification::{
        Certification, CertificationMessage, CertificationMessageHash, CertificationShare,
    },
    consensus::HasHeight,
    Height,
};
use std::collections::HashSet;

/// Certification pool contains 2 types of artifacts: partial and
/// multi-signatures of (height, hash) pairs, where hash corresponds to an
/// execution state.
pub struct CertificationPoolImpl {
    // Unvalidated shares and certifications are stored separately to improve the validation
    // performance by checking for full certifications first.
    unvalidated_shares: HeightIndex<CertificationShare>,
    unvalidated_certifications: HeightIndex<Certification>,

    pub persistent_pool: Box<dyn MutablePoolSection + Send + Sync>,

    unvalidated_pool_metrics: PoolMetrics,
    validated_pool_metrics: PoolMetrics,
}

const POOL_CERTIFICATION: &str = "certification";

impl CertificationPoolImpl {
    pub fn new(
        config: ArtifactPoolConfig,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        let persistent_pool = match config.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(lmdb_config) => Box::new(
                crate::lmdb_pool::PersistentHeightIndexedPool::new_certification_pool(
                    lmdb_config,
                    config.persistent_pool_read_only,
                    log,
                ),
            ) as Box<_>,
            #[cfg(feature = "rocksdb_backend")]
            PersistentPoolBackend::RocksDB(config) => Box::new(
                crate::rocksdb_pool::PersistentHeightIndexedPool::new_certification_pool(
                    config, log,
                ),
            ) as Box<_>,
            #[allow(unreachable_patterns)]
            cfg => {
                unimplemented!("Configuration {:?} is not supported", cfg)
            }
        };

        CertificationPoolImpl {
            unvalidated_shares: HeightIndex::default(),
            unvalidated_certifications: HeightIndex::default(),
            persistent_pool,
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
}

impl MutableCertificationPool for CertificationPoolImpl {
    fn insert(&mut self, msg: CertificationMessage) {
        let height = msg.height();
        match &msg {
            CertificationMessage::CertificationShare(share) => {
                if self.unvalidated_shares.insert(height, share) {
                    self.unvalidated_pool_metrics
                        .received_artifact_bytes
                        .observe(std::mem::size_of_val(share) as f64);
                }
            }
            CertificationMessage::Certification(cert) => {
                if self.unvalidated_certifications.insert(height, cert) {
                    self.unvalidated_pool_metrics
                        .received_artifact_bytes
                        .observe(std::mem::size_of_val(cert) as f64);
                }
            }
        }
    }

    fn apply_changes(&mut self, change_set: ChangeSet) {
        change_set.into_iter().for_each(|action| match action {
            ChangeAction::AddToValidated(msg) => {
                self.validated_pool_metrics
                    .received_artifact_bytes
                    .observe(std::mem::size_of_val(&msg) as f64);
                self.persistent_pool.insert(msg);
            }

            ChangeAction::MoveToValidated(msg) => {
                let height = msg.height();
                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.unvalidated_shares.remove(height, &share);
                        self.validated_pool_metrics
                            .received_artifact_bytes
                            .observe(std::mem::size_of_val(&share) as f64);
                        self.persistent_pool
                            .insert(CertificationMessage::CertificationShare(share));
                    }
                    CertificationMessage::Certification(cert) => {
                        self.unvalidated_certifications.remove(height, &cert);
                        self.validated_pool_metrics
                            .received_artifact_bytes
                            .observe(std::mem::size_of_val(&cert) as f64);
                        self.insert_validated_certification(cert);
                    }
                };
            }

            ChangeAction::RemoveFromUnvalidated(msg) => {
                let height = msg.height();
                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.unvalidated_shares.remove(height, &share)
                    }
                    CertificationMessage::Certification(cert) => {
                        self.unvalidated_certifications.remove(height, &cert)
                    }
                };
            }

            ChangeAction::RemoveAllBelow(height) => {
                self.unvalidated_shares.remove_all_below(height);
                self.unvalidated_certifications.remove_all_below(height);
                self.persistent_pool.purge_below(height);
            }

            ChangeAction::HandleInvalid(msg, _) => {
                let height = msg.height();
                match msg {
                    CertificationMessage::CertificationShare(share) => {
                        self.unvalidated_shares.remove(height, &share);
                    }
                    CertificationMessage::Certification(cert) => {
                        self.unvalidated_certifications.remove(height, &cert);
                    }
                };
            }
        });
    }
}

/// Operations that mutates the persistent pool.
pub trait MutablePoolSection {
    fn insert(&self, message: CertificationMessage);
    fn certifications(&self) -> &dyn HeightIndexedPool<Certification>;
    fn certification_shares(&self) -> &dyn HeightIndexedPool<CertificationShare>;
    fn purge_below(&self, height: Height);
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
        self.unvalidated_shares.lookup(height)
    }

    fn unvalidated_certifications_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &Certification> + '_> {
        self.unvalidated_certifications.lookup(height)
    }

    fn all_heights_with_artifacts(&self) -> Vec<Height> {
        let mut heights: Vec<Height> = self
            .unvalidated_shares
            .heights()
            .cloned()
            .chain(self.unvalidated_certifications.heights().cloned())
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

impl GossipPool<CertificationMessage, ChangeSet> for CertificationPoolImpl {
    type MessageId = CertificationMessageId;
    type Filter = Height;

    fn contains(&self, id: &Self::MessageId) -> bool {
        // TODO: this is a very inefficient implementation as we compute all hashes
        // every time.
        match &id.hash {
            CertificationMessageHash::CertificationShare(hash) => {
                self.unvalidated_shares
                    .lookup(id.height)
                    .any(|share| &crypto_hash(share) == hash)
                    || self
                        .persistent_pool
                        .certification_shares()
                        .get_by_height(id.height)
                        .any(|share| &crypto_hash(&share) == hash)
            }
            CertificationMessageHash::Certification(hash) => {
                self.unvalidated_certifications
                    .lookup(id.height)
                    .any(|cert| &crypto_hash(cert) == hash)
                    || self
                        .persistent_pool
                        .certifications()
                        .get_by_height(id.height)
                        .any(|cert| &crypto_hash(&cert) == hash)
            }
        }
    }

    fn get_validated_by_identifier(&self, id: &Self::MessageId) -> Option<CertificationMessage> {
        match &id.hash {
            CertificationMessageHash::CertificationShare(hash) => self
                .shares_at_height(id.height)
                .find(|share| &crypto_hash(&*share) == hash)
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

    fn get_all_validated_by_filter(
        &self,
        filter: Self::Filter,
    ) -> Box<dyn Iterator<Item = CertificationMessage> + '_> {
        // Return all validated certifications and all shares above the filter
        let min_height = filter.get();
        let all_certs = self
            .validated_certifications()
            .filter(move |cert| cert.height > Height::from(min_height))
            .map(CertificationMessage::Certification);
        let all_shares = self
            .validated_shares()
            .filter(move |share| share.height > Height::from(min_height))
            .map(CertificationMessage::CertificationShare);
        Box::new(all_certs.chain(all_shares))
    }
}

impl CertificationGossipPool for CertificationPoolImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces::certification::{CertificationPool, MutableCertificationPool};
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::consensus::fake::{Fake, FakeSigner};
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{
            certification::{
                Certification, CertificationContent, CertificationMessage, CertificationShare,
            },
            ThresholdSignature, ThresholdSignatureShare,
        },
        crypto::{
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            CryptoHash, Signed,
        },
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

    #[test]
    fn test_certification_pool_inserts() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool =
                CertificationPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            pool.insert(fake_share(1, 0));
            pool.insert(fake_share(2, 1));

            pool.insert(fake_cert(1));
            let mut other = fake_cert(1);
            if let CertificationMessage::Certification(x) = &mut other {
                x.signed.signature.signer = NiDkgId {
                    start_block_height: Height::from(10),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Local,
                };
            }
            pool.insert(other);
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
        })
    }

    #[test]
    fn test_certification_pool_add_to_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool =
                CertificationPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let share_msg = fake_share(7, 0);
            let cert_msg = fake_cert(8);
            pool.apply_changes(vec![
                ChangeAction::AddToValidated(share_msg.clone()),
                ChangeAction::AddToValidated(cert_msg.clone()),
            ]);
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
            let mut pool =
                CertificationPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let share_msg = fake_share(10, 10);
            let cert_msg = fake_cert(20);
            pool.insert(share_msg.clone());
            pool.insert(cert_msg.clone());
            pool.apply_changes(vec![
                ChangeAction::MoveToValidated(share_msg.clone()),
                ChangeAction::MoveToValidated(cert_msg.clone()),
            ]);
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
        });
    }

    #[test]
    fn test_certification_pool_remove_all() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool =
                CertificationPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let share_msg = fake_share(10, 10);
            let cert_msg = fake_cert(10);
            pool.insert(share_msg.clone());
            pool.insert(cert_msg.clone());
            pool.apply_changes(vec![
                ChangeAction::MoveToValidated(share_msg),
                ChangeAction::MoveToValidated(cert_msg),
            ]);
            let share_msg = fake_share(10, 30);
            let cert_msg = fake_cert(10);
            pool.insert(share_msg);
            pool.insert(cert_msg);

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

            pool.apply_changes(vec![ChangeAction::RemoveAllBelow(Height::from(11))]);
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
        });
    }

    #[test]
    fn test_certification_pool_handle_invalid() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut pool =
                CertificationPoolImpl::new(pool_config, no_op_logger(), MetricsRegistry::new());
            let share_msg = fake_share(10, 10);
            pool.insert(share_msg.clone());

            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                1
            );
            pool.apply_changes(vec![ChangeAction::HandleInvalid(
                share_msg,
                "Testing the removal of invalid artifacts".to_string(),
            )]);
            assert_eq!(
                pool.unvalidated_shares_at_height(Height::from(10)).count(),
                0
            );
        });
    }
}
