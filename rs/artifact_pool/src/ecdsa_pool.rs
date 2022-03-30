//! ECDSA artifact pool implementation.
//!
//! 1. EcdsaPoolImpl implements the artifact pool. It is made of
//! two EcdsaPoolSection, one each for the validated/unvalidated
//! sections.
//! 2. InMemoryEcdsaPoolSection is the in memory implementation of
//! EcdsaPoolSection. This is a collection of individual EcdsaObjectPools,
//! one for every type of EcdsaMessage (dealing, dealing support, etc)

use crate::metrics::{EcdsaPoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_ecdsa_object::ecdsa_msg_hash;
use ic_interfaces::artifact_pool::{IntoInner, UnvalidatedArtifact};
use ic_interfaces::ecdsa::{
    EcdsaChangeAction, EcdsaChangeSet, EcdsaPool, EcdsaPoolSection, MutableEcdsaPool,
    MutableEcdsaPoolSection,
};
use ic_interfaces::gossip_pool::{EcdsaGossipPool, GossipPool};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::EcdsaMessageId;
use ic_types::consensus::ecdsa::{
    EcdsaComplaint, EcdsaDealingSupport, EcdsaMessage, EcdsaMessageHash, EcdsaMessageType,
    EcdsaOpening, EcdsaSigShare, EcdsaSignedDealing,
};

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use strum::IntoEnumIterator;

const POOL_ECDSA: &str = "ecdsa";

/// Workaround for `EcdsaMessage` not implementing `CountBytes`.
#[allow(dead_code)]
const MESSAGE_SIZE_BYTES: usize = 0;

/// The per-artifact type object pool
struct EcdsaObjectPool {
    objects: BTreeMap<EcdsaMessageHash, EcdsaMessage>,
    metrics: EcdsaPoolMetrics,
    object_type: EcdsaMessageType,
}

impl EcdsaObjectPool {
    fn new(object_type: EcdsaMessageType, metrics: EcdsaPoolMetrics) -> Self {
        Self {
            objects: BTreeMap::new(),
            metrics,
            object_type,
        }
    }

    fn insert_object(&mut self, message: EcdsaMessage) {
        assert_eq!(EcdsaMessageType::from(&message), self.object_type);
        let key = ecdsa_msg_hash(&message);
        if self.objects.insert(key, message).is_none() {
            self.metrics.observe_insert();
        }
    }

    fn get_object(&self, key: &EcdsaMessageHash) -> Option<EcdsaMessage> {
        self.objects.get(key).cloned()
    }

    fn remove_object(&mut self, key: &EcdsaMessageHash) -> bool {
        if self.objects.remove(key).is_some() {
            self.metrics.observe_remove();
            true
        } else {
            false
        }
    }

    fn iter<T: TryFrom<EcdsaMessage>>(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, T)> + '_>
    where
        <T as TryFrom<EcdsaMessage>>::Error: Debug,
    {
        Box::new(self.objects.iter().map(|(key, object)| {
            let inner = T::try_from(object.clone()).unwrap_or_else(|err| {
                panic!("Failed to convert EcdsaMessage to inner type: {:?}", err)
            });
            (key.clone(), inner)
        }))
    }
}

/// The InMemoryEcdsaPoolSection is just a collection of per-type
/// object pools. The main role is to route the operations
/// to the appropriate object pool.
struct InMemoryEcdsaPoolSection {
    // Per message type artifact map
    object_pools: Vec<(EcdsaMessageType, EcdsaObjectPool)>,
}

impl InMemoryEcdsaPoolSection {
    fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        let metrics = EcdsaPoolMetrics::new(metrics_registry, pool, pool_type);
        // Set up the per message type object pools
        let mut object_pools = Vec::new();
        for message_type in EcdsaMessageType::iter() {
            object_pools.push((
                message_type,
                EcdsaObjectPool::new(message_type, metrics.clone()),
            ));
        }
        Self { object_pools }
    }

    fn get_pool(&self, message_type: EcdsaMessageType) -> &EcdsaObjectPool {
        self.object_pools
            .iter()
            .find(|(pool_type, _)| *pool_type == message_type)
            .map(|(_, pool)| pool)
            .unwrap()
    }

    fn get_pool_mut(&mut self, message_type: EcdsaMessageType) -> &mut EcdsaObjectPool {
        self.object_pools
            .iter_mut()
            .find(|(pool_type, _)| *pool_type == message_type)
            .map(|(_, pool)| pool)
            .unwrap()
    }

    fn insert_object(&mut self, message: EcdsaMessage) {
        let object_pool = self.get_pool_mut(EcdsaMessageType::from(&message));
        object_pool.insert_object(message);
    }

    fn get_object(&self, id: &EcdsaMessageHash) -> Option<EcdsaMessage> {
        let object_pool = self.get_pool(EcdsaMessageType::from(id));
        object_pool.get_object(id)
    }

    fn remove_object(&mut self, id: &EcdsaMessageHash) -> bool {
        let object_pool = self.get_pool_mut(EcdsaMessageType::from(id));
        object_pool.remove_object(id)
    }
}

impl EcdsaPoolSection for InMemoryEcdsaPoolSection {
    fn contains(&self, msg_id: &EcdsaMessageId) -> bool {
        self.get_object(msg_id).is_some()
    }

    fn get(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.get_object(msg_id)
    }

    fn signed_dealings(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSignedDealing)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Dealing);
        object_pool.iter()
    }

    fn dealing_support(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaDealingSupport)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::DealingSupport);
        object_pool.iter()
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSigShare)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::SigShare);
        object_pool.iter()
    }

    fn complaints(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaComplaint)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Complaint);
        object_pool.iter()
    }

    fn openings(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaOpening)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Opening);
        object_pool.iter()
    }
}

impl MutableEcdsaPoolSection for InMemoryEcdsaPoolSection {
    fn insert(&mut self, message: EcdsaMessage) {
        self.insert_object(message)
    }

    fn remove(&mut self, id: &EcdsaMessageId) -> bool {
        self.remove_object(id)
    }

    fn as_pool_section(&self) -> &dyn EcdsaPoolSection {
        self
    }
}

/// The artifact pool implementation.
pub struct EcdsaPoolImpl {
    validated: Box<dyn MutableEcdsaPoolSection>,
    unvalidated: Box<dyn MutableEcdsaPoolSection>,
    log: ReplicaLogger,
}

impl EcdsaPoolImpl {
    pub fn new(
        config: ArtifactPoolConfig,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        let validated = match config.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(lmdb_config) => Box::new(
                crate::lmdb_pool::PersistentEcdsaPoolSection::new_ecdsa_pool(
                    lmdb_config,
                    config.persistent_pool_read_only,
                    log.clone(),
                    metrics_registry.clone(),
                    POOL_ECDSA,
                    POOL_TYPE_VALIDATED,
                ),
            ) as Box<_>,
            _ => Box::new(InMemoryEcdsaPoolSection::new(
                metrics_registry.clone(),
                POOL_ECDSA,
                POOL_TYPE_VALIDATED,
            )) as Box<_>,
        };
        Self {
            validated,
            unvalidated: Box::new(InMemoryEcdsaPoolSection::new(
                metrics_registry,
                POOL_ECDSA,
                POOL_TYPE_UNVALIDATED,
            )),
            log,
        }
    }
}

impl EcdsaPool for EcdsaPoolImpl {
    fn validated(&self) -> &dyn EcdsaPoolSection {
        self.validated.as_pool_section()
    }

    fn unvalidated(&self) -> &dyn EcdsaPoolSection {
        self.unvalidated.as_pool_section()
    }
}

impl MutableEcdsaPool for EcdsaPoolImpl {
    fn insert(&mut self, artifact: UnvalidatedArtifact<EcdsaMessage>) {
        self.unvalidated.insert(artifact.into_inner());
    }

    fn apply_changes(&mut self, change_set: EcdsaChangeSet) {
        for action in change_set {
            match action {
                EcdsaChangeAction::AddToValidated(message) => {
                    self.validated.insert(message);
                }
                EcdsaChangeAction::MoveToValidated(ref msg_id) => {
                    if let Some(removed) = self.unvalidated.as_pool_section().get(msg_id) {
                        if !self.unvalidated.remove(msg_id) {
                            warn!(
                                self.log,
                                "MoveToValidated:: artifact was not found after get: {:?}", action
                            );
                        }
                        self.validated.insert(removed);
                    } else {
                        warn!(
                            self.log,
                            "MoveToValidated:: artifact was not found: {:?}", action
                        );
                    }
                }
                EcdsaChangeAction::RemoveValidated(ref msg_id) => {
                    if !self.validated.remove(msg_id) {
                        warn!(
                            self.log,
                            "RemoveValidated:: artifact was not found: {:?}", action
                        );
                    }
                }
                EcdsaChangeAction::RemoveUnvalidated(ref msg_id) => {
                    if !self.unvalidated.remove(msg_id) {
                        warn!(
                            self.log,
                            "RemoveUnvalidated:: artifact was not found: {:?}", action
                        );
                    }
                }
                EcdsaChangeAction::HandleInvalid(ref msg_id, _) => {
                    if !self.unvalidated.remove(msg_id) && !self.validated.remove(msg_id) {
                        warn!(
                            self.log,
                            "HandleInvalid:: artifact was not found: {:?}", action
                        );
                    }
                }
            }
        }
    }
}

impl GossipPool<EcdsaMessage, EcdsaChangeSet> for EcdsaPoolImpl {
    type MessageId = EcdsaMessageId;
    type Filter = ();

    fn contains(&self, msg_id: &Self::MessageId) -> bool {
        self.unvalidated.as_pool_section().contains(msg_id)
            || self.validated.as_pool_section().contains(msg_id)
    }

    fn get_validated_by_identifier(&self, msg_id: &Self::MessageId) -> Option<EcdsaMessage> {
        self.validated.as_pool_section().get(msg_id)
    }

    fn get_all_validated_by_filter(
        &self,
        _filter: Self::Filter,
    ) -> Box<dyn Iterator<Item = EcdsaMessage>> {
        unimplemented!()
    }
}

impl EcdsaGossipPool for EcdsaPoolImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_ecdsa_object::EcdsaObject;
    use ic_interfaces::time_source::TimeSource;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::consensus::fake::*;
    use ic_test_utilities::crypto::{
        dummy_idkg_dealing_for_tests, dummy_idkg_transcript_id_for_tests,
    };
    use ic_test_utilities::types::ids::NODE_1;
    use ic_test_utilities::with_test_replica_logger;
    use ic_test_utilities::FastForwardTimeSource;
    use ic_types::consensus::ecdsa::EcdsaDealing;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::signature::BasicSignature;
    use ic_types::Height;
    use std::collections::BTreeSet;

    fn create_ecdsa_dealing(transcript_id: IDkgTranscriptId) -> EcdsaSignedDealing {
        let mut idkg_dealing = dummy_idkg_dealing_for_tests();
        idkg_dealing.dealer_id = NODE_1;
        idkg_dealing.transcript_id = transcript_id;
        EcdsaSignedDealing {
            content: EcdsaDealing {
                requested_height: Height::from(10),
                idkg_dealing,
            },
            signature: BasicSignature::fake(NODE_1),
        }
    }

    // Checks if the validated/unvalidated pool members are as expected
    fn check_state(
        ecdsa_pool: &EcdsaPoolImpl,
        unvalidated_expected: &[EcdsaMessageId],
        validated_expected: &[EcdsaMessageId],
    ) {
        let unvalidated_expected =
            unvalidated_expected
                .iter()
                .fold(BTreeSet::new(), |mut acc, id| {
                    acc.insert(id);
                    acc
                });
        let validated_expected = validated_expected
            .iter()
            .fold(BTreeSet::new(), |mut acc, id| {
                acc.insert(id);
                acc
            });

        let unvalidated =
            ecdsa_pool
                .unvalidated()
                .signed_dealings()
                .fold(BTreeSet::new(), |mut acc, (id, _)| {
                    acc.insert(id);
                    acc
                });
        let validated =
            ecdsa_pool
                .validated()
                .signed_dealings()
                .fold(BTreeSet::new(), |mut acc, (id, _)| {
                    acc.insert(id);
                    acc
                });

        assert_eq!(validated.len(), validated_expected.len());
        for id in &validated {
            assert!(validated_expected.contains(id));
            assert!(ecdsa_pool.contains(id));
            assert!(ecdsa_pool.get_validated_by_identifier(id).is_some());

            assert!(ecdsa_pool.validated().contains(id));
            assert!(ecdsa_pool.validated().get(id).is_some());

            assert!(!ecdsa_pool.unvalidated().contains(id));
            assert!(ecdsa_pool.unvalidated().get(id).is_none());
        }

        assert_eq!(unvalidated.len(), unvalidated_expected.len());
        for id in &unvalidated {
            assert!(unvalidated_expected.contains(id));
            assert!(ecdsa_pool.contains(id));
            assert!(ecdsa_pool.get_validated_by_identifier(id).is_none());

            assert!(ecdsa_pool.unvalidated().contains(id));
            assert!(ecdsa_pool.unvalidated().get(id).is_some());

            assert!(!ecdsa_pool.validated().contains(id));
            assert!(ecdsa_pool.validated().get(id).is_none());
        }
    }

    #[test]
    fn test_ecdsa_object_pool() {
        let metrics_registry = MetricsRegistry::new();
        let metrics = EcdsaPoolMetrics::new(metrics_registry, POOL_ECDSA, POOL_TYPE_VALIDATED);
        let mut object_pool = EcdsaObjectPool::new(EcdsaMessageType::Dealing, metrics);

        let key_1 = {
            let ecdsa_dealing = EcdsaMessage::EcdsaSignedDealing(create_ecdsa_dealing(
                dummy_idkg_transcript_id_for_tests(100),
            ));
            let key = ecdsa_msg_hash(&ecdsa_dealing);
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(ecdsa_dealing);
            key
        };
        let key_2 = {
            let ecdsa_dealing = EcdsaMessage::EcdsaSignedDealing(create_ecdsa_dealing(
                dummy_idkg_transcript_id_for_tests(200),
            ));
            let key = ecdsa_msg_hash(&ecdsa_dealing);
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(ecdsa_dealing);
            key
        };
        assert!(object_pool.get_object(&key_1).is_some());
        assert!(object_pool.get_object(&key_2).is_some());

        let iter_pool = |object_pool: &EcdsaObjectPool| {
            let iter: Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSignedDealing)>> =
                object_pool.iter();
            let mut items: Vec<EcdsaMessageHash> = Vec::new();
            for item in iter {
                items.push(item.0);
            }
            items
        };

        let items = iter_pool(&object_pool);
        assert_eq!(items.len(), 2);

        let mut ids = BTreeSet::new();
        ids.insert(items[0].clone());
        ids.insert(items[1].clone());
        assert!(ids.contains(&key_1));
        assert!(ids.contains(&key_2));

        assert!(object_pool.remove_object(&key_1));
        assert!(object_pool.get_object(&key_1).is_none());
        assert!(!object_pool.remove_object(&key_1));

        assert!(object_pool.remove_object(&key_2));
        assert!(object_pool.get_object(&key_2).is_none());
        assert!(!object_pool.remove_object(&key_2));

        let items = iter_pool(&object_pool);
        assert_eq!(items.len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_ecdsa_object_pool_panic_on_wrong_type() {
        let metrics_registry = MetricsRegistry::new();
        let metrics = EcdsaPoolMetrics::new(metrics_registry, POOL_ECDSA, POOL_TYPE_VALIDATED);
        let mut object_pool = EcdsaObjectPool::new(EcdsaMessageType::DealingSupport, metrics);

        let ecdsa_dealing = EcdsaMessage::EcdsaSignedDealing(create_ecdsa_dealing(
            dummy_idkg_transcript_id_for_tests(100),
        ));
        object_pool.insert_object(ecdsa_dealing);
    }

    #[test]
    fn test_ecdsa_pool_insert() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());
                let time_source = FastForwardTimeSource::new();

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };

                check_state(&ecdsa_pool, &[msg_id_1, msg_id_2], &[]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_add_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());
                let time_source = FastForwardTimeSource::new();

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_hash();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };

                check_state(&ecdsa_pool, &[msg_id_2], &[msg_id_1]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_move_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());
                let time_source = FastForwardTimeSource::new();

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_hash();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };
                check_state(&ecdsa_pool, &[msg_id_2.clone()], &[msg_id_1.clone()]);

                ecdsa_pool
                    .apply_changes(vec![EcdsaChangeAction::MoveToValidated(msg_id_2.clone())]);
                check_state(&ecdsa_pool, &[], &[msg_id_1, msg_id_2]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_remove_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());
                let time_source = FastForwardTimeSource::new();

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_hash();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_hash();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_3 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(300));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };
                check_state(
                    &ecdsa_pool,
                    &[msg_id_3.clone()],
                    &[msg_id_1.clone(), msg_id_2.clone()],
                );

                ecdsa_pool.apply_changes(vec![EcdsaChangeAction::RemoveValidated(msg_id_1)]);
                check_state(&ecdsa_pool, &[msg_id_3.clone()], &[msg_id_2.clone()]);

                ecdsa_pool.apply_changes(vec![EcdsaChangeAction::RemoveValidated(msg_id_2)]);
                check_state(&ecdsa_pool, &[msg_id_3], &[]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_remove_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());
                let time_source = FastForwardTimeSource::new();

                let msg_id = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };
                check_state(&ecdsa_pool, &[msg_id.clone()], &[]);

                ecdsa_pool.apply_changes(vec![EcdsaChangeAction::RemoveUnvalidated(msg_id)]);
                check_state(&ecdsa_pool, &[], &[]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_handle_invalid_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());
                let time_source = FastForwardTimeSource::new();

                let msg_id = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_hash();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: time_source.get_relative_time(),
                    });
                    msg_id
                };
                check_state(&ecdsa_pool, &[msg_id.clone()], &[]);

                ecdsa_pool.apply_changes(vec![EcdsaChangeAction::HandleInvalid(
                    msg_id,
                    "test".to_string(),
                )]);
                check_state(&ecdsa_pool, &[], &[]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_handle_invalid_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool =
                    EcdsaPoolImpl::new(pool_config, logger, MetricsRegistry::new());

                let msg_id = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_hash();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                check_state(&ecdsa_pool, &[], &[msg_id.clone()]);

                ecdsa_pool.apply_changes(vec![EcdsaChangeAction::HandleInvalid(
                    msg_id,
                    "test".to_string(),
                )]);
                check_state(&ecdsa_pool, &[], &[]);
            })
        })
    }
}
