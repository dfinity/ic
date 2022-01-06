//! ECDSA artifact pool implementation.
//!
//! 1. EcdsaPoolImpl implements the artifact pool. It is made of
//! two EcdsaPoolSectionImpl, one each for the validated/unvalidated
//! sections.
//! 2. EcdsaPoolSectionImpl is a collection of individual EcdsaObjectPools,
//! one for every type of EcdsaMessage (dealing, dealing support, etc)
//! 3. EcdsaObjectPool is the backend storage for a particular artifact
//! type. This is where the in memory artifacts are actually stored.

use crate::metrics::{PoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED};
use ic_ecdsa_object::EcdsaObject;
use ic_interfaces::artifact_pool::{IntoInner, UnvalidatedArtifact};
use ic_interfaces::ecdsa::{
    EcdsaChangeAction, EcdsaChangeSet, EcdsaPool, EcdsaPoolSection, MutableEcdsaPool,
};
use ic_interfaces::gossip_pool::{EcdsaGossipPool, GossipPool};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::EcdsaMessageId;
use ic_types::consensus::ecdsa::{
    EcdsaDealingSupport, EcdsaMessage, EcdsaMessageHash, EcdsaSigShare, EcdsaSignedDealing,
};
use ic_types::crypto::CryptoHashOf;

use std::collections::BTreeMap;

const POOL_ECDSA: &str = "ecdsa";

/// Workaround for `EcdsaMessage` not implementing `CountBytes`.
#[allow(dead_code)]
const MESSAGE_SIZE_BYTES: usize = 0;

/// The per-artifact type object pool
struct EcdsaObjectPool<T: EcdsaObject> {
    // The key is the hash of the sub-message type in EcdsaMessage.
    objects: BTreeMap<CryptoHashOf<T>, T>,
    metrics: PoolMetrics,
}

impl<T: EcdsaObject> EcdsaObjectPool<T> {
    fn new(metrics: PoolMetrics) -> Self {
        Self {
            objects: BTreeMap::new(),
            metrics,
        }
    }

    fn insert_object(&mut self, object: T) {
        self.metrics.observe_insert(MESSAGE_SIZE_BYTES);
        if self.objects.insert(object.key(), object).is_some() {
            self.metrics.observe_duplicate(MESSAGE_SIZE_BYTES);
        }
    }

    fn get_object(&self, key: &CryptoHashOf<T>) -> Option<T> {
        self.objects.get(key).cloned()
    }

    fn remove_object(&mut self, key: &CryptoHashOf<T>) -> Option<T> {
        self.objects.remove(key).map(|value| {
            self.metrics.observe_remove(MESSAGE_SIZE_BYTES);
            value
        })
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (&CryptoHashOf<T>, &T)> + '_> {
        Box::new(self.objects.iter())
    }
}

/// The EcdsaPoolSectionImpl is just a collection of per-type
/// object pools. The main role is to route the operations
/// to the appropriate object pool.
struct EcdsaPoolSectionImpl {
    signed_dealings: EcdsaObjectPool<EcdsaSignedDealing>,
    dealing_support: EcdsaObjectPool<EcdsaDealingSupport>,
    sig_shares: EcdsaObjectPool<EcdsaSigShare>,
}

impl EcdsaPoolSectionImpl {
    fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        let metrics = PoolMetrics::new(metrics_registry, pool, pool_type);
        Self {
            signed_dealings: EcdsaObjectPool::new(metrics.clone()),
            dealing_support: EcdsaObjectPool::new(metrics.clone()),
            sig_shares: EcdsaObjectPool::new(metrics),
        }
    }

    fn insert_object(&mut self, message: EcdsaMessage) {
        match message {
            EcdsaMessage::EcdsaSignedDealing(object) => self.signed_dealings.insert_object(object),
            EcdsaMessage::EcdsaDealingSupport(object) => self.dealing_support.insert_object(object),
            EcdsaMessage::EcdsaSigShare(object) => self.sig_shares.insert_object(object),
        }
    }

    fn get_object(&self, id: &EcdsaMessageHash) -> Option<EcdsaMessage> {
        match id {
            EcdsaMessageHash::EcdsaSignedDealing(_) => self
                .signed_dealings
                .get_object(&EcdsaSignedDealing::key_from_outer_hash(id))
                .map(|object| object.into_outer()),
            EcdsaMessageHash::EcdsaDealingSupport(_) => self
                .dealing_support
                .get_object(&EcdsaDealingSupport::key_from_outer_hash(id))
                .map(|object| object.into_outer()),
            EcdsaMessageHash::EcdsaSigShare(_) => self
                .sig_shares
                .get_object(&EcdsaSigShare::key_from_outer_hash(id))
                .map(|object| object.into_outer()),
        }
    }

    fn remove_object(&mut self, id: &EcdsaMessageHash) -> Option<EcdsaMessage> {
        match id {
            EcdsaMessageHash::EcdsaSignedDealing(_) => self
                .signed_dealings
                .remove_object(&EcdsaSignedDealing::key_from_outer_hash(id))
                .map(|object| object.into_outer()),
            EcdsaMessageHash::EcdsaDealingSupport(_) => self
                .dealing_support
                .remove_object(&EcdsaDealingSupport::key_from_outer_hash(id))
                .map(|object| object.into_outer()),
            EcdsaMessageHash::EcdsaSigShare(_) => self
                .sig_shares
                .remove_object(&EcdsaSigShare::key_from_outer_hash(id))
                .map(|object| object.into_outer()),
        }
    }
}

impl EcdsaPoolSection for EcdsaPoolSectionImpl {
    fn contains(&self, msg_id: &EcdsaMessageId) -> bool {
        self.get_object(msg_id).is_some()
    }

    fn get(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.get_object(msg_id)
    }

    fn signed_dealings(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, &EcdsaSignedDealing)> + '_> {
        Box::new(self.signed_dealings.iter().map(|(inner_hash, object)| {
            (EcdsaSignedDealing::key_to_outer_hash(inner_hash), object)
        }))
    }

    fn dealing_support(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, &EcdsaDealingSupport)> + '_> {
        Box::new(self.dealing_support.iter().map(|(inner_hash, object)| {
            (EcdsaDealingSupport::key_to_outer_hash(inner_hash), object)
        }))
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, &EcdsaSigShare)> + '_> {
        Box::new(
            self.sig_shares
                .iter()
                .map(|(inner_hash, object)| (EcdsaSigShare::key_to_outer_hash(inner_hash), object)),
        )
    }
}

/// The artifact pool implementation.
pub struct EcdsaPoolImpl {
    validated: EcdsaPoolSectionImpl,
    unvalidated: EcdsaPoolSectionImpl,
    log: ReplicaLogger,
}

impl EcdsaPoolImpl {
    #[allow(dead_code)]
    pub fn new(log: ReplicaLogger, metrics_registry: MetricsRegistry) -> Self {
        Self {
            validated: EcdsaPoolSectionImpl::new(
                metrics_registry.clone(),
                POOL_ECDSA,
                POOL_TYPE_VALIDATED,
            ),
            unvalidated: EcdsaPoolSectionImpl::new(
                metrics_registry,
                POOL_ECDSA,
                POOL_TYPE_UNVALIDATED,
            ),
            log,
        }
    }
}

impl EcdsaPool for EcdsaPoolImpl {
    fn validated(&self) -> &dyn EcdsaPoolSection {
        &self.validated
    }

    fn unvalidated(&self) -> &dyn EcdsaPoolSection {
        &self.unvalidated
    }
}

impl MutableEcdsaPool for EcdsaPoolImpl {
    fn insert(&mut self, artifact: UnvalidatedArtifact<EcdsaMessage>) {
        self.unvalidated.insert_object(artifact.into_inner());
    }

    fn apply_changes(&mut self, change_set: EcdsaChangeSet) {
        for action in change_set {
            match action {
                EcdsaChangeAction::AddToValidated(message) => {
                    self.validated.insert_object(message);
                }
                EcdsaChangeAction::MoveToValidated(ref msg_id) => {
                    if let Some(removed) = self.unvalidated.remove_object(msg_id) {
                        self.validated.insert_object(removed);
                    } else {
                        warn!(
                            self.log,
                            "MoveToValidated:: artifact was not found: {:?}", action
                        );
                    }
                }
                EcdsaChangeAction::RemoveValidated(ref msg_id) => {
                    if self.validated.remove_object(msg_id).is_none() {
                        warn!(
                            self.log,
                            "RemoveValidated:: artifact was not found: {:?}", action
                        );
                    }
                }
                EcdsaChangeAction::RemoveUnvalidated(ref msg_id) => {
                    if self.unvalidated.remove_object(msg_id).is_none() {
                        warn!(
                            self.log,
                            "RemoveUnvalidated:: artifact was not found: {:?}", action
                        );
                    }
                }
                EcdsaChangeAction::HandleInvalid(ref msg_id, _) => {
                    if self.unvalidated.remove_object(msg_id).is_none() {
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
        self.unvalidated.contains(msg_id) || self.validated.contains(msg_id)
    }

    fn get_validated_by_identifier(&self, msg_id: &Self::MessageId) -> Option<EcdsaMessage> {
        self.validated.get(msg_id)
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
    use ic_interfaces::time_source::TimeSource;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::consensus::fake::*;
    use ic_test_utilities::crypto::{
        dummy_idkg_dealing_for_tests, dummy_idkg_transcript_id_for_tests,
    };
    use ic_test_utilities::types::ids::NODE_1;
    use ic_test_utilities::FastForwardTimeSource;
    use ic_types::consensus::ecdsa::EcdsaDealing;
    use ic_types::consensus::BasicSignature;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
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
        unvalidated_expected: &[EcdsaMessageHash],
        validated_expected: &[EcdsaMessageHash],
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
        let metrics = PoolMetrics::new(metrics_registry, POOL_ECDSA, POOL_TYPE_VALIDATED);
        let mut object_pool: EcdsaObjectPool<EcdsaSignedDealing> = EcdsaObjectPool::new(metrics);

        let key_1 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
            let key = ecdsa_dealing.key();
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(ecdsa_dealing);
            key
        };
        let key_2 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(ecdsa_dealing);
            key
        };
        assert!(object_pool.get_object(&key_1).is_some());
        assert!(object_pool.get_object(&key_2).is_some());

        let items: Vec<(&CryptoHashOf<EcdsaSignedDealing>, &EcdsaSignedDealing)> =
            object_pool.iter().collect();
        assert_eq!(items.len(), 2);

        let mut ids = BTreeSet::new();
        ids.insert(items[0].0.clone());
        ids.insert(items[1].0.clone());
        assert!(ids.contains(&key_1));
        assert!(ids.contains(&key_2));

        assert!(object_pool.remove_object(&key_1).is_some());
        assert!(object_pool.get_object(&key_1).is_none());
        assert!(object_pool.remove_object(&key_1).is_none());

        assert!(object_pool.remove_object(&key_2).is_some());
        assert!(object_pool.get_object(&key_2).is_none());
        assert!(object_pool.remove_object(&key_2).is_none());

        let items = object_pool.iter();
        assert_eq!(items.count(), 0);
    }

    #[test]
    fn test_ecdsa_pool_insert() {
        let mut ecdsa_pool = EcdsaPoolImpl::new(
            ic_logger::replica_logger::no_op_logger(),
            MetricsRegistry::new(),
        );
        let time_source = FastForwardTimeSource::new();

        let msg_id_1 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            ecdsa_pool.insert(UnvalidatedArtifact {
                message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                peer_id: NODE_1,
                timestamp: time_source.get_relative_time(),
            });
            msg_id
        };
        let msg_id_2 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            ecdsa_pool.insert(UnvalidatedArtifact {
                message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                peer_id: NODE_1,
                timestamp: time_source.get_relative_time(),
            });
            msg_id
        };

        check_state(&ecdsa_pool, &[msg_id_1, msg_id_2], &[]);
    }

    #[test]
    fn test_ecdsa_pool_add_validated() {
        let mut ecdsa_pool = EcdsaPoolImpl::new(
            ic_logger::replica_logger::no_op_logger(),
            MetricsRegistry::new(),
        );
        let time_source = FastForwardTimeSource::new();

        let msg_id_1 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            let change_set = vec![EcdsaChangeAction::AddToValidated(
                EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
            )];
            ecdsa_pool.apply_changes(change_set);
            msg_id
        };
        let msg_id_2 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            ecdsa_pool.insert(UnvalidatedArtifact {
                message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                peer_id: NODE_1,
                timestamp: time_source.get_relative_time(),
            });
            msg_id
        };

        check_state(&ecdsa_pool, &[msg_id_2], &[msg_id_1]);
    }

    #[test]
    fn test_ecdsa_pool_move_validated() {
        let mut ecdsa_pool = EcdsaPoolImpl::new(
            ic_logger::replica_logger::no_op_logger(),
            MetricsRegistry::new(),
        );
        let time_source = FastForwardTimeSource::new();

        let msg_id_1 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            let change_set = vec![EcdsaChangeAction::AddToValidated(
                EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
            )];
            ecdsa_pool.apply_changes(change_set);
            msg_id
        };
        let msg_id_2 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            ecdsa_pool.insert(UnvalidatedArtifact {
                message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                peer_id: NODE_1,
                timestamp: time_source.get_relative_time(),
            });
            msg_id
        };
        check_state(&ecdsa_pool, &[msg_id_2.clone()], &[msg_id_1.clone()]);

        ecdsa_pool.apply_changes(vec![EcdsaChangeAction::MoveToValidated(msg_id_2.clone())]);
        check_state(&ecdsa_pool, &[], &[msg_id_1, msg_id_2]);
    }

    #[test]
    fn test_ecdsa_pool_remove_validated() {
        let mut ecdsa_pool = EcdsaPoolImpl::new(
            ic_logger::replica_logger::no_op_logger(),
            MetricsRegistry::new(),
        );
        let time_source = FastForwardTimeSource::new();

        let msg_id_1 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            let change_set = vec![EcdsaChangeAction::AddToValidated(
                EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
            )];
            ecdsa_pool.apply_changes(change_set);
            msg_id
        };
        let msg_id_2 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
            let change_set = vec![EcdsaChangeAction::AddToValidated(
                EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
            )];
            ecdsa_pool.apply_changes(change_set);
            msg_id
        };
        let msg_id_3 = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(300));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
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
    }

    #[test]
    fn test_ecdsa_pool_remove_unvalidated() {
        let mut ecdsa_pool = EcdsaPoolImpl::new(
            ic_logger::replica_logger::no_op_logger(),
            MetricsRegistry::new(),
        );
        let time_source = FastForwardTimeSource::new();

        let msg_id = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
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
    }

    #[test]
    fn test_ecdsa_pool_handle_invalid() {
        let mut ecdsa_pool = EcdsaPoolImpl::new(
            ic_logger::replica_logger::no_op_logger(),
            MetricsRegistry::new(),
        );
        let time_source = FastForwardTimeSource::new();

        let msg_id = {
            let ecdsa_dealing = create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
            let key = ecdsa_dealing.key();
            let msg_id = EcdsaSignedDealing::key_to_outer_hash(&key);
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
    }
}
