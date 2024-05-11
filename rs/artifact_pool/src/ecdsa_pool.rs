//! ECDSA artifact pool implementation.
//!
//! 1. EcdsaPoolImpl implements the artifact pool. It is made of
//! two EcdsaPoolSection, one each for the validated/unvalidated
//! sections.
//! 2. InMemoryEcdsaPoolSection is the in memory implementation of
//! EcdsaPoolSection. This is a collection of individual EcdsaObjectPools,
//! one for every type of EcdsaMessage (dealing, dealing support, etc)

use crate::{
    metrics::{EcdsaPoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    IntoInner,
};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_interfaces::ecdsa::{
    EcdsaChangeAction, EcdsaChangeSet, EcdsaPool, EcdsaPoolSection, EcdsaPoolSectionOp,
    EcdsaPoolSectionOps, MutableEcdsaPoolSection,
};
use ic_interfaces::p2p::consensus::{
    ArtifactWithOpt, ChangeResult, MutablePool, UnvalidatedArtifact, ValidatedPoolReader,
};
use ic_logger::{info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::{ArtifactKind, EcdsaMessageId};
use ic_types::artifact_kind::EcdsaArtifact;
use ic_types::consensus::{
    idkg::{
        EcdsaArtifactId, EcdsaComplaint, EcdsaMessage, EcdsaMessageType, EcdsaOpening,
        EcdsaPrefixOf, EcdsaSigShare, EcdsaStats,
    },
    CatchUpPackage,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealingSupport, SignedIDkgDealing};
use prometheus::IntCounter;
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
    objects: BTreeMap<EcdsaMessageId, EcdsaMessage>,
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
        let key = EcdsaArtifactId::from(&message);
        if self.objects.insert(key, message).is_none() {
            self.metrics.observe_insert(self.object_type.as_str());
        }
    }

    fn get_object(&self, key: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.objects.get(key).cloned()
    }

    fn remove_object(&mut self, key: &EcdsaMessageId) -> bool {
        if self.objects.remove(key).is_some() {
            self.metrics.observe_remove(self.object_type.as_str());
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

    fn iter_by_prefix<T: TryFrom<EcdsaMessage>>(
        &self,
        prefix: EcdsaPrefixOf<T>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, T)> + '_>
    where
        <T as TryFrom<EcdsaMessage>>::Error: Debug,
    {
        // TODO: currently uses a simple O(n) scheme: iterate to the first match for the prefix
        // and take the following matching items. This avoids any complex two level maps/trie style
        // indexing for partial matching. Since the in memory map is fairly fast, this should not
        // be a problem, revisit if needed.

        // Find the first entry that matches the prefix.
        let prefix_cl = prefix.as_ref().clone();
        let first = self
            .objects
            .iter()
            .skip_while(move |(key, _)| key.prefix() != prefix_cl);

        // Keep collecting while the prefix matches.
        let prefix_cl = prefix.as_ref().clone();
        Box::new(
            first
                .take_while(move |(key, _)| key.prefix() == prefix_cl)
                .map(|(key, object)| {
                    let inner = T::try_from(object.clone()).unwrap_or_else(|err| {
                        panic!("Failed to convert EcdsaMessage to inner type: {:?}", err)
                    });
                    (key.clone(), inner)
                }),
        )
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

    fn get_object(&self, id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        let object_pool = self.get_pool(EcdsaMessageType::from(id));
        object_pool.get_object(id)
    }

    fn remove_object(&mut self, id: &EcdsaMessageId) -> bool {
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
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, SignedIDkgDealing)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Dealing);
        object_pool.iter()
    }

    fn signed_dealings_by_prefix(
        &self,
        prefix: EcdsaPrefixOf<SignedIDkgDealing>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, SignedIDkgDealing)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Dealing);
        object_pool.iter_by_prefix(prefix)
    }

    fn dealing_support(
        &self,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, IDkgDealingSupport)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::DealingSupport);
        object_pool.iter()
    }

    fn dealing_support_by_prefix(
        &self,
        prefix: EcdsaPrefixOf<IDkgDealingSupport>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, IDkgDealingSupport)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::DealingSupport);
        object_pool.iter_by_prefix(prefix)
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSigShare)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::SigShare);
        object_pool.iter()
    }

    fn signature_shares_by_prefix(
        &self,
        prefix: EcdsaPrefixOf<EcdsaSigShare>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaSigShare)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::SigShare);
        object_pool.iter_by_prefix(prefix)
    }

    fn complaints(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaComplaint)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Complaint);
        object_pool.iter()
    }

    fn complaints_by_prefix(
        &self,
        prefix: EcdsaPrefixOf<EcdsaComplaint>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaComplaint)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Complaint);
        object_pool.iter_by_prefix(prefix)
    }

    fn openings(&self) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaOpening)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Opening);
        object_pool.iter()
    }

    fn openings_by_prefix(
        &self,
        prefix: EcdsaPrefixOf<EcdsaOpening>,
    ) -> Box<dyn Iterator<Item = (EcdsaMessageId, EcdsaOpening)> + '_> {
        let object_pool = self.get_pool(EcdsaMessageType::Opening);
        object_pool.iter_by_prefix(prefix)
    }
}

impl MutableEcdsaPoolSection for InMemoryEcdsaPoolSection {
    fn mutate(&mut self, ops: EcdsaPoolSectionOps) {
        for op in ops.ops {
            match op {
                EcdsaPoolSectionOp::Insert(message) => {
                    self.insert_object(message);
                }
                EcdsaPoolSectionOp::Remove(id) => {
                    self.remove_object(&id);
                }
            }
        }
    }

    fn as_pool_section(&self) -> &dyn EcdsaPoolSection {
        self
    }
}

/// The artifact pool implementation.
pub struct EcdsaPoolImpl {
    validated: Box<dyn MutableEcdsaPoolSection>,
    unvalidated: Box<dyn MutableEcdsaPoolSection>,
    stats: Box<dyn EcdsaStats>,
    invalidated_artifacts: IntCounter,
    log: ReplicaLogger,
}

impl EcdsaPoolImpl {
    pub fn new(
        config: ArtifactPoolConfig,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        stats: Box<dyn EcdsaStats>,
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
            invalidated_artifacts: metrics_registry.int_counter(
                "ecdsa_invalidated_artifacts",
                "The number of invalidated ECDSA artifacts",
            ),
            validated,
            unvalidated: Box::new(InMemoryEcdsaPoolSection::new(
                metrics_registry,
                POOL_ECDSA,
                POOL_TYPE_UNVALIDATED,
            )),
            stats,
            log,
        }
    }

    // Populates the validated pool with the initial dealings from the CUP.
    pub fn add_initial_dealings(&mut self, catch_up_package: &CatchUpPackage) {
        let block = catch_up_package.content.block.get_value();

        let mut initial_dealings = Vec::new();
        if block.payload.is_summary() {
            let block_payload = block.payload.as_ref();
            if let Some(ecdsa_summary) = &block_payload.as_summary().ecdsa {
                initial_dealings = ecdsa_summary.initial_dkg_dealings().collect();
            }
        }

        if initial_dealings.is_empty() {
            return;
        }

        let mut change_set = Vec::new();
        for signed_dealing in initial_dealings
            .iter()
            .flat_map(|initial_dealings| initial_dealings.dealings())
        {
            info!(
                self.log,
                "add_initial_dealings(): dealer: {:?}, transcript_id = {:?}",
                signed_dealing.dealer_id(),
                signed_dealing.idkg_dealing().transcript_id,
            );

            change_set.push(EcdsaChangeAction::AddToValidated(
                EcdsaMessage::EcdsaSignedDealing(signed_dealing.clone()),
            ));
        }

        self.apply_changes(change_set);
    }
}

impl EcdsaPool for EcdsaPoolImpl {
    fn validated(&self) -> &dyn EcdsaPoolSection {
        self.validated.as_pool_section()
    }

    fn unvalidated(&self) -> &dyn EcdsaPoolSection {
        self.unvalidated.as_pool_section()
    }

    fn stats(&self) -> &dyn EcdsaStats {
        self.stats.as_ref()
    }
}

impl MutablePool<EcdsaArtifact> for EcdsaPoolImpl {
    type ChangeSet = EcdsaChangeSet;

    fn insert(&mut self, artifact: UnvalidatedArtifact<EcdsaMessage>) {
        let mut ops = EcdsaPoolSectionOps::new();
        ops.insert(artifact.into_inner());
        self.unvalidated.mutate(ops);
    }

    fn remove(&mut self, id: &EcdsaArtifactId) {
        let mut ops = EcdsaPoolSectionOps::new();
        ops.remove(id.clone());
        self.unvalidated.mutate(ops);
    }

    fn apply_changes(&mut self, change_set: EcdsaChangeSet) -> ChangeResult<EcdsaArtifact> {
        let mut unvalidated_ops = EcdsaPoolSectionOps::new();
        let mut validated_ops = EcdsaPoolSectionOps::new();
        let changed = !change_set.is_empty();
        let mut artifacts_with_opt = Vec::new();
        let mut purged = Vec::new();
        for action in change_set {
            match action {
                EcdsaChangeAction::AddToValidated(message) => {
                    artifacts_with_opt.push(ArtifactWithOpt {
                        advert: EcdsaArtifact::message_to_advert(&message),
                        is_latency_sensitive: true,
                    });
                    validated_ops.insert(message);
                }
                EcdsaChangeAction::MoveToValidated(message) => {
                    match &message {
                        EcdsaMessage::EcdsaDealingSupport(_)
                        | EcdsaMessage::EcdsaSigShare(_)
                        | EcdsaMessage::EcdsaSignedDealing(_) => (),
                        _ => artifacts_with_opt.push(ArtifactWithOpt {
                            advert: EcdsaArtifact::message_to_advert(&message),
                            // relayed
                            is_latency_sensitive: false,
                        }),
                    }
                    unvalidated_ops.remove(EcdsaArtifactId::from(&message));
                    validated_ops.insert(message);
                }
                EcdsaChangeAction::RemoveValidated(msg_id) => {
                    purged.push(msg_id.clone());
                    validated_ops.remove(msg_id);
                }
                EcdsaChangeAction::RemoveUnvalidated(msg_id) => {
                    unvalidated_ops.remove(msg_id);
                }
                EcdsaChangeAction::HandleInvalid(msg_id, msg) => {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid ECDSA artifact ({:?}): {:?}", msg, msg_id);
                    if self.unvalidated.as_pool_section().contains(&msg_id) {
                        unvalidated_ops.remove(msg_id);
                    } else if self.validated.as_pool_section().contains(&msg_id) {
                        purged.push(msg_id.clone());
                        validated_ops.remove(msg_id);
                    } else {
                        warn!(
                            self.log,
                            "HandleInvalid:: artifact was not found: msg_id = {msg_id:?}, msg = {msg}"
                        );
                    }
                }
            }
        }

        self.unvalidated.mutate(unvalidated_ops);
        self.validated.mutate(validated_ops);
        ChangeResult {
            purged,
            artifacts_with_opt,
            poll_immediately: changed,
        }
    }
}

impl ValidatedPoolReader<EcdsaArtifact> for EcdsaPoolImpl {
    fn get(&self, msg_id: &EcdsaMessageId) -> Option<EcdsaMessage> {
        self.validated.as_pool_section().get(msg_id)
    }

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = EcdsaMessage>> {
        Box::new(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_consensus::{fake::*, EcdsaStatsNoOp};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{
        subnet_test_id, NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, NODE_6,
    };
    use ic_types::consensus::idkg::{dealing_support_prefix, EcdsaObject};
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::crypto::{CryptoHash, CryptoHashOf};
    use ic_types::{signature::BasicSignature, time::UNIX_EPOCH, Height, NodeId};
    use std::collections::BTreeSet;

    fn create_ecdsa_pool(config: ArtifactPoolConfig, log: ReplicaLogger) -> EcdsaPoolImpl {
        EcdsaPoolImpl::new(
            config,
            log,
            MetricsRegistry::new(),
            Box::new(EcdsaStatsNoOp {}),
        )
    }

    fn create_ecdsa_dealing(transcript_id: IDkgTranscriptId) -> SignedIDkgDealing {
        let mut idkg_dealing = dummy_idkg_dealing_for_tests();
        idkg_dealing.transcript_id = transcript_id;
        SignedIDkgDealing {
            content: idkg_dealing,
            signature: BasicSignature::fake(NODE_1),
        }
    }

    fn dummy_idkg_transcript_id_for_tests_with_height(id: u64, height: u64) -> IDkgTranscriptId {
        IDkgTranscriptId::new(subnet_test_id(1), id, Height::from(height))
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
            assert!(ecdsa_pool.get(id).is_some());

            assert!(ecdsa_pool.validated().contains(id));
            assert!(ecdsa_pool.validated().get(id).is_some());

            assert!(!ecdsa_pool.unvalidated().contains(id));
            assert!(ecdsa_pool.unvalidated().get(id).is_none());
        }

        assert_eq!(unvalidated.len(), unvalidated_expected.len());
        for id in &unvalidated {
            assert!(unvalidated_expected.contains(id));
            assert!(ecdsa_pool.get(id).is_none());

            assert!(ecdsa_pool.unvalidated().contains(id));
            assert!(ecdsa_pool.unvalidated().get(id).is_some());

            assert!(!ecdsa_pool.validated().contains(id));
            assert!(ecdsa_pool.validated().get(id).is_none());
        }
    }

    // Verifies the prefix based search
    fn check_search_by_prefix(ecdsa_pool: &mut EcdsaPoolImpl, test_unvalidated: bool) {
        let transcript_10 = dummy_idkg_transcript_id_for_tests_with_height(10, 20);
        let transcript_100 = dummy_idkg_transcript_id_for_tests_with_height(100, 20);
        let transcript_1000 = dummy_idkg_transcript_id_for_tests_with_height(1000, 20);
        // Same transcript Id but higher source transcript height
        let transcript_1000_h = dummy_idkg_transcript_id_for_tests_with_height(1000, 40);
        let transcript_50 = dummy_idkg_transcript_id_for_tests_with_height(50, 20);
        let transcript_2000 = dummy_idkg_transcript_id_for_tests_with_height(2000, 20);

        // (transcript Id, dealer_id, signer_id, crypto hash pattern)
        let supports_to_add = [
            // Prefix 1
            (transcript_1000, NODE_1, NODE_2, 1),
            (transcript_1000, NODE_1, NODE_2, 2),
            (transcript_1000, NODE_1, NODE_2, 3),
            // Prefix 2 (higher source transcript height)
            (transcript_1000_h, NODE_1, NODE_2, 3),
            // Prefix 3
            (transcript_1000, NODE_2, NODE_3, 4),
            // Prefix 4
            (transcript_10, NODE_3, NODE_4, 5),
            // Prefix 5
            (transcript_100, NODE_5, NODE_6, 6),
            (transcript_100, NODE_5, NODE_6, 7),
        ];

        for (transcript_id, dealer_id, signer_id, hash) in &supports_to_add {
            let support = IDkgDealingSupport {
                transcript_id: *transcript_id,
                dealer_id: *dealer_id,
                dealing_hash: CryptoHashOf::new(CryptoHash(vec![*hash; 32])),
                sig_share: BasicSignature::fake(*signer_id),
            };
            if test_unvalidated {
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaDealingSupport(support),
                    peer_id: NODE_1,
                    timestamp: UNIX_EPOCH,
                });
            } else {
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaDealingSupport(support.clone()),
                )];
                let result = ecdsa_pool.apply_changes(change_set);
                assert!(result.purged.is_empty());
                assert_eq!(result.artifacts_with_opt[0].advert.id, support.message_id());
                assert!(result.poll_immediately);
            }
        }

        let pool_section = if test_unvalidated {
            ecdsa_pool.unvalidated()
        } else {
            ecdsa_pool.validated()
        };

        // Verify iteration produces artifacts in increasing order of
        // transcript Id.
        let ret: Vec<IDkgTranscriptId> = pool_section
            .dealing_support()
            .map(|(_, support)| support.transcript_id)
            .collect();
        let expected = vec![
            transcript_10,
            transcript_100,
            transcript_100,
            transcript_1000,
            transcript_1000,
            transcript_1000,
            transcript_1000,
            transcript_1000_h,
        ];
        assert_eq!(ret, expected);

        // Verify by prefixes
        type RetType = (IDkgTranscriptId, NodeId, NodeId, u8);
        let ret_fn = |support: &IDkgDealingSupport| -> RetType {
            (
                support.transcript_id,
                support.dealer_id,
                support.sig_share.signer,
                support.dealing_hash.as_ref().0[0],
            )
        };

        let mut ret: Vec<RetType> = pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_1000, &NODE_1, &NODE_2))
            .map(|(_, support)| (ret_fn)(&support))
            .collect();
        ret.sort();
        assert_eq!(
            ret,
            vec![
                (transcript_1000, NODE_1, NODE_2, 1),
                (transcript_1000, NODE_1, NODE_2, 2),
                (transcript_1000, NODE_1, NODE_2, 3),
            ]
        );

        let ret: Vec<RetType> = pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_1000_h, &NODE_1, &NODE_2))
            .map(|(_, support)| (ret_fn)(&support))
            .collect();
        assert_eq!(ret, vec![(transcript_1000_h, NODE_1, NODE_2, 3)]);

        let ret: Vec<RetType> = pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_1000, &NODE_2, &NODE_3))
            .map(|(_, support)| (ret_fn)(&support))
            .collect();
        assert_eq!(ret, vec![(transcript_1000, NODE_2, NODE_3, 4)]);

        let ret: Vec<RetType> = pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_10, &NODE_3, &NODE_4))
            .map(|(_, support)| (ret_fn)(&support))
            .collect();
        assert_eq!(ret, vec![(transcript_10, NODE_3, NODE_4, 5)]);

        let mut ret: Vec<RetType> = pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_100, &NODE_5, &NODE_6))
            .map(|(_, support)| (ret_fn)(&support))
            .collect();
        ret.sort();
        assert_eq!(
            ret,
            vec![
                (transcript_100, NODE_5, NODE_6, 6),
                (transcript_100, NODE_5, NODE_6, 7),
            ]
        );

        assert!(pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_50, &NODE_5, &NODE_6))
            .next()
            .is_none());

        assert!(pool_section
            .dealing_support_by_prefix(dealing_support_prefix(&transcript_2000, &NODE_1, &NODE_2))
            .next()
            .is_none());
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
            let key = EcdsaArtifactId::from(&ecdsa_dealing);
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(ecdsa_dealing);
            key
        };
        let key_2 = {
            let ecdsa_dealing = EcdsaMessage::EcdsaSignedDealing(create_ecdsa_dealing(
                dummy_idkg_transcript_id_for_tests(200),
            ));
            let key = EcdsaArtifactId::from(&ecdsa_dealing);
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(ecdsa_dealing);
            key
        };
        assert!(object_pool.get_object(&key_1).is_some());
        assert!(object_pool.get_object(&key_2).is_some());

        let iter_pool = |object_pool: &EcdsaObjectPool| {
            let iter: Box<dyn Iterator<Item = (EcdsaMessageId, SignedIDkgDealing)>> =
                object_pool.iter();
            let mut items: Vec<EcdsaMessageId> = Vec::new();
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
    fn test_ecdsa_pool_insert_remove() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_id();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_id();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };

                check_state(&ecdsa_pool, &[msg_id_1.clone(), msg_id_2.clone()], &[]);

                ecdsa_pool.remove(&msg_id_1);
                check_state(&ecdsa_pool, &[msg_id_2], &[]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_add_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_id();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_id();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
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
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);

                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_id();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let (msg_id_2, msg_2) = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_id();
                    let msg = EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing);
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: msg.clone(),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    (msg_id, msg)
                };
                let msg_3 = {
                    let support = IDkgDealingSupport {
                        transcript_id: dummy_idkg_transcript_id_for_tests(100),
                        dealer_id: NODE_2,
                        dealing_hash: CryptoHashOf::new(CryptoHash(vec![1])),
                        sig_share: BasicSignature::fake(NODE_2),
                    };
                    let msg = EcdsaMessage::EcdsaDealingSupport(support);
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: msg.clone(),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg
                };
                check_state(&ecdsa_pool, &[msg_id_2.clone()], &[msg_id_1.clone()]);

                let result = ecdsa_pool.apply_changes(vec![
                    EcdsaChangeAction::MoveToValidated(msg_2),
                    EcdsaChangeAction::MoveToValidated(msg_3),
                ]);
                assert!(result.purged.is_empty());
                // No artifacts_with_opt are created for moved dealings and dealing support
                assert!(result.artifacts_with_opt.is_empty());
                assert!(result.poll_immediately);
                check_state(&ecdsa_pool, &[], &[msg_id_1, msg_id_2]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_remove_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);
                let msg_id_1 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_id();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_id();
                    let change_set = vec![EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                    )];
                    ecdsa_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_3 = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(300));
                    let msg_id = ecdsa_dealing.message_id();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                check_state(
                    &ecdsa_pool,
                    &[msg_id_3.clone()],
                    &[msg_id_1.clone(), msg_id_2.clone()],
                );

                let result = ecdsa_pool
                    .apply_changes(vec![EcdsaChangeAction::RemoveValidated(msg_id_1.clone())]);
                assert!(result.artifacts_with_opt.is_empty());
                assert_eq!(result.purged, vec![msg_id_1]);
                assert!(result.poll_immediately);
                check_state(&ecdsa_pool, &[msg_id_3.clone()], &[msg_id_2.clone()]);

                let result = ecdsa_pool
                    .apply_changes(vec![EcdsaChangeAction::RemoveValidated(msg_id_2.clone())]);
                assert!(result.artifacts_with_opt.is_empty());
                assert_eq!(result.purged, vec![msg_id_2]);
                assert!(result.poll_immediately);
                check_state(&ecdsa_pool, &[msg_id_3], &[]);

                let result = ecdsa_pool.apply_changes(vec![]);
                assert!(!result.poll_immediately);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_remove_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);
                let msg_id = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_id();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                check_state(&ecdsa_pool, &[msg_id.clone()], &[]);

                let result =
                    ecdsa_pool.apply_changes(vec![EcdsaChangeAction::RemoveUnvalidated(msg_id)]);
                assert!(result.purged.is_empty());
                assert!(result.artifacts_with_opt.is_empty());
                assert!(result.poll_immediately);
                check_state(&ecdsa_pool, &[], &[]);
            })
        })
    }

    #[test]
    fn test_ecdsa_pool_handle_invalid_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);
                let msg_id = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = ecdsa_dealing.message_id();
                    ecdsa_pool.insert(UnvalidatedArtifact {
                        message: EcdsaMessage::EcdsaSignedDealing(ecdsa_dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
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
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);

                let msg_id = {
                    let ecdsa_dealing =
                        create_ecdsa_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = ecdsa_dealing.message_id();
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

    #[test]
    fn test_ecdsa_prefix_search_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);
                check_search_by_prefix(&mut ecdsa_pool, true);
            })
        })
    }

    #[test]
    fn test_ecdsa_prefix_search_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut ecdsa_pool = create_ecdsa_pool(pool_config, logger);
                check_search_by_prefix(&mut ecdsa_pool, false);
            })
        })
    }
}
