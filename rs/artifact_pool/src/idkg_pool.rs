//! IDKG artifact pool implementation.
//!
//! 1. IDkgPoolImpl implements the artifact pool. It is made of
//!    two IDkgPoolSection, one each for the validated/unvalidated
//!    sections.
//! 2. InMemoryIDkgPoolSection is the in memory implementation of
//!    IDkgPoolSection. This is a collection of individual IDkgObjectPools,
//!    one for every type of IDkgMessage (dealing, dealing support, etc)

use crate::{
    metrics::{IDkgPoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    IntoInner,
};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_interfaces::p2p::consensus::{
    ArtifactMutation, ArtifactWithOpt, ChangeResult, MutablePool, UnvalidatedArtifact,
    ValidatedPoolReader,
};
use ic_interfaces::{
    idkg::{
        IDkgChangeAction, IDkgChangeSet, IDkgPool, IDkgPoolSection, IDkgPoolSectionOp,
        IDkgPoolSectionOps, MutableIDkgPoolSection,
    },
    time_source::TimeSource,
};
use ic_logger::{info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::{
    idkg::{
        EcdsaSigShare, IDkgArtifactId, IDkgMessage, IDkgMessageType, IDkgPrefixOf, IDkgStats,
        SchnorrSigShare, SigShare, SignedIDkgComplaint, SignedIDkgOpening,
    },
    CatchUpPackage,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgDealingSupport, SignedIDkgDealing};
use prometheus::IntCounter;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use strum::IntoEnumIterator;

const POOL_IDKG: &str = "idkg";

/// Workaround for `IDkgMessage` not implementing `CountBytes`.
#[allow(dead_code)]
const MESSAGE_SIZE_BYTES: usize = 0;

/// The per-artifact type object pool
struct IDkgObjectPool {
    objects: BTreeMap<IDkgMessageId, IDkgMessage>,
    metrics: IDkgPoolMetrics,
    object_type: IDkgMessageType,
}

impl IDkgObjectPool {
    fn new(object_type: IDkgMessageType, metrics: IDkgPoolMetrics) -> Self {
        Self {
            objects: BTreeMap::new(),
            metrics,
            object_type,
        }
    }

    fn insert_object(&mut self, message: IDkgMessage) {
        assert_eq!(IDkgMessageType::from(&message), self.object_type);
        let key = IDkgArtifactId::from(&message);
        if self.objects.insert(key, message).is_none() {
            self.metrics.observe_insert(self.object_type.as_str());
        }
    }

    fn get_object(&self, key: &IDkgMessageId) -> Option<IDkgMessage> {
        self.objects.get(key).cloned()
    }

    fn remove_object(&mut self, key: &IDkgMessageId) -> bool {
        if self.objects.remove(key).is_some() {
            self.metrics.observe_remove(self.object_type.as_str());
            true
        } else {
            false
        }
    }

    fn iter<T: TryFrom<IDkgMessage>>(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, T)> + '_>
    where
        <T as TryFrom<IDkgMessage>>::Error: Debug,
    {
        Box::new(self.objects.iter().map(|(key, object)| {
            let inner = T::try_from(object.clone()).unwrap_or_else(|err| {
                panic!("Failed to convert IDkgMessage to inner type: {:?}", err)
            });
            (key.clone(), inner)
        }))
    }

    fn iter_by_prefix<T: TryFrom<IDkgMessage>>(
        &self,
        prefix: IDkgPrefixOf<T>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, T)> + '_>
    where
        <T as TryFrom<IDkgMessage>>::Error: Debug,
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
                        panic!("Failed to convert IDkgMessage to inner type: {:?}", err)
                    });
                    (key.clone(), inner)
                }),
        )
    }
}

/// The InMemoryIDkgPoolSection is just a collection of per-type
/// object pools. The main role is to route the operations
/// to the appropriate object pool.
struct InMemoryIDkgPoolSection {
    // Per message type artifact map
    object_pools: Vec<(IDkgMessageType, IDkgObjectPool)>,
}

impl InMemoryIDkgPoolSection {
    fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        let metrics = IDkgPoolMetrics::new(metrics_registry, pool, pool_type);
        // Set up the per message type object pools
        let mut object_pools = Vec::new();
        for message_type in IDkgMessageType::iter() {
            object_pools.push((
                message_type,
                IDkgObjectPool::new(message_type, metrics.clone()),
            ));
        }
        Self { object_pools }
    }

    fn get_pool(&self, message_type: IDkgMessageType) -> &IDkgObjectPool {
        self.object_pools
            .iter()
            .find(|(pool_type, _)| *pool_type == message_type)
            .map(|(_, pool)| pool)
            .unwrap()
    }

    fn get_pool_mut(&mut self, message_type: IDkgMessageType) -> &mut IDkgObjectPool {
        self.object_pools
            .iter_mut()
            .find(|(pool_type, _)| *pool_type == message_type)
            .map(|(_, pool)| pool)
            .unwrap()
    }

    fn insert_object(&mut self, message: IDkgMessage) {
        let object_pool = self.get_pool_mut(IDkgMessageType::from(&message));
        object_pool.insert_object(message);
    }

    fn get_object(&self, id: &IDkgMessageId) -> Option<IDkgMessage> {
        let object_pool = self.get_pool(IDkgMessageType::from(id));
        object_pool.get_object(id)
    }

    fn remove_object(&mut self, id: &IDkgMessageId) -> bool {
        let object_pool = self.get_pool_mut(IDkgMessageType::from(id));
        object_pool.remove_object(id)
    }
}

impl IDkgPoolSection for InMemoryIDkgPoolSection {
    fn contains(&self, msg_id: &IDkgMessageId) -> bool {
        self.get_object(msg_id).is_some()
    }

    fn get(&self, msg_id: &IDkgMessageId) -> Option<IDkgMessage> {
        self.get_object(msg_id)
    }

    fn signed_dealings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::Dealing);
        object_pool.iter()
    }

    fn signed_dealings_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SignedIDkgDealing>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::Dealing);
        object_pool.iter_by_prefix(prefix)
    }

    fn dealing_support(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::DealingSupport);
        object_pool.iter()
    }

    fn dealing_support_by_prefix(
        &self,
        prefix: IDkgPrefixOf<IDkgDealingSupport>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::DealingSupport);
        object_pool.iter_by_prefix(prefix)
    }

    fn ecdsa_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaSigShare)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::EcdsaSigShare);
        object_pool.iter()
    }

    fn ecdsa_signature_shares_by_prefix(
        &self,
        prefix: IDkgPrefixOf<EcdsaSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaSigShare)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::EcdsaSigShare);
        object_pool.iter_by_prefix(prefix)
    }

    fn schnorr_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::SchnorrSigShare);
        object_pool.iter()
    }

    fn schnorr_signature_shares_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SchnorrSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::SchnorrSigShare);
        object_pool.iter_by_prefix(prefix)
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SigShare)> + '_> {
        let idkg_pool = self.get_pool(IDkgMessageType::EcdsaSigShare);
        let schnorr_pool = self.get_pool(IDkgMessageType::SchnorrSigShare);
        Box::new(
            idkg_pool
                .iter()
                .map(|(id, share)| (id, SigShare::Ecdsa(share)))
                .chain(
                    schnorr_pool
                        .iter()
                        .map(|(id, share)| (id, SigShare::Schnorr(share))),
                ),
        )
    }

    fn complaints(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgComplaint)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::Complaint);
        object_pool.iter()
    }

    fn complaints_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SignedIDkgComplaint>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgComplaint)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::Complaint);
        object_pool.iter_by_prefix(prefix)
    }

    fn openings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgOpening)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::Opening);
        object_pool.iter()
    }

    fn openings_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SignedIDkgOpening>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgOpening)> + '_> {
        let object_pool = self.get_pool(IDkgMessageType::Opening);
        object_pool.iter_by_prefix(prefix)
    }
}

impl MutableIDkgPoolSection for InMemoryIDkgPoolSection {
    fn mutate(&mut self, ops: IDkgPoolSectionOps) {
        for op in ops.ops {
            match op {
                IDkgPoolSectionOp::Insert(message) => {
                    self.insert_object(message);
                }
                IDkgPoolSectionOp::Remove(id) => {
                    self.remove_object(&id);
                }
            }
        }
    }

    fn as_pool_section(&self) -> &dyn IDkgPoolSection {
        self
    }
}

/// The artifact pool implementation.
pub struct IDkgPoolImpl {
    validated: Box<dyn MutableIDkgPoolSection>,
    unvalidated: Box<dyn MutableIDkgPoolSection>,
    stats: Box<dyn IDkgStats>,
    invalidated_artifacts: IntCounter,
    log: ReplicaLogger,
}

impl IDkgPoolImpl {
    pub fn new(
        config: ArtifactPoolConfig,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        stats: Box<dyn IDkgStats>,
    ) -> Self {
        let validated = match config.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(lmdb_config) => {
                Box::new(crate::lmdb_pool::PersistentIDkgPoolSection::new_idkg_pool(
                    lmdb_config,
                    config.persistent_pool_read_only,
                    log.clone(),
                    metrics_registry.clone(),
                    POOL_IDKG,
                    POOL_TYPE_VALIDATED,
                )) as Box<_>
            }
            _ => Box::new(InMemoryIDkgPoolSection::new(
                metrics_registry.clone(),
                POOL_IDKG,
                POOL_TYPE_VALIDATED,
            )) as Box<_>,
        };
        Self {
            invalidated_artifacts: metrics_registry.int_counter(
                "idkg_invalidated_artifacts",
                "The number of invalidated IDKG artifacts",
            ),
            validated,
            unvalidated: Box::new(InMemoryIDkgPoolSection::new(
                metrics_registry,
                POOL_IDKG,
                POOL_TYPE_UNVALIDATED,
            )),
            stats,
            log,
        }
    }

    // Populates the unvalidated pool with the initial dealings from the CUP.
    pub fn add_initial_dealings(
        &mut self,
        catch_up_package: &CatchUpPackage,
        time_source: &dyn TimeSource,
    ) {
        let block = catch_up_package.content.block.get_value();

        let mut initial_dealings = Vec::new();
        if block.payload.is_summary() {
            let block_payload = block.payload.as_ref();
            if let Some(idkg_summary) = &block_payload.as_summary().idkg {
                initial_dealings = idkg_summary.initial_dkg_dealings().collect();
            }
        }

        if initial_dealings.is_empty() {
            return;
        }

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

            self.insert(UnvalidatedArtifact {
                message: IDkgMessage::Dealing(signed_dealing.clone()),
                peer_id: signed_dealing.dealer_id(),
                timestamp: time_source.get_relative_time(),
            })
        }
    }
}

impl IDkgPool for IDkgPoolImpl {
    fn validated(&self) -> &dyn IDkgPoolSection {
        self.validated.as_pool_section()
    }

    fn unvalidated(&self) -> &dyn IDkgPoolSection {
        self.unvalidated.as_pool_section()
    }

    fn stats(&self) -> &dyn IDkgStats {
        self.stats.as_ref()
    }
}

impl MutablePool<IDkgMessage> for IDkgPoolImpl {
    type ChangeSet = IDkgChangeSet;

    fn insert(&mut self, artifact: UnvalidatedArtifact<IDkgMessage>) {
        let mut ops = IDkgPoolSectionOps::new();
        ops.insert(artifact.into_inner());
        self.unvalidated.mutate(ops);
    }

    fn remove(&mut self, id: &IDkgArtifactId) {
        let mut ops = IDkgPoolSectionOps::new();
        ops.remove(id.clone());
        self.unvalidated.mutate(ops);
    }

    fn apply_changes(&mut self, change_set: IDkgChangeSet) -> ChangeResult<IDkgMessage> {
        let mut unvalidated_ops = IDkgPoolSectionOps::new();
        let mut validated_ops = IDkgPoolSectionOps::new();
        let changed = !change_set.is_empty();
        let mut mutations = vec![];
        for action in change_set {
            match action {
                IDkgChangeAction::AddToValidated(message) => {
                    mutations.push(ArtifactMutation::Insert(ArtifactWithOpt {
                        artifact: message.clone(),
                        is_latency_sensitive: true,
                    }));
                    validated_ops.insert(message);
                }
                IDkgChangeAction::MoveToValidated(message) => {
                    match &message {
                        IDkgMessage::DealingSupport(_)
                        | IDkgMessage::EcdsaSigShare(_)
                        | IDkgMessage::SchnorrSigShare(_)
                        | IDkgMessage::Dealing(_) => (),
                        _ => mutations.push(ArtifactMutation::Insert(ArtifactWithOpt {
                            artifact: message.clone(),
                            // relayed
                            is_latency_sensitive: false,
                        })),
                    }
                    unvalidated_ops.remove(IDkgArtifactId::from(&message));
                    validated_ops.insert(message);
                }
                IDkgChangeAction::RemoveValidated(msg_id) => {
                    mutations.push(ArtifactMutation::Remove(msg_id.clone()));
                    validated_ops.remove(msg_id);
                }
                IDkgChangeAction::RemoveUnvalidated(msg_id) => {
                    unvalidated_ops.remove(msg_id);
                }
                IDkgChangeAction::HandleInvalid(msg_id, msg) => {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid IDKG artifact ({:?}): {:?}", msg, msg_id);
                    if self.unvalidated.as_pool_section().contains(&msg_id) {
                        unvalidated_ops.remove(msg_id);
                    } else if self.validated.as_pool_section().contains(&msg_id) {
                        mutations.push(ArtifactMutation::Remove(msg_id.clone()));
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
            mutations,
            poll_immediately: changed,
        }
    }
}

impl ValidatedPoolReader<IDkgMessage> for IDkgPoolImpl {
    fn get(&self, msg_id: &IDkgMessageId) -> Option<IDkgMessage> {
        self.validated.as_pool_section().get(msg_id)
    }

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = IDkgMessage>> {
        Box::new(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_consensus::{fake::*, IDkgStatsNoOp};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, NODE_6};
    use ic_types::artifact::IdentifiableArtifact;
    use ic_types::consensus::idkg::{dealing_support_prefix, IDkgObject};
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::crypto::{CryptoHash, CryptoHashOf};
    use ic_types::{signature::BasicSignature, time::UNIX_EPOCH, NodeId};
    use std::collections::BTreeSet;

    fn create_idkg_pool(config: ArtifactPoolConfig, log: ReplicaLogger) -> IDkgPoolImpl {
        IDkgPoolImpl::new(
            config,
            log,
            MetricsRegistry::new(),
            Box::new(IDkgStatsNoOp {}),
        )
    }

    fn create_idkg_dealing(transcript_id: IDkgTranscriptId) -> SignedIDkgDealing {
        let mut idkg_dealing = dummy_idkg_dealing_for_tests();
        idkg_dealing.transcript_id = transcript_id;
        SignedIDkgDealing {
            content: idkg_dealing,
            signature: BasicSignature::fake(NODE_1),
        }
    }

    // Checks if the validated/unvalidated pool members are as expected
    fn check_state(
        idkg_pool: &IDkgPoolImpl,
        unvalidated_expected: &[IDkgMessageId],
        validated_expected: &[IDkgMessageId],
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
            idkg_pool
                .unvalidated()
                .signed_dealings()
                .fold(BTreeSet::new(), |mut acc, (id, _)| {
                    acc.insert(id);
                    acc
                });
        let validated =
            idkg_pool
                .validated()
                .signed_dealings()
                .fold(BTreeSet::new(), |mut acc, (id, _)| {
                    acc.insert(id);
                    acc
                });

        assert_eq!(validated.len(), validated_expected.len());
        for id in &validated {
            assert!(validated_expected.contains(id));
            assert!(idkg_pool.get(id).is_some());

            assert!(idkg_pool.validated().contains(id));
            assert!(idkg_pool.validated().get(id).is_some());

            assert!(!idkg_pool.unvalidated().contains(id));
            assert!(idkg_pool.unvalidated().get(id).is_none());
        }

        assert_eq!(unvalidated.len(), unvalidated_expected.len());
        for id in &unvalidated {
            assert!(unvalidated_expected.contains(id));
            assert!(idkg_pool.get(id).is_none());

            assert!(idkg_pool.unvalidated().contains(id));
            assert!(idkg_pool.unvalidated().get(id).is_some());

            assert!(!idkg_pool.validated().contains(id));
            assert!(idkg_pool.validated().get(id).is_none());
        }
    }

    // Verifies the prefix based search
    fn check_search_by_prefix(idkg_pool: &mut IDkgPoolImpl, test_unvalidated: bool) {
        let transcript_10 = dummy_idkg_transcript_id_for_tests(10);
        let transcript_100 = dummy_idkg_transcript_id_for_tests(100);
        let transcript_1000 = dummy_idkg_transcript_id_for_tests(1000);
        let transcript_50 = dummy_idkg_transcript_id_for_tests(50);
        let transcript_2000 = dummy_idkg_transcript_id_for_tests(2000);

        // (transcript Id, dealer_id, signer_id, crypto hash pattern)
        let supports_to_add = [
            // Prefix 1
            (transcript_1000, NODE_1, NODE_2, 1),
            (transcript_1000, NODE_1, NODE_2, 2),
            (transcript_1000, NODE_1, NODE_2, 3),
            // Prefix 2
            (transcript_1000, NODE_2, NODE_3, 4),
            // Prefix 3
            (transcript_10, NODE_3, NODE_4, 5),
            // Prefix 4
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
                idkg_pool.insert(UnvalidatedArtifact {
                    message: IDkgMessage::DealingSupport(support),
                    peer_id: NODE_1,
                    timestamp: UNIX_EPOCH,
                });
            } else {
                let change_set = vec![IDkgChangeAction::AddToValidated(
                    IDkgMessage::DealingSupport(support.clone()),
                )];
                let result = idkg_pool.apply_changes(change_set);
                assert!(!result
                    .mutations
                    .iter()
                    .any(|x| matches!(x, ArtifactMutation::Remove(_))));
                assert!(matches!(
                    &result.mutations[0], ArtifactMutation::Insert(x) if x.artifact.id() == support.message_id()
                ));
                assert!(result.poll_immediately);
            }
        }

        let pool_section = if test_unvalidated {
            idkg_pool.unvalidated()
        } else {
            idkg_pool.validated()
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
    fn test_idkg_object_pool() {
        let metrics_registry = MetricsRegistry::new();
        let metrics = IDkgPoolMetrics::new(metrics_registry, POOL_IDKG, POOL_TYPE_VALIDATED);
        let mut object_pool = IDkgObjectPool::new(IDkgMessageType::Dealing, metrics);

        let key_1 = {
            let dealing =
                IDkgMessage::Dealing(create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100)));
            let key = IDkgArtifactId::from(&dealing);
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(dealing);
            key
        };
        let key_2 = {
            let dealing =
                IDkgMessage::Dealing(create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200)));
            let key = IDkgArtifactId::from(&dealing);
            assert!(object_pool.get_object(&key).is_none());
            object_pool.insert_object(dealing);
            key
        };
        assert!(object_pool.get_object(&key_1).is_some());
        assert!(object_pool.get_object(&key_2).is_some());

        let iter_pool = |object_pool: &IDkgObjectPool| {
            let iter: Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)>> =
                object_pool.iter();
            let mut items: Vec<IDkgMessageId> = Vec::new();
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
    fn test_idkg_object_pool_panic_on_wrong_type() {
        let metrics_registry = MetricsRegistry::new();
        let metrics = IDkgPoolMetrics::new(metrics_registry, POOL_IDKG, POOL_TYPE_VALIDATED);
        let mut object_pool = IDkgObjectPool::new(IDkgMessageType::DealingSupport, metrics);

        let dealing =
            IDkgMessage::Dealing(create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100)));
        object_pool.insert_object(dealing);
    }

    #[test]
    fn test_idkg_pool_insert_remove() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);

                let msg_id_1 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = dealing.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: IDkgMessage::Dealing(dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                let msg_id_2 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = dealing.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: IDkgMessage::Dealing(dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };

                check_state(&idkg_pool, &[msg_id_1.clone(), msg_id_2.clone()], &[]);

                idkg_pool.remove(&msg_id_1);
                check_state(&idkg_pool, &[msg_id_2], &[]);
            })
        })
    }

    #[test]
    fn test_idkg_pool_add_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);

                let msg_id_1 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = dealing.message_id();
                    let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                        dealing,
                    ))];
                    idkg_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = dealing.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: IDkgMessage::Dealing(dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };

                check_state(&idkg_pool, &[msg_id_2], &[msg_id_1]);
            })
        })
    }

    #[test]
    fn test_idkg_pool_move_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);

                let msg_id_1 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = dealing.message_id();
                    let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                        dealing,
                    ))];
                    idkg_pool.apply_changes(change_set);
                    msg_id
                };
                let (msg_id_2, msg_2) = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = dealing.message_id();
                    let msg = IDkgMessage::Dealing(dealing);
                    idkg_pool.insert(UnvalidatedArtifact {
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
                    let msg = IDkgMessage::DealingSupport(support);
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: msg.clone(),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg
                };
                check_state(&idkg_pool, &[msg_id_2.clone()], &[msg_id_1.clone()]);

                let result = idkg_pool.apply_changes(vec![
                    IDkgChangeAction::MoveToValidated(msg_2),
                    IDkgChangeAction::MoveToValidated(msg_3),
                ]);
                assert!(result.mutations.is_empty());
                assert!(result.poll_immediately);
                check_state(&idkg_pool, &[], &[msg_id_1, msg_id_2]);
            })
        })
    }

    #[test]
    fn test_idkg_pool_remove_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);
                let msg_id_1 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = dealing.message_id();
                    let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                        dealing,
                    ))];
                    idkg_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_2 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = dealing.message_id();
                    let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                        dealing,
                    ))];
                    idkg_pool.apply_changes(change_set);
                    msg_id
                };
                let msg_id_3 = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(300));
                    let msg_id = dealing.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: IDkgMessage::Dealing(dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                check_state(
                    &idkg_pool,
                    &[msg_id_3.clone()],
                    &[msg_id_1.clone(), msg_id_2.clone()],
                );

                let result = idkg_pool
                    .apply_changes(vec![IDkgChangeAction::RemoveValidated(msg_id_1.clone())]);
                assert_eq!(result.mutations.len(), 1);
                assert!(
                    matches!(&result.mutations[0], ArtifactMutation::Remove(x) if *x == msg_id_1)
                );
                assert!(result.poll_immediately);
                check_state(&idkg_pool, &[msg_id_3.clone()], &[msg_id_2.clone()]);

                let result = idkg_pool
                    .apply_changes(vec![IDkgChangeAction::RemoveValidated(msg_id_2.clone())]);
                assert_eq!(result.mutations.len(), 1);
                assert!(
                    matches!(&result.mutations[0], ArtifactMutation::Remove(x) if *x == msg_id_2)
                );
                assert!(result.poll_immediately);
                check_state(&idkg_pool, &[msg_id_3], &[]);

                let result = idkg_pool.apply_changes(vec![]);
                assert!(!result.poll_immediately);
            })
        })
    }

    #[test]
    fn test_idkg_pool_remove_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);
                let msg_id = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = dealing.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: IDkgMessage::Dealing(dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                check_state(&idkg_pool, &[msg_id.clone()], &[]);

                let result =
                    idkg_pool.apply_changes(vec![IDkgChangeAction::RemoveUnvalidated(msg_id)]);
                assert!(result.mutations.is_empty());
                assert!(result.poll_immediately);
                check_state(&idkg_pool, &[], &[]);
            })
        })
    }

    #[test]
    fn test_idkg_pool_handle_invalid_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);
                let msg_id = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(200));
                    let msg_id = dealing.message_id();
                    idkg_pool.insert(UnvalidatedArtifact {
                        message: IDkgMessage::Dealing(dealing),
                        peer_id: NODE_1,
                        timestamp: UNIX_EPOCH,
                    });
                    msg_id
                };
                check_state(&idkg_pool, &[msg_id.clone()], &[]);

                idkg_pool.apply_changes(vec![IDkgChangeAction::HandleInvalid(
                    msg_id,
                    "test".to_string(),
                )]);
                check_state(&idkg_pool, &[], &[]);
            })
        })
    }

    #[test]
    fn test_idkg_pool_handle_invalid_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);

                let msg_id = {
                    let dealing = create_idkg_dealing(dummy_idkg_transcript_id_for_tests(100));
                    let msg_id = dealing.message_id();
                    let change_set = vec![IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(
                        dealing,
                    ))];
                    idkg_pool.apply_changes(change_set);
                    msg_id
                };
                check_state(&idkg_pool, &[], &[msg_id.clone()]);

                idkg_pool.apply_changes(vec![IDkgChangeAction::HandleInvalid(
                    msg_id,
                    "test".to_string(),
                )]);
                check_state(&idkg_pool, &[], &[]);
            })
        })
    }

    #[test]
    fn test_idkg_prefix_search_unvalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);
                check_search_by_prefix(&mut idkg_pool, true);
            })
        })
    }

    #[test]
    fn test_idkg_prefix_search_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let mut idkg_pool = create_idkg_pool(pool_config, logger);
                check_search_by_prefix(&mut idkg_pool, false);
            })
        })
    }
}
