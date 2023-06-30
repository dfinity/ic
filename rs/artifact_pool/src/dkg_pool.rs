use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::PoolSection,
};
use ic_interfaces::{
    artifact_pool::{
        ChangeResult, MutablePool, UnvalidatedArtifact, ValidatedArtifact, ValidatedPoolReader,
    },
    dkg::{ChangeAction, ChangeSet, DkgPool},
    time_source::TimeSource,
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{ArtifactKind, DkgMessageId},
    artifact_kind::DkgArtifact,
    consensus,
    consensus::dkg,
    crypto::CryptoHashOf,
    time::{current_time, Time},
    Height,
};
use prometheus::IntCounter;
use std::time::Duration;

/// The DkgPool is used to store messages that are exchanged between replicas in
/// the process of executing DKG.
pub struct DkgPoolImpl {
    validated: PoolSection<
        CryptoHashOf<consensus::dkg::Message>,
        ValidatedArtifact<consensus::dkg::Message>,
    >,
    unvalidated: PoolSection<
        CryptoHashOf<consensus::dkg::Message>,
        UnvalidatedArtifact<consensus::dkg::Message>,
    >,
    invalidated_artifacts: IntCounter,
    current_start_height: Height,
    log: ReplicaLogger,
}

const POOL_DKG: &str = "dkg";

impl DkgPoolImpl {
    /// Instantiates a new DKG pool from the time source.
    pub fn new(metrics_registry: MetricsRegistry, log: ReplicaLogger) -> Self {
        Self {
            invalidated_artifacts: metrics_registry.int_counter(
                "dkg_invalidated_artifacts",
                "The number of invalidated DKG artifacts",
            ),
            validated: PoolSection::new(metrics_registry.clone(), POOL_DKG, POOL_TYPE_VALIDATED),
            unvalidated: PoolSection::new(metrics_registry, POOL_DKG, POOL_TYPE_UNVALIDATED),
            current_start_height: Height::from(1),
            log,
        }
    }

    /// Returns a DKG message by hash if available in either the validated or
    /// unvalidated sections.
    pub fn get(&self, hash: &CryptoHashOf<consensus::dkg::Message>) -> Option<&dkg::Message> {
        self.validated
            .get(hash)
            .map(|artifact| artifact.as_ref())
            .or_else(|| self.unvalidated.get(hash).map(|pa| &pa.message))
    }

    /// Deletes all validated and unvalidated messages, which do not correspond
    /// to the current DKG interval. Return the Ids of validated messages that were
    /// purged
    fn purge(&mut self, height: Height) -> Vec<DkgMessageId> {
        self.current_start_height = height;
        // TODO: use drain_filter once it's stable.
        let unvalidated_keys: Vec<_> = self
            .unvalidated
            .iter()
            .filter(|(_, artifact)| artifact.message.content.dkg_id.start_block_height < height)
            .map(|(hash, _)| hash)
            .cloned()
            .collect();
        for hash in unvalidated_keys {
            self.unvalidated.remove(&hash);
        }

        let validated_keys: Vec<_> = self
            .validated
            .iter()
            .filter(|(_, artifact)| artifact.msg.content.dkg_id.start_block_height < height)
            .map(|(hash, _)| hash)
            .cloned()
            .collect();
        for hash in &validated_keys {
            self.validated.remove(hash);
        }
        validated_keys
    }

    /// Returns the validated entries that have creation timestamp <= timestamp
    fn entries_older_than(&self, timestamp: Time) -> Box<dyn Iterator<Item = &dkg::Message> + '_> {
        Box::new(
            self.validated
                .values()
                .filter(move |artifact| artifact.timestamp <= timestamp)
                .map(|artifact| artifact.as_ref()),
        )
    }
}

impl MutablePool<DkgArtifact, ChangeSet> for DkgPoolImpl {
    /// Inserts an unvalidated artifact into the unvalidated section.
    fn insert(&mut self, artifact: UnvalidatedArtifact<consensus::dkg::Message>) {
        self.unvalidated
            .insert(ic_types::crypto::crypto_hash(&artifact.message), artifact);
    }

    /// Applies the provided change set atomically.
    ///
    /// # Panics
    ///
    /// It panics if we pass a hash for an artifact to be moved into the
    /// validated section, but it cannot be found in the unvalidated
    /// section.
    fn apply_changes(
        &mut self,
        _time_source: &dyn TimeSource,
        change_set: ChangeSet,
    ) -> ChangeResult<DkgArtifact> {
        let changed = !change_set.is_empty();
        let mut adverts = Vec::new();
        let mut purged = Vec::new();
        for action in change_set {
            match action {
                ChangeAction::HandleInvalid(hash, reason) => {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid DKG message ({:?}): {:?}", reason, hash);
                    self.unvalidated.remove(&hash);
                }
                ChangeAction::AddToValidated(message) => {
                    adverts.push(DkgArtifact::message_to_advert(&message));
                    self.validated.insert(
                        ic_types::crypto::crypto_hash(&message),
                        ValidatedArtifact {
                            msg: message,
                            timestamp: current_time(),
                        },
                    );
                }
                ChangeAction::MoveToValidated(message) => {
                    adverts.push(DkgArtifact::message_to_advert(&message));
                    let hash = ic_types::crypto::crypto_hash(&message);
                    self.unvalidated
                        .remove(&hash)
                        .expect("Unvalidated artifact was not found.");
                    self.validated.insert(
                        hash,
                        ValidatedArtifact {
                            msg: message,
                            timestamp: current_time(),
                        },
                    );
                }
                ChangeAction::RemoveFromUnvalidated(message) => {
                    let hash = ic_types::crypto::crypto_hash(&message);
                    self.unvalidated
                        .remove(&hash)
                        .expect("Unvalidated artifact was not found.");
                }
                ChangeAction::Purge(height) => purged.append(&mut self.purge(height)),
            }
        }
        ChangeResult {
            purged,
            adverts,
            changed,
        }
    }
}

impl ValidatedPoolReader<DkgArtifact> for DkgPoolImpl {
    fn contains(&self, hash: &CryptoHashOf<dkg::Message>) -> bool {
        self.unvalidated.contains_key(hash) || self.validated.contains_key(hash)
    }

    fn get_validated_by_identifier(&self, id: &CryptoHashOf<dkg::Message>) -> Option<dkg::Message> {
        self.validated
            .get(id)
            .map(|artifact| artifact.as_ref())
            .cloned()
    }

    fn get_all_validated_by_filter(&self, _filter: &()) -> Box<dyn Iterator<Item = dkg::Message>> {
        unimplemented!()
    }
}

impl DkgPool for DkgPoolImpl {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_> {
        Box::new(self.validated.values().map(|artifact| artifact.as_ref()))
    }

    fn get_validated_older_than(
        &self,
        age_threshold: Duration,
    ) -> Box<dyn Iterator<Item = &dkg::Message> + '_> {
        self.entries_older_than(current_time().saturating_sub_duration(age_threshold))
    }

    fn get_unvalidated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_> {
        Box::new(
            self.unvalidated
                .values()
                .map(|artifact: &UnvalidatedArtifact<consensus::dkg::Message>| &artifact.message),
        )
    }

    fn get_current_start_height(&self) -> Height {
        self.current_start_height
    }

    fn validated_contains(&self, msg: &dkg::Message) -> bool {
        self.validated
            .contains_key(&ic_types::crypto::crypto_hash(msg))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_interfaces::dkg::DkgPool;
    use ic_interfaces::time_source::SysTimeSource;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{
        consensus::fake::FakeSigner,
        mock_time,
        types::ids::{node_test_id, subnet_test_id},
    };
    use ic_types::{
        crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        signature::BasicSignature,
        NodeId,
    };
    use std::ops::Add;

    fn make_message(start_height: Height, node_id: NodeId) -> dkg::Message {
        let dkg_id = NiDkgId {
            start_block_height: start_height,
            dealer_subnet: subnet_test_id(100),
            dkg_tag: NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        };
        dkg::Message {
            content: dkg::DealingContent::new(NiDkgDealing::dummy_dealing_for_tests(0), dkg_id),
            signature: BasicSignature::fake(node_id),
        }
    }

    #[test]
    fn test_dkg_pool_purging() {
        // create 2 DKGs for the same subnet
        let current_dkg_id_start_height = Height::from(30);
        let last_dkg_id_start_height = Height::from(10);
        let mut pool = DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        // add two validated messages, one for every DKG instance
        let result = pool.apply_changes(
            &SysTimeSource::new(),
            [
                make_message(current_dkg_id_start_height, node_test_id(0)),
                make_message(last_dkg_id_start_height, node_test_id(0)),
            ]
            .iter()
            .cloned()
            .map(ChangeAction::AddToValidated)
            .collect(),
        );
        // add two unvalidated
        pool.insert(UnvalidatedArtifact {
            message: make_message(current_dkg_id_start_height, node_test_id(1)),
            peer_id: node_test_id(1),
            timestamp: mock_time(),
        });
        pool.insert(UnvalidatedArtifact {
            message: make_message(last_dkg_id_start_height, node_test_id(1)),
            peer_id: node_test_id(1),
            timestamp: mock_time(),
        });
        // ensure we have 2 validated and 2 unvalidated artifacts
        assert_eq!(result.adverts.len(), 2);
        assert!(result.purged.is_empty());
        assert!(result.changed);
        assert_eq!(pool.get_validated().count(), 2);
        assert_eq!(pool.get_unvalidated().count(), 2);

        // purge below the height of the current dkg and make sure the older artifacts
        // are purged from the validated and unvalidated sections
        let result = pool.apply_changes(
            &SysTimeSource::new(),
            vec![ChangeAction::Purge(current_dkg_id_start_height)],
        );
        assert_eq!(result.purged.len(), 1);
        assert!(result.adverts.is_empty());
        assert!(result.changed);
        assert_eq!(pool.get_validated().count(), 1);
        assert_eq!(pool.get_unvalidated().count(), 1);

        // purge the highest height and make sure everything is gone
        let result = pool.apply_changes(
            &SysTimeSource::new(),
            vec![ChangeAction::Purge(current_dkg_id_start_height.increment())],
        );
        assert_eq!(result.purged.len(), 1);
        assert!(result.adverts.is_empty());
        assert!(result.changed);
        assert_eq!(pool.get_validated().count(), 0);
        assert_eq!(pool.get_unvalidated().count(), 0);
    }

    #[test]
    fn test_dkg_pool_filter_by_age() {
        let mut pool = DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let now = current_time();

        // 200 sec old
        let msg = make_message(Height::from(1), node_test_id(1));
        pool.validated.insert(
            ic_types::crypto::crypto_hash(&msg),
            ValidatedArtifact {
                msg,
                timestamp: now.saturating_sub_duration(Duration::from_secs(200)),
            },
        );

        // 100 sec old
        let msg = make_message(Height::from(2), node_test_id(2));
        pool.validated.insert(
            ic_types::crypto::crypto_hash(&msg),
            ValidatedArtifact {
                msg,
                timestamp: now.saturating_sub_duration(Duration::from_secs(100)),
            },
        );

        // 50 sec old
        let msg = make_message(Height::from(3), node_test_id(3));
        pool.validated.insert(
            ic_types::crypto::crypto_hash(&msg),
            ValidatedArtifact {
                msg,
                timestamp: now.saturating_sub_duration(Duration::from_secs(50)),
            },
        );

        // In future
        let msg = make_message(Height::from(4), node_test_id(4));
        pool.validated.insert(
            ic_types::crypto::crypto_hash(&msg),
            ValidatedArtifact {
                msg,
                timestamp: now.add(Duration::from_secs(50)),
            },
        );

        assert_eq!(
            pool.entries_older_than(now.saturating_sub_duration(Duration::from_secs(300)))
                .count(),
            0
        );
        assert_eq!(
            pool.entries_older_than(now.saturating_sub_duration(Duration::from_secs(150)))
                .count(),
            1
        );
        assert_eq!(
            pool.entries_older_than(now.saturating_sub_duration(Duration::from_secs(75)))
                .count(),
            2
        );
        assert_eq!(
            pool.entries_older_than(now.saturating_sub_duration(Duration::from_secs(50)))
                .count(),
            3
        );
        assert_eq!(
            pool.entries_older_than(now.add(Duration::from_secs(500)))
                .count(),
            4
        );
    }
}
