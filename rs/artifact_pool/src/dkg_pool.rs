use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::{HasLabel, PoolSection},
};
use ic_interfaces::{
    dkg::{ChangeAction, DkgPool, Mutations},
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool, UnvalidatedArtifact,
        ValidatedPoolReader,
    },
};
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_types::{Height, consensus, consensus::dkg, consensus::dkg::DkgMessageId};
use prometheus::IntCounter;

/// The DkgPool is used to store messages that are exchanged between replicas in
/// the process of executing DKG.
pub struct DkgPoolImpl {
    validated: PoolSection<DkgMessageId, dkg::Message>,
    unvalidated: PoolSection<DkgMessageId, UnvalidatedArtifact<dkg::Message>>,
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
    pub fn get(&self, id: &DkgMessageId) -> Option<&dkg::Message> {
        self.validated
            .get(id)
            .or_else(|| self.unvalidated.get(id).map(|pa| &pa.message))
    }

    /// Deletes all validated and unvalidated messages, which do not correspond
    /// to the current DKG interval. Return the Ids of validated messages that were
    /// purged
    fn purge(&mut self, height: Height) -> Vec<DkgMessageId> {
        self.current_start_height = height;
        // TODO: use drain_filter once it's stable.
        let unvalidated_keys: Vec<_> = self
            .unvalidated
            .keys()
            .filter(|id| id.height < height)
            .cloned()
            .collect();
        for id in unvalidated_keys {
            self.unvalidated.remove(&id);
        }

        let validated_keys: Vec<_> = self
            .validated
            .keys()
            .filter(|id| id.height < height)
            .cloned()
            .collect();
        for hash in &validated_keys {
            self.validated.remove(hash);
        }
        validated_keys
    }
}

impl MutablePool<dkg::Message> for DkgPoolImpl {
    type Mutations = Mutations;

    /// Inserts an unvalidated artifact into the unvalidated section.
    fn insert(&mut self, artifact: UnvalidatedArtifact<consensus::dkg::Message>) {
        self.unvalidated
            .insert(DkgMessageId::from(&artifact.message), artifact);
    }

    /// Removes an unvalidated artifact from the unvalidated section.
    fn remove(&mut self, id: &DkgMessageId) {
        self.unvalidated.remove(id);
    }

    /// Applies the provided change set atomically.
    ///
    /// # Panics
    ///
    /// It panics if we pass a hash for an artifact to be moved into the
    /// validated section, but it cannot be found in the unvalidated
    /// section.
    fn apply(&mut self, change_set: Mutations) -> ArtifactTransmits<dkg::Message> {
        let changed = !change_set.is_empty();
        let mut transmits = vec![];
        for action in change_set {
            match action {
                ChangeAction::HandleInvalid(id, reason) => {
                    self.invalidated_artifacts.inc();
                    warn!(self.log, "Invalid DKG message ({:?}): {:?}", reason, id);
                    self.unvalidated.remove(&id);
                }
                ChangeAction::AddToValidated(message) => {
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: message.clone(),
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(DkgMessageId::from(&message), message);
                }
                ChangeAction::MoveToValidated(message) => {
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: message.clone(),
                        // relayed
                        is_latency_sensitive: false,
                    }));
                    let id = DkgMessageId::from(&message);
                    self.unvalidated
                        .remove(&id)
                        .expect("Unvalidated artifact was not found.");
                    self.validated.insert(id, message);
                }
                ChangeAction::RemoveFromUnvalidated(message) => {
                    let id = DkgMessageId::from(&message);
                    self.unvalidated
                        .remove(&id)
                        .expect("Unvalidated artifact was not found.");
                }
                ChangeAction::Purge(height) => {
                    transmits.extend(self.purge(height).drain(..).map(ArtifactTransmit::Abort))
                }
            }
        }
        ArtifactTransmits {
            transmits,
            poll_immediately: changed,
        }
    }
}

impl ValidatedPoolReader<dkg::Message> for DkgPoolImpl {
    fn get(&self, id: &DkgMessageId) -> Option<dkg::Message> {
        self.validated.get(id).cloned()
    }
}

impl DkgPool for DkgPoolImpl {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_> {
        Box::new(self.validated.values())
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
        self.validated.contains_key(&DkgMessageId::from(msg))
    }
}

impl HasLabel for dkg::Message {
    fn label(&self) -> &str {
        "dkg_message"
    }
}

impl HasLabel for UnvalidatedArtifact<dkg::Message> {
    fn label(&self) -> &str {
        self.message.label()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_crypto_test_utils_ni_dkg::dummy_dealing;
    use ic_interfaces::dkg::DkgPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_consensus::fake::FakeSigner;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        NodeId,
        crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        signature::BasicSignature,
        time::UNIX_EPOCH,
    };

    fn make_message(start_height: Height, node_id: NodeId) -> dkg::Message {
        let dkg_id = NiDkgId {
            start_block_height: start_height,
            dealer_subnet: subnet_test_id(100),
            dkg_tag: NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        };
        dkg::Message {
            content: dkg::DealingContent::new(dummy_dealing(0), dkg_id),
            signature: BasicSignature::fake(node_id),
        }
    }

    #[test]
    fn test_dkg_pool_insert_and_remove() {
        let mut pool = DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let message = make_message(Height::from(30), node_test_id(1));
        let id = DkgMessageId::from(&message);

        // add unvalidated
        pool.insert(UnvalidatedArtifact {
            message,
            peer_id: node_test_id(1),
            timestamp: UNIX_EPOCH,
        });
        assert!(pool.unvalidated.contains_key(&id));

        // remove unvalidated
        pool.remove(&id);
        assert!(!pool.unvalidated.contains_key(&id));
    }

    #[test]
    fn test_dkg_pool_purging() {
        // create 2 DKGs for the same subnet
        let current_dkg_id_start_height = Height::from(30);
        let last_dkg_id_start_height = Height::from(10);
        let mut pool = DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        // add two validated messages, one for every DKG instance
        let result = pool.apply(
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
            timestamp: UNIX_EPOCH,
        });
        pool.insert(UnvalidatedArtifact {
            message: make_message(last_dkg_id_start_height, node_test_id(1)),
            peer_id: node_test_id(1),
            timestamp: UNIX_EPOCH,
        });
        // ensure we have 2 validated and 2 unvalidated artifacts
        assert_eq!(result.transmits.len(), 2);
        assert!(
            !result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Abort(_)))
        );
        assert!(result.poll_immediately);
        assert_eq!(pool.get_validated().count(), 2);
        assert_eq!(pool.get_unvalidated().count(), 2);

        // purge below the height of the current dkg and make sure the older artifacts
        // are purged from the validated and unvalidated sections
        let result = pool.apply(vec![ChangeAction::Purge(current_dkg_id_start_height)]);
        assert_eq!(result.transmits.len(), 1);
        assert!(
            !result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Deliver(_)))
        );
        assert!(result.poll_immediately);
        assert_eq!(pool.get_validated().count(), 1);
        assert_eq!(pool.get_unvalidated().count(), 1);

        // purge the highest height and make sure everything is gone
        let result = pool.apply(vec![ChangeAction::Purge(
            current_dkg_id_start_height.increment(),
        )]);
        assert_eq!(result.transmits.len(), 1);
        assert!(
            !result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Deliver(_)))
        );
        assert!(result.poll_immediately);
        assert_eq!(pool.get_validated().count(), 0);
        assert_eq!(pool.get_unvalidated().count(), 0);
    }

    #[test]
    fn test_dkg_pool_filter_by_age() {
        let mut pool = DkgPoolImpl::new(MetricsRegistry::new(), no_op_logger());

        // 200 sec old
        let msg = make_message(Height::from(1), node_test_id(1));
        pool.validated.insert(DkgMessageId::from(&msg), msg);

        // 100 sec old
        let msg = make_message(Height::from(2), node_test_id(2));
        pool.validated.insert(DkgMessageId::from(&msg), msg);

        // 50 sec old
        let msg = make_message(Height::from(3), node_test_id(3));
        pool.validated.insert(DkgMessageId::from(&msg), msg);

        // In future
        let msg = make_message(Height::from(4), node_test_id(4));
        pool.validated.insert(DkgMessageId::from(&msg), msg);
    }
}
