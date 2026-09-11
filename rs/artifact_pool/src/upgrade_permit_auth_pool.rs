use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::{HasLabel, PoolSection},
};
use ic_interfaces::{
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool, UnvalidatedArtifact,
        ValidatedPoolReader,
    },
    upgrade::{UpgradePermitAuthChangeAction, UpgradePermitAuthChangeSet, UpgradePermitAuthPool},
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{IdentifiableArtifact, UpgradePermitAuthorizationShareId},
    consensus::UpgradePermitAuthorizationShare,
};
use prometheus::IntCounter;

const POOL_NAME: &str = "upgrade_permit_auth";

type ValidatedSection =
    PoolSection<UpgradePermitAuthorizationShareId, UpgradePermitAuthorizationShare>;
type UnvalidatedSection = PoolSection<
    UpgradePermitAuthorizationShareId,
    UnvalidatedArtifact<UpgradePermitAuthorizationShare>,
>;

/// Upgrade Permit Authorization Pool implementation.
pub struct UpgradePermitAuthPoolImpl {
    validated: ValidatedSection,
    unvalidated: UnvalidatedSection,
    invalidated_artifacts: IntCounter,
    log: ReplicaLogger,
}

impl UpgradePermitAuthPoolImpl {
    pub fn new(metrics: MetricsRegistry, log: ReplicaLogger) -> Self {
        Self {
            invalidated_artifacts: metrics.int_counter(
                "upgrade_permit_auth_invalidated_artifacts",
                "The number of invalidated upgrade permit auth artifacts",
            ),
            validated: PoolSection::new(metrics.clone(), POOL_NAME, POOL_TYPE_VALIDATED),
            unvalidated: PoolSection::new(metrics, POOL_NAME, POOL_TYPE_UNVALIDATED),
            log,
        }
    }
}

impl UpgradePermitAuthPool for UpgradePermitAuthPoolImpl {
    fn get_validated_shares(
        &self,
    ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_> {
        Box::new(self.validated.values())
    }

    fn get_unvalidated_shares(
        &self,
    ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_> {
        Box::new(self.unvalidated.values().map(|pa| &pa.message))
    }
}

impl MutablePool<UpgradePermitAuthorizationShare> for UpgradePermitAuthPoolImpl {
    type Mutations = UpgradePermitAuthChangeSet;

    fn insert(&mut self, artifact: UnvalidatedArtifact<UpgradePermitAuthorizationShare>) {
        let id = artifact.message.id();
        self.unvalidated.insert(id, artifact);
    }

    fn remove(&mut self, id: &UpgradePermitAuthorizationShareId) {
        self.unvalidated.remove(id);
    }

    fn apply(
        &mut self,
        change_set: UpgradePermitAuthChangeSet,
    ) -> ArtifactTransmits<UpgradePermitAuthorizationShare> {
        let changed = !change_set.is_empty();
        let mut transmits = vec![];
        for action in change_set {
            match action {
                UpgradePermitAuthChangeAction::AddToValidated(share) => {
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: share.clone(),
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(share.id(), share);
                }
                UpgradePermitAuthChangeAction::MoveToValidated(share) => {
                    let id = share.id();
                    self.unvalidated.remove(&id);
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: share.clone(),
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(id, share);
                }
                UpgradePermitAuthChangeAction::RemoveValidated(id) => {
                    if self.validated.remove(&id).is_some() {
                        transmits.push(ArtifactTransmit::Abort(id));
                    }
                }
                UpgradePermitAuthChangeAction::RemoveUnvalidated(id) => {
                    self.unvalidated.remove(&id);
                }
                UpgradePermitAuthChangeAction::HandleInvalid(id, reason) => {
                    ic_logger::warn!(
                        self.log,
                        "Invalidating upgrade permit auth artifact {id:?}: {reason}"
                    );
                    self.invalidated_artifacts.inc();
                    self.unvalidated.remove(&id);
                }
            }
        }
        ArtifactTransmits {
            transmits,
            poll_immediately: changed,
        }
    }
}

impl ValidatedPoolReader<UpgradePermitAuthorizationShare> for UpgradePermitAuthPoolImpl {
    fn get(
        &self,
        id: &UpgradePermitAuthorizationShareId,
    ) -> Option<UpgradePermitAuthorizationShare> {
        self.validated.get(id).cloned()
    }

    fn get_all_for_initial_broadcast(
        &self,
    ) -> Box<dyn Iterator<Item = UpgradePermitAuthorizationShare> + '_> {
        // Not persisted — no initial broadcast on restart.
        Box::new(std::iter::empty())
    }
}

impl HasLabel for UpgradePermitAuthorizationShare {
    fn label(&self) -> &str {
        "upgrade_permit_auth_share"
    }
}

impl HasLabel for UnvalidatedArtifact<UpgradePermitAuthorizationShare> {
    fn label(&self) -> &str {
        self.message.label()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::Height;
    use ic_types::consensus::UpgradePermitAuthorizationRequest;
    use ic_types::crypto::{BasicSig, BasicSigOf};
    use ic_types::signature::BasicSignature;
    use ic_types::time::UNIX_EPOCH;

    fn fake_share(
        signer: u64,
        requestor: u64,
        request_height: u64,
    ) -> UpgradePermitAuthorizationShare {
        UpgradePermitAuthorizationShare {
            content: UpgradePermitAuthorizationRequest {
                requestor: node_test_id(requestor),
                request_height: Height::from(request_height),
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node_test_id(signer),
            },
        }
    }

    fn to_unvalidated(
        share: UpgradePermitAuthorizationShare,
    ) -> UnvalidatedArtifact<UpgradePermitAuthorizationShare> {
        UnvalidatedArtifact {
            message: share,
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        }
    }

    fn pool() -> UpgradePermitAuthPoolImpl {
        UpgradePermitAuthPoolImpl::new(MetricsRegistry::new(), no_op_logger())
    }

    #[test]
    fn test_insert_and_remove_unvalidated() {
        let mut pool = pool();
        let share = fake_share(1, 2, 10);
        let id = share.id();

        pool.insert(to_unvalidated(share.clone()));
        assert!(pool.get_unvalidated_shares().eq([&share]));
        assert!(pool.get(&id).is_none());

        pool.remove(&id);
        assert_eq!(pool.get_unvalidated_shares().count(), 0);
    }

    #[test]
    fn test_add_to_validated_broadcasts() {
        let mut pool = pool();
        let share = fake_share(1, 2, 10);

        let result = pool.apply(vec![UpgradePermitAuthChangeAction::AddToValidated(
            share.clone(),
        )]);

        assert!(result.poll_immediately);
        assert_eq!(result.transmits.len(), 1);
        assert!(matches!(
            &result.transmits[0],
            ArtifactTransmit::Deliver(a) if a.artifact == share
        ));
        assert!(pool.get_validated_shares().eq([&share]));
        assert_eq!(pool.get(&share.id()).unwrap(), share);
    }

    #[test]
    fn test_move_to_validated_replaces_unvalidated_and_broadcasts() {
        let mut pool = pool();
        let share = fake_share(1, 2, 10);
        pool.insert(to_unvalidated(share.clone()));
        assert!(pool.get_unvalidated_shares().eq([&share]));

        let result = pool.apply(vec![UpgradePermitAuthChangeAction::MoveToValidated(
            share.clone(),
        )]);

        assert_eq!(result.transmits.len(), 1);
        assert_eq!(pool.get_unvalidated_shares().count(), 0);
        assert!(pool.get_validated_shares().eq([&share]));
        assert_eq!(pool.get(&share.id()).unwrap(), share);
    }

    #[test]
    fn test_remove_validated_aborts_broadcast() {
        let mut pool = pool();
        let share = fake_share(1, 2, 10);
        pool.apply(vec![UpgradePermitAuthChangeAction::AddToValidated(
            share.clone(),
        )]);

        let result = pool.apply(vec![UpgradePermitAuthChangeAction::RemoveValidated(
            share.id(),
        )]);

        assert!(result.poll_immediately);
        assert!(matches!(&result.transmits[0], ArtifactTransmit::Abort(id) if *id == share.id()));
        assert_eq!(pool.get_validated_shares().count(), 0);

        // Removing again is a no-op without a redundant Abort.
        let result = pool.apply(vec![UpgradePermitAuthChangeAction::RemoveValidated(
            share.id(),
        )]);
        assert_eq!(result.transmits.len(), 0);
    }

    #[test]
    fn test_handle_invalid_drops_unvalidated_without_broadcast() {
        let mut pool = pool();
        let share = fake_share(1, 2, 10);
        pool.insert(to_unvalidated(share.clone()));

        let result = pool.apply(vec![UpgradePermitAuthChangeAction::HandleInvalid(
            share.id(),
            "bad signature".to_string(),
        )]);

        assert!(result.poll_immediately);
        assert!(result.transmits.is_empty());
        assert_eq!(pool.get_unvalidated_shares().count(), 0);
    }

    #[test]
    fn test_empty_change_set_does_not_poll() {
        let mut pool = pool();
        let result = pool.apply(vec![]);
        assert!(!result.poll_immediately);
        assert!(result.transmits.is_empty());
    }

    #[test]
    fn test_shares_keyed_by_signer_and_request() {
        let mut pool = pool();
        pool.apply(vec![
            // Same signer, different requests: two entries.
            UpgradePermitAuthChangeAction::AddToValidated(fake_share(1, 2, 10)),
            UpgradePermitAuthChangeAction::AddToValidated(fake_share(1, 2, 11)),
            UpgradePermitAuthChangeAction::AddToValidated(fake_share(3, 2, 10)),
            UpgradePermitAuthChangeAction::AddToValidated(fake_share(4, 2, 10)),
        ]);
        assert_eq!(pool.get_validated_shares().count(), 4);

        // Re-adding the same (signer, request) pair overwrites.
        pool.apply(vec![UpgradePermitAuthChangeAction::AddToValidated(
            fake_share(1, 2, 10),
        )]);
        assert_eq!(pool.get_validated_shares().count(), 4);
    }
}
