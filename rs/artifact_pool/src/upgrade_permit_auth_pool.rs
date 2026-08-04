//! Upgrade Permit Authorization Pool implementation.
//!
//! In-memory pool for `UpgradePermitAuthorizationShare` messages, separate from
//! the consensus pool. Shares are produced (signed) by the
//! `UpgradePermitAuthPoolManager` and read by the `UpgradePayloadBuilder` to
//! produce `Authorize` block payloads.
//!
//! Gossiped shares arrive as unvalidated and are moved to validated after
//! signature verification by the pool manager.

use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::{HasLabel, PoolSection},
};
use ic_interfaces::{
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool, UnvalidatedArtifact,
        ValidatedPoolReader,
    },
    upgrade_permit_auth::{UpgradePermitAuthChangeAction, UpgradePermitAuthChangeSet, UpgradePermitAuthPool},
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{IdentifiableArtifact, UpgradePermitAuthId},
    consensus::UpgradePermitAuthorizationShare,
};
use prometheus::IntCounter;

const POOL_NAME: &str = "upgrade_permit_auth";

type ValidatedSection = PoolSection<UpgradePermitAuthId, UpgradePermitAuthorizationShare>;
type UnvalidatedSection =
    PoolSection<UpgradePermitAuthId, UnvalidatedArtifact<UpgradePermitAuthorizationShare>>;

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

    fn remove(&mut self, id: &UpgradePermitAuthId) {
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
                        "Invalidating upgrade permit auth artifact {:?}: {}",
                        id,
                        reason
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
    fn get(&self, id: &UpgradePermitAuthId) -> Option<UpgradePermitAuthorizationShare> {
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
