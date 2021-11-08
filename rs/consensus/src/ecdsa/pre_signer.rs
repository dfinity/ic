//! The pre signature process manager

use crate::consensus::{
    metrics::{timed_call, EcdsaPreSignerMetrics},
    utils::RoundRobin,
    ConsensusCrypto,
};

use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces::ecdsa::{EcdsaChangeSet, EcdsaPool};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::NodeId;

use std::sync::Arc;

pub(crate) trait EcdsaPreSigner: Send {
    /// The on_state_change() called from the main ECDSA path.
    fn on_state_change(&self, ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet;
}

pub(crate) struct EcdsaPreSignerImpl {
    node_id: NodeId,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    metrics: EcdsaPreSignerMetrics,
    logger: ReplicaLogger,
}

impl EcdsaPreSignerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        metrics_registry: MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            consensus_cache,
            crypto,
            schedule: RoundRobin::default(),
            metrics: EcdsaPreSignerMetrics::new(metrics_registry),
            logger,
        }
    }

    /// Checks and starts new requests from latest summary block
    fn on_requests(&self) -> EcdsaChangeSet {
        Default::default()
    }

    /// Processes the dealings received from peer dealers
    fn on_dealings(&self, _ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet {
        Default::default()
    }

    /// Processes the received dealing support messages
    fn on_dealing_support(&self, _ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet {
        Default::default()
    }
}

impl EcdsaPreSigner for EcdsaPreSignerImpl {
    fn on_state_change(&self, ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet {
        let metrics = self.metrics.clone();
        let on_requests = || {
            timed_call(
                "on_requests",
                || self.on_requests(),
                &metrics.on_state_change_duration,
            )
        };
        let on_dealings = || {
            timed_call(
                "on_dealings",
                || self.on_dealings(ecdsa_pool),
                &metrics.on_state_change_duration,
            )
        };
        let on_dealing_support = || {
            timed_call(
                "on_dealing_support",
                || self.on_dealing_support(ecdsa_pool),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> EcdsaChangeSet; 3] =
            [&on_requests, &on_dealings, &on_dealing_support];

        self.schedule.call_next(&calls)
    }
}
