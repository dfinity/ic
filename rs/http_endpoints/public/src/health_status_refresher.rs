use crate::metrics::HttpHandlerMetrics;
use axum::body::Body;
use crossbeam::atomic::AtomicCell;
use http::Request;
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{info, warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::ReplicaHealthStatus;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[derive(Clone)]
pub(crate) struct HealthStatusRefreshLayer {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl HealthStatusRefreshLayer {
    pub fn new(
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Self {
        Self {
            log,
            metrics,
            health_status,
            consensus_pool_cache,
            state_reader,
        }
    }
}

impl<S> Layer<S> for HealthStatusRefreshLayer {
    type Service = HealthStatusRefreshService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HealthStatusRefreshService {
            log: self.log.clone(),
            metrics: self.metrics.clone(),
            health_status: self.health_status.clone(),
            consensus_pool_cache: self.consensus_pool_cache.clone(),
            state_reader: self.state_reader.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
pub struct HealthStatusRefreshService<S> {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    inner: S,
}

impl<S> Service<Request<Body>> for HealthStatusRefreshService<S>
where
    S: Service<Request<Body>> + Clone + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, body: Request<Body>) -> Self::Future {
        // If this replicas certified state height lags blocks behind the finalizied height,
        // we consider this replica unhealthy because it serves a old/stale state. This is a
        // best-effort check and does not detect any case where the replica is behind.
        //
        // Only valid state transitions are `Healthy` -> `CertifiedStateBehind` and
        // `CertifiedStateBehind` -> `Healthy`. Correct state transition is enforeced by
        // `compare_exchange` that only updates the value if the we currently are in the
        // correct state (1st argument)
        if self
            .consensus_pool_cache
            .is_replica_behind(self.state_reader.latest_certified_height())
        {
            self.health_status
                .compare_exchange(
                    ReplicaHealthStatus::Healthy,
                    ReplicaHealthStatus::CertifiedStateBehind,
                )
                .map(|old| {
                    warn!(
                        self.log,
                        "Replicas latest certified state {} is considerably behind last finalized height {} setting health status to {:?}",
                        self.state_reader.latest_certified_height(),
                        self.consensus_pool_cache.finalized_block().height,
                        ReplicaHealthStatus::CertifiedStateBehind,
                    );
                    self.metrics
                        .health_status_transitions_total
                        .with_label_values(&[
                            (old.as_ref()),
                            (ReplicaHealthStatus::CertifiedStateBehind.as_ref()),
                        ])
                        .inc();
                })
                .ok();
        } else {
            self.health_status
                .compare_exchange(
                    ReplicaHealthStatus::CertifiedStateBehind,
                    ReplicaHealthStatus::Healthy,
                )
                .map(|old| {
                    info!(
                        self.log,
                        "Replicas latest state {} has caught up to last finalized height: {}",
                        self.state_reader.latest_certified_height(),
                        self.consensus_pool_cache.finalized_block().height
                    );
                    self.metrics
                        .health_status_transitions_total
                        .with_label_values(&[
                            (old.as_ref()),
                            (ReplicaHealthStatus::Healthy.as_ref()),
                        ])
                        .inc();
                })
                .ok();
        }

        self.inner.call(body)
    }
}
