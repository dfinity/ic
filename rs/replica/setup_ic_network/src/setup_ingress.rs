use ic_artifact_manager::artifact::IngressArtifact;
use ic_interfaces::{artifact_manager::ArtifactManager, ingress_pool::IngressPoolThrottler};
use ic_interfaces_p2p::{IngressError, IngressIngestionService};
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_types::{
    artifact::{Artifact, ArtifactKind},
    messages::SignedIngress,
    NodeId,
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use threadpool::ThreadPool;
use tower::{util::BoxCloneService, Service, ServiceBuilder};

/// Max number of inflight requests into P2P. Note each each requests requires a
/// dedicated thread to execute on so this number should be relatively small.
// Do not increase the number until we get to the root cause of NET-743.
const MAX_INFLIGHT_INGRESS_MESSAGES: usize = 1;
/// Max ingress messages per second that can go into P2P.
// There is some internal contention inside P2P (NET-743). We achieve lower
// throughput if we process messages one after the other.
const MAX_INGRESS_MESSAGES_PER_SECOND: u64 = 100;

/// Max number of ingress message we can buffer until the P2P layer is ready to
/// accept them.
// The latency SLO for 'call' requests is set for 2s. Given the rate limiter of
// 100 per second this buffer should not be bigger than 200. We are conservite
// setting it to 100.
const MAX_BUFFERED_INGRESS_MESSAGES: usize = 100;

// Each message for each flow is being executed on the same code path. Unless those codepaths are
// lock free (which is not the case because Gossip has locks) there is no point in having more
// than 1 thread processing messages per flow.
const MAX_INGRESS_THREADS: usize = 1;

/// The ingress throttler is protected by a read-write lock for concurrent
/// access.
pub type IngressThrottler = Arc<std::sync::RwLock<dyn IngressPoolThrottler + Send + Sync>>;

#[derive(Clone)]
pub(crate) struct IngressEventHandler {
    log: ReplicaLogger,
    threadpool: ThreadPool,
    /// The ingress throttler.
    ingress_throttler: IngressThrottler,
    artifact_manager: Arc<dyn ArtifactManager>,
    /// The node ID.
    node_id: NodeId,
}

impl IngressEventHandler {
    /// The function creates an `IngressEventHandler` instance.
    pub(crate) fn new_service(
        log: ReplicaLogger,
        ingress_throttler: IngressThrottler,
        artifact_manager: Arc<dyn ArtifactManager>,
        node_id: NodeId,
    ) -> IngressIngestionService {
        let threadpool = threadpool::Builder::new()
            .num_threads(MAX_INGRESS_THREADS)
            .thread_name("P2P_Ingress_Thread".into())
            .build();

        let base_service = Self {
            log,
            threadpool,
            ingress_throttler,
            artifact_manager,
            node_id,
        };

        BoxCloneService::new(
            ServiceBuilder::new()
                .buffer(MAX_BUFFERED_INGRESS_MESSAGES)
                .concurrency_limit(MAX_INFLIGHT_INGRESS_MESSAGES)
                .rate_limit(MAX_INGRESS_MESSAGES_PER_SECOND, Duration::from_secs(1))
                .service(base_service),
        )
    }
}

/// `IngressEventHandler` implements the `IngressEventHandler` trait.
impl Service<SignedIngress> for IngressEventHandler {
    type Response = Result<(), IngressError>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// The method is called when an ingress message is received.
    fn call(&mut self, signed_ingress: SignedIngress) -> Self::Future {
        let artifact_manager = Arc::clone(&self.artifact_manager);
        let log = self.log.clone();
        let throttler = Arc::clone(&self.ingress_throttler);
        let node_id = self.node_id;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.threadpool.execute(move || {
            // We ingnore the error in case the receiver was dropped. This can happen when the
            // client drops the future executing this code.
            let _ = tx.send(if throttler.read().unwrap().exceeds_threshold() {
                Err(IngressError::Overloaded)
            } else {
                let advert = IngressArtifact::message_to_advert(&signed_ingress);
                artifact_manager
                    .on_artifact(
                        Artifact::IngressMessage(signed_ingress.into()),
                        advert.into(),
                        &node_id,
                    )
                    .map_err(|e| {
                        info!(log, "Artifact not inserted {:?}", e);
                        IngressError::Overloaded
                    })
            });
        });
        Box::pin(async move { Ok(rx.await.expect("Ingress ingestion task MUST NOT panic.")) })
    }
}
