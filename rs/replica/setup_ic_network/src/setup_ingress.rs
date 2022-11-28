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
};
use threadpool::ThreadPool;
use tower::{util::BoxCloneService, Service, ServiceBuilder};

/// Max number of inflight requests that add artifacts into the ArtifactManager.
// Do not increase the number until we get to the root cause of NET-743.
const MAX_INFLIGHT_INGRESS_MESSAGES: usize = 50;

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
                .concurrency_limit(MAX_INFLIGHT_INGRESS_MESSAGES)
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
            if !tx.is_closed() {
                // We ingnore the error in case the receiver was dropped. This can happen when the
                // client drops the future executing this code.
                let _ = tx.send(if throttler.read().unwrap().exceeds_threshold() {
                    Err(IngressError::Overloaded)
                } else {
                    let advert = IngressArtifact::message_to_advert(&signed_ingress);
                    artifact_manager
                        .on_artifact(
                            Artifact::IngressMessage(signed_ingress),
                            advert.into(),
                            &node_id,
                        )
                        .map_err(|e| {
                            info!(log, "Artifact not inserted {:?}", e);
                            IngressError::Overloaded
                        })
                });
            }
        });
        Box::pin(async move { Ok(rx.await.expect("Ingress ingestion task MUST NOT panic.")) })
    }
}
