use std::{
    fmt::{Debug, Display},
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    routing::any,
};
use backon::{BackoffBuilder, ExponentialBuilder};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{
    ArtifactAssembler, AssembleResult, Bouncer, BouncerFactory, BouncerValue, Peers,
    ValidatedPoolReader,
};
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::ProtoProxy;
use ic_quic_transport::Transport;
use ic_types::artifact::{IdentifiableArtifact, PbArtifact};
use rand::{SeedableRng, rngs::SmallRng, seq::IteratorRandom};
use tokio::{
    runtime::Handle,
    sync::watch,
    task::JoinHandle,
    time::{Instant, sleep_until, timeout_at},
};
use tracing::instrument;

use super::metrics::FetchArtifactMetrics;

const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn uri_prefix<Artifact: PbArtifact>() -> String {
    Artifact::NAME.to_lowercase()
}

fn build_axum_router<Artifact, Pool>(pool: Arc<RwLock<Pool>>) -> Router
where
    Artifact: PbArtifact,
    Pool: ValidatedPoolReader<Artifact> + 'static,
{
    Router::new()
        .route(
            &format!("/{}/rpc", uri_prefix::<Artifact>()),
            any(rpc_handler),
        )
        .with_state(pool)
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable())
}

async fn rpc_handler<Artifact, Pool>(
    State(pool): State<Arc<RwLock<Pool>>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode>
where
    Artifact: PbArtifact,
    Pool: ValidatedPoolReader<Artifact> + 'static,
{
    let jh = tokio::task::spawn_blocking(move || {
        let id: Artifact::Id =
            Artifact::PbId::proxy_decode(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;
        let artifact = pool
            .read()
            .unwrap()
            .get(&id)
            .ok_or(StatusCode::NO_CONTENT)?;
        Ok::<_, StatusCode>(Bytes::from(Artifact::PbMessage::proxy_encode(artifact)))
    });
    let bytes = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

pub struct FetchArtifact<Artifact: PbArtifact> {
    log: ReplicaLogger,
    transport: Arc<dyn Transport>,
    bouncer_rx: watch::Receiver<Bouncer<Artifact::Id>>,
    pub(crate) metrics: FetchArtifactMetrics,
    jh: Arc<JoinHandle<()>>,
}

impl<Artifact: PbArtifact> Clone for FetchArtifact<Artifact> {
    fn clone(&self) -> Self {
        Self {
            log: self.log.clone(),
            transport: self.transport.clone(),
            bouncer_rx: self.bouncer_rx.clone(),
            metrics: self.metrics.clone(),
            jh: self.jh.clone(),
        }
    }
}

impl<Artifact> ArtifactAssembler<Artifact, Artifact> for FetchArtifact<Artifact>
where
    Artifact: PbArtifact,
    Artifact::Id: Debug,
{
    fn disassemble_message(&self, msg: Artifact) -> Artifact {
        msg
    }
    async fn assemble_message<P: Peers + Send + 'static>(
        &self,
        id: <Artifact as IdentifiableArtifact>::Id,
        artifact: Option<(Artifact, NodeId)>,
        peers: P,
    ) -> AssembleResult<Artifact> {
        let id = &id;
        self.assemble_with_retries(id, artifact, move |artifact, deadline| {
            self.try_fetch(id, artifact, peers.peers(), deadline)
        })
        .await
    }
}

/// The outcome of one attempt to assemble a message.
pub(crate) enum Attempt<T> {
    Done {
        message: T,
        peer_id: NodeId,
    },
    Unwanted,
    /// The attempt failed, and another one has to be made.
    Retry,
}

impl<Artifact: PbArtifact> FetchArtifact<Artifact> {
    pub fn new<Pool, Factory>(
        log: ReplicaLogger,
        rt: Handle,
        pool: Arc<RwLock<Pool>>,
        bouncer_factory: Factory,
        metrics_registry: MetricsRegistry,
    ) -> (impl FnOnce(Arc<dyn Transport>) -> Self, Router)
    where
        Pool: ValidatedPoolReader<Artifact> + 'static,
        Factory: BouncerFactory<Artifact::Id, Pool> + 'static,
    {
        let pool_clone = pool.clone();
        (
            move |transport: Arc<dyn Transport>| {
                let bouncer = {
                    let p = pool.read().unwrap();
                    bouncer_factory.new_bouncer(&p)
                };
                let (bouncer_tx, bouncer_rx) = watch::channel(bouncer);
                let jh = rt.spawn(async move {
                    loop {
                        let bouncer = {
                            let p = pool.read().unwrap();
                            bouncer_factory.new_bouncer(&p)
                        };
                        if bouncer_tx.send(bouncer).is_err() {
                            break;
                        }

                        tokio::time::sleep(bouncer_factory.refresh_period()).await
                    }
                });
                Self {
                    log,
                    transport,
                    bouncer_rx,
                    metrics: FetchArtifactMetrics::new::<Artifact>(&metrics_registry),
                    jh: Arc::new(jh),
                }
            },
            build_axum_router(pool_clone),
        )
    }

    /// Returns a watcher over the bouncer used by this assembler, so callers can react to the
    /// artifact becoming [`BouncerValue::Unwanted`] (e.g. to cancel in-progress assembly work).
    pub(crate) fn bouncer_watcher(&self) -> watch::Receiver<Bouncer<Artifact::Id>> {
        self.bouncer_rx.clone()
    }

    /// Waits until advert resolves to wanted. If the bouncer value becomes Unwanted, false is returned.
    #[instrument(skip_all)]
    async fn should_download(
        id: &Artifact::Id,
        artifact: &mut Option<(Artifact, NodeId)>,
        metrics: &FetchArtifactMetrics,
        bouncer_watcher: &mut watch::Receiver<Bouncer<Artifact::Id>>,
    ) -> bool {
        let mut bouncer_value = bouncer_watcher.borrow_and_update()(id);

        // Clear the artifact from memory if it was pushed.
        if let BouncerValue::MaybeWantsLater = bouncer_value {
            artifact.take();
            metrics.download_task_stashed_total.inc();
        }

        while let BouncerValue::MaybeWantsLater = bouncer_value {
            let _ = bouncer_watcher.changed().await;
            bouncer_value = bouncer_watcher.borrow_and_update()(id);
        }

        BouncerValue::Unwanted != bouncer_value
    }

    /// Makes attempts to assemble the message until one succeeds or the message is unwanted.
    ///
    /// Before each attempt, waits until the bouncer wants the message. The attempt gets the pushed
    /// artifact, if still there, and a deadline for its request that backs off exponentially. After
    /// a failed attempt, the next one starts once that deadline has passed.
    #[instrument(skip_all)]
    pub(crate) async fn assemble_with_retries<T, F, Fut>(
        &self,
        id: &Artifact::Id,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact, NodeId)>,
        mut attempt: F,
    ) -> AssembleResult<T>
    where
        F: FnMut(Option<(Artifact, NodeId)>, Instant) -> Fut,
        Fut: Future<Output = Attempt<T>>,
    {
        let mut bouncer_watcher = self.bouncer_rx.clone();
        let mut backoff = ExponentialBuilder::new()
            .with_min_delay(MIN_ARTIFACT_RPC_TIMEOUT)
            .with_max_delay(MAX_ARTIFACT_RPC_TIMEOUT)
            .with_factor(1.5)
            .with_jitter()
            .without_max_times()
            .build();
        // Records the download time when dropped.
        let mut download_timer = None;

        loop {
            if !Self::should_download(id, &mut artifact, &self.metrics, &mut bouncer_watcher).await
            {
                return AssembleResult::Unwanted;
            }
            if artifact.is_none() && download_timer.is_none() {
                download_timer = Some(
                    self.metrics
                        .download_task_artifact_download_duration
                        .start_timer(),
                );
            }

            let deadline = Instant::now() + backoff.next().unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
            // Only the first attempt gets the pushed copy, so that a failed one is followed by
            // downloading a copy from a random peer.
            match attempt(artifact.take(), deadline).await {
                Attempt::Done { message, peer_id } => {
                    return AssembleResult::Done { message, peer_id };
                }
                Attempt::Unwanted => return AssembleResult::Unwanted,
                // Wait before checking the bouncer so we might be able to avoid an unnecessary download.
                Attempt::Retry => sleep_until(deadline).await,
            }
        }
    }

    /// Returns the pushed artifact, if any, or tries once to download the artifact from a random one
    /// of the `peers` advertising it, giving up at `deadline`.
    pub(crate) async fn try_fetch(
        &self,
        id: &Artifact::Id,
        artifact: Option<(Artifact, NodeId)>,
        peers: Vec<NodeId>,
        deadline: Instant,
    ) -> Attempt<Artifact>
    where
        Artifact::Id: Debug,
    {
        // Artifact was pushed by peer. In this case we don't need check that the artifact ID corresponds
        // to the artifact because we earlier derived the ID from the artifact.
        if let Some((message, peer_id)) = artifact {
            return Attempt::Done { message, peer_id };
        }
        let Some(peer) = peers.into_iter().choose(&mut SmallRng::from_entropy()) else {
            return Attempt::Retry;
        };

        let bytes = Bytes::from(Artifact::PbId::proxy_encode(id.clone()));
        let request = Request::builder()
            .uri(format!("/{}/rpc", uri_prefix::<Artifact>()))
            .body(bytes)
            .unwrap();
        match timeout_at(deadline, self.transport.rpc(&peer, request)).await {
            Ok(Ok(response)) if response.status() == StatusCode::OK => {
                return match Artifact::PbMessage::proxy_decode(&response.into_body()) {
                    Ok(message) if message.id() == *id => Attempt::Done {
                        message,
                        peer_id: peer,
                    },
                    Ok(_) => self.invalid_copy(id, peer, "the copy has a different id"),
                    Err(err) => self.invalid_copy(id, peer, err),
                };
            }
            _ => {
                self.metrics
                    .download_task_artifact_download_errors_total
                    .inc();
            }
        }
        Attempt::Retry
    }

    /// Counts and logs an invalid copy of the artifact that `peer` sent.
    pub(crate) fn invalid_copy<T>(
        &self,
        id: &Artifact::Id,
        peer: NodeId,
        err: impl Display,
    ) -> Attempt<T>
    where
        Artifact::Id: Debug,
    {
        self.metrics.download_task_invalid_copies_total.inc();
        warn!(
            self.log,
            "Peer {} sent an invalid copy of {:?}, fetching another one: {}", peer, id, err
        );
        Attempt::Retry
    }
}
