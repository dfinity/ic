use std::{
    fmt::Debug,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    consensus::{TestConsensus, U64Artifact},
    create_peer_manager_and_registry_handle, temp_crypto_component_with_tls_keys,
    RegistryConsensusHandle,
};
use axum::Router;
use bytes::BytesMut;
use futures::{future::BoxFuture, FutureExt};
use ic_artifact_downloader::FetchArtifact;
use ic_artifact_manager::run_artifact_processor;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::{
    p2p::artifact_manager::JoinGuard, p2p::consensus::ArtifactMutation,
    p2p::state_sync::StateSyncClient, time_source::SysTimeSource,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_quic_transport::SubnetTopology;
use ic_quic_transport::{QuicTransport, Transport};
use ic_state_manager::state_sync::types::StateSyncMessage;
use ic_types::{artifact::UnvalidatedArtifactMutation, NodeId, RegistryVersion};
use quinn::{self, udp::EcnCodepoint, AsyncUdpSocket, UdpPoller};
use tokio::{
    select,
    sync::{mpsc, oneshot, watch, Notify},
};
use turmoil::Sim;

pub struct CustomUdp {
    ip: IpAddr,
    inner: turmoil::net::UdpSocket,
}

impl CustomUdp {
    const ECN: EcnCodepoint = EcnCodepoint::Ect0;

    pub fn new(ip: IpAddr, inner: turmoil::net::UdpSocket) -> Self {
        Self { ip, inner }
    }
}

impl std::fmt::Debug for CustomUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CustomUdp")
    }
}

pin_project_lite::pin_project! {
    /// Helper adapting a function `MakeFut` that constructs a single-use future `Fut` into a
    /// [`UdpPoller`] that may be reused indefinitely
    struct UdpPollHelper<MakeFut, Fut> {
        make_fut: MakeFut,
        #[pin]
        fut: Option<Fut>,
    }
}

impl<MakeFut, Fut> UdpPollHelper<MakeFut, Fut> {
    /// Construct a [`UdpPoller`] that calls `make_fut` to get the future to poll, storing it until
    /// it yields [`Poll::Ready`], then creating a new one on the next
    /// [`poll_writable`](UdpPoller::poll_writable)
    fn new(make_fut: MakeFut) -> Self {
        Self {
            make_fut,
            fut: None,
        }
    }
}

impl<MakeFut, Fut> UdpPoller for UdpPollHelper<MakeFut, Fut>
where
    MakeFut: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if this.fut.is_none() {
            this.fut.set(Some((this.make_fut)()));
        }
        // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
        // obtain an `&mut Fut` after storing it in `self.fut` when `self` is already behind `Pin`,
        // and if we didn't store it then we wouldn't be able to keep it alive between
        // `poll_writable` calls.
        let result = this.fut.as_mut().as_pin_mut().unwrap().poll(cx);
        if result.is_ready() {
            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.fut.set(None);
        }
        result
    }
}

impl<MakeFut, Fut> Debug for UdpPollHelper<MakeFut, Fut> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPollHelper").finish_non_exhaustive()
    }
}
//

impl AsyncUdpSocket for CustomUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<(dyn UdpPoller + 'static)>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.inner.writable().await }
        }))
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit<'_>) -> Result<(), std::io::Error> {
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&transmit.segment_size.unwrap_or_default().to_le_bytes());
        buffer.extend_from_slice(transmit.contents);
        let mut bytes_sent = 0;
        loop {
            match self.inner.try_send_to(&buffer, transmit.destination) {
                Ok(x) => bytes_sent += x,
                Err(e) => {
                    if matches!(e.kind(), io::ErrorKind::WouldBlock) {
                        break;
                    }
                    return Err(e);
                }
            }
            if bytes_sent == buffer.len() {
                break;
            }
            if bytes_sent > buffer.len() {
                panic!("Bug: Should not send more bytes then in buffer");
            }
        }

        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        {
            let fut = self.inner.readable();
            tokio::pin!(fut);

            match fut.poll(cx) {
                Poll::Ready(x) => x?,
                Poll::Pending => return Poll::Pending,
            };
        }

        assert!(bufs.len() == meta.len());
        let mut packets_received = 0;
        for (packet_meta, packet_buf) in meta.iter_mut().zip(bufs) {
            let mut turmoil_udp_buffer = vec![0; packet_buf.len() + 8];
            match self.inner.try_recv_from(&mut turmoil_udp_buffer) {
                Ok((bytes_received, addr)) if !turmoil_udp_buffer.is_empty() => {
                    let stride = usize::from_le_bytes(turmoil_udp_buffer[..8].try_into().unwrap());
                    // First 8 bytes are strid
                    packet_buf.copy_from_slice(&turmoil_udp_buffer[8..]);
                    packet_meta.addr = addr;
                    packet_meta.len = bytes_received - 8;
                    packet_meta.stride = if stride == 0 {
                        bytes_received - 8
                    } else {
                        stride
                    };
                    packet_meta.ecn = Some(Self::ECN);
                    packet_meta.dst_ip = Some(self.ip);
                }
                Err(e) => {
                    if matches!(e.kind(), io::ErrorKind::WouldBlock) {
                        break;
                    }
                    return Poll::Ready(Err(e));
                }
                _ => continue,
            }
            packets_received += 1;
        }

        Poll::Ready(Ok(packets_received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
/// Runs the tokio simulation until provided closure evaluates to true.
/// If Ok(true) is returned all clients have completed.
pub fn wait_for<F>(sim: &mut Sim, mut f: F) -> turmoil::Result
where
    F: FnMut() -> bool,
{
    while !f() {
        if sim.step()? {
            panic!("Simulation finished while checking condition");
        }
    }
    Ok(())
}

/// Runs the tokio simulation for the provided duration.
/// If Ok(true) is returned all clients have completed.
pub fn run_simulation_for(sim: &mut Sim, timeout: Duration) -> turmoil::Result {
    let now = sim.elapsed();
    loop {
        if sim.elapsed() > timeout + now {
            break;
        }
        if sim.step()? {
            panic!("Simulation finished while checking condition");
        }
    }
    Ok(())
}

/// Runs the tokio simulation until the timeout is reached.
/// Panics if simulation finishes or condition evaluates to true.
pub fn wait_for_timeout<F>(sim: &mut Sim, f: F, timeout: Duration) -> turmoil::Result
where
    F: Fn() -> bool,
{
    let now = sim.elapsed();
    loop {
        if f() {
            return Err("Provided condition evaluated to true".into());
        }

        if sim.elapsed() > timeout + now {
            break;
        }
        if sim.step()? {
            panic!("Simulation finished while checking condition");
        }
    }
    Ok(())
}

pub enum PeerManagerAction {
    Add((NodeId, RegistryVersion)),
    Remove((NodeId, RegistryVersion)),
}

pub fn add_peer_manager_to_sim(
    sim: &mut Sim,
    stop_notify: Arc<Notify>,
    log: ReplicaLogger,
) -> (
    mpsc::UnboundedSender<PeerManagerAction>,
    watch::Receiver<SubnetTopology>,
    RegistryConsensusHandle,
) {
    let (peer_manager_sender, mut peer_manager_receiver) = oneshot::channel();
    #[allow(clippy::disallowed_methods)]
    let (peer_manager_cmd_sender, mut peer_manager_cmd_receiver) = mpsc::unbounded_channel();
    sim.client("peer-manager", async move {
        let rt = tokio::runtime::Handle::current();
        let (_jh, topology_watcher, mut registry_handler) =
            create_peer_manager_and_registry_handle(&rt, log);

        let _ = peer_manager_sender.send((topology_watcher, registry_handler.clone()));

        // Listen for peer manager actions of finished notification.
        loop {
            select! {
                _ = stop_notify.notified() => {
                    break;
                }
                Some(action) = peer_manager_cmd_receiver.recv() => {
                    match action {
                        PeerManagerAction::Add((peer, rv)) => {
                            registry_handler.add_node(
                                rv,
                                peer,
                                Some(&turmoil::lookup(peer.to_string()).to_string())
                            );
                        }
                        PeerManagerAction::Remove((peer, rv)) => {
                            registry_handler.remove_node(
                                rv,
                                peer,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    });

    // Get topology receiver.
    loop {
        if let Ok((watcher, registry_handler)) = peer_manager_receiver.try_recv() {
            break (peer_manager_cmd_sender, watcher, registry_handler);
        }
        sim.step().unwrap();
    }
}

#[allow(clippy::type_complexity)]
pub fn add_transport_to_sim<F>(
    sim: &mut Sim,
    log: ReplicaLogger,
    peer: NodeId,
    registry_handler: RegistryConsensusHandle,
    topology_watcher: watch::Receiver<SubnetTopology>,
    conn_checker: Option<Router>,
    crypto: Option<Arc<dyn TlsConfig + Send + Sync>>,
    state_sync_client: Option<Arc<dyn StateSyncClient<Message = StateSyncMessage>>>,
    consensus_manager: Option<TestConsensus<U64Artifact>>,
    post_setup_future: F,
) where
    F: Fn(NodeId, Arc<dyn Transport>) -> BoxFuture<'static, ()> + Clone + 'static,
{
    let node_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 4100).into();
    let consensus_manager = consensus_manager.map(|m| Arc::new(RwLock::new(m.clone())));

    let node_crypto =
        crypto.unwrap_or_else(|| temp_crypto_component_with_tls_keys(&registry_handler, peer));
    registry_handler.registry_client.update_to_latest_version();

    sim.host(peer.to_string(), move || {
        let log = log.clone();
        let registry_client = registry_handler.registry_client.clone();
        let node_crypto_clone = node_crypto.clone();
        let conn_checker_clone = conn_checker.clone();
        let topology_watcher_clone = topology_watcher.clone();
        let post_setup_future_clone = post_setup_future.clone();
        let state_sync_client_clone = state_sync_client.clone();
        let consensus_manager_clone = consensus_manager.clone();

        async move {
            let metrics_registry = MetricsRegistry::default();
            let mut consensus_builder = ic_consensus_manager::ConsensusManagerBuilder::new(
                log.clone(),
                tokio::runtime::Handle::current(),
                metrics_registry,
            );

            let mut router = conn_checker_clone;
            let udp_listener = turmoil::net::UdpSocket::bind(node_addr).await.unwrap();
            let this_ip = turmoil::lookup(peer.to_string());
            let custom_udp = CustomUdp::new(this_ip, udp_listener);

            let state_sync_rx = if let Some(ref state_sync) = state_sync_client_clone {
                let (state_sync_router, state_sync_rx) = ic_state_sync_manager::build_axum_router(
                    state_sync.clone(),
                    log.clone(),
                    &MetricsRegistry::default(),
                );
                router = Some(router.unwrap_or_default().merge(state_sync_router));
                Some(state_sync_rx)
            } else {
                None
            };

            let _artifact_processor_jh = if let Some(consensus) = consensus_manager_clone {
                let (artifact_processor_jh, artifact_manager_event_rx, artifact_sender) =
                    start_test_processor(
                        consensus.clone(),
                        consensus.clone().read().unwrap().clone(),
                    );
                let bouncer_factory = Arc::new(consensus.clone().read().unwrap().clone());

                let downloader = FetchArtifact::new(
                    log.clone(),
                    tokio::runtime::Handle::current(),
                    consensus,
                    bouncer_factory,
                    MetricsRegistry::default(),
                );
                consensus_builder.add_client(
                    artifact_manager_event_rx,
                    artifact_sender,
                    downloader,
                );
                router = Some(router.unwrap_or_default().merge(consensus_builder.router()));

                Some(artifact_processor_jh)
            } else {
                None
            };

            let transport = Arc::new(QuicTransport::start(
                &log,
                &MetricsRegistry::default(),
                &tokio::runtime::Handle::current(),
                node_crypto_clone,
                registry_client,
                peer,
                topology_watcher_clone.clone(),
                Arc::new(custom_udp),
                router.unwrap_or_default(),
            ));

            consensus_builder.run(transport.clone(), topology_watcher_clone.clone());

            if let Some(state_sync_rx) = state_sync_rx {
                ic_state_sync_manager::start_state_sync_manager(
                    &log,
                    &MetricsRegistry::default(),
                    &tokio::runtime::Handle::current(),
                    transport.clone(),
                    state_sync_client_clone.unwrap().clone(),
                    state_sync_rx,
                );
            }

            post_setup_future_clone(peer, transport).await;
            Ok(())
        }
    });
}

pub fn waiter_fut(
) -> impl Fn(NodeId, Arc<dyn Transport>) -> BoxFuture<'static, ()> + Clone + 'static {
    |_, _| {
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        .boxed()
    }
}

#[allow(clippy::type_complexity)]
pub fn start_test_processor(
    pool: Arc<RwLock<TestConsensus<U64Artifact>>>,
    change_set_producer: TestConsensus<U64Artifact>,
) -> (
    Box<dyn JoinGuard>,
    mpsc::Receiver<ArtifactMutation<U64Artifact>>,
    mpsc::UnboundedSender<UnvalidatedArtifactMutation<U64Artifact>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let time_source = Arc::new(SysTimeSource::new());
    let client = ic_artifact_manager::Processor::new(pool, change_set_producer);
    let (jh, sender) = run_artifact_processor(
        time_source,
        MetricsRegistry::default(),
        Box::new(client),
        tx,
        vec![],
    );
    (jh, rx, sender)
}
