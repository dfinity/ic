use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{routing::any, Router};
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use either::Either;
use http::Request;
use ic_icos_sev::Sev;
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::{
    create_registry_handle, temp_crypto_component_with_tls_keys, RegistryConsensusHandle,
};
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{DummyUdpSocket, QuicTransport, Transport};
use ic_types::NodeId;
use ic_types_test_utils::ids::node_test_id;
use tokio::{runtime::Handle, sync::watch, task::JoinSet};

const NUM_NODES: u64 = 40;
const PARALLEL_REQUESTS: u64 = 100;
const REQUEST_SIZE_BYTES: u64 = 512000;
const RESPONSE_SIZE_BYTES: u64 = 512;

async fn pong() -> String {
    "a".repeat(RESPONSE_SIZE_BYTES as usize)
}

fn spawn_transport(
    log: ReplicaLogger,
    rt: Handle,
    id: u64,
    watch_rx: watch::Receiver<SubnetTopology>,
    registry_handle: RegistryConsensusHandle,
) -> (Arc<dyn Transport>, NodeId, SocketAddr) {
    let node_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 8000 + id as u16).into();
    let node_id = node_test_id(id);
    let tls = temp_crypto_component_with_tls_keys(&registry_handle, node_id);
    let sev = Arc::new(Sev::new(node_id, registry_handle.registry_client.clone()));
    registry_handle.registry_client.reload();
    registry_handle.registry_client.update_to_latest_version();

    let transport = Arc::new(QuicTransport::build(
        &log,
        &MetricsRegistry::default(),
        rt,
        tls,
        registry_handle.registry_client.clone(),
        sev,
        node_id,
        watch_rx,
        Either::<_, DummyUdpSocket>::Left(node_addr),
        Some(Router::new().route("/", any(pong))),
    ));
    (transport, node_id, node_addr)
}

fn bench_transport(criterion: &mut Criterion) {
    let log = no_op_logger();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = criterion.benchmark_group("quic-transport-send-throughput");

    let (watch_tx, watch_rx) = watch::channel(SubnetTopology::default());
    let (_mock, registry_handle) = create_registry_handle();

    let mut transports = Vec::new();

    for i in 0..NUM_NODES {
        transports.push(spawn_transport(
            log.clone(),
            rt.handle().clone(),
            i,
            watch_rx.clone(),
            registry_handle.clone(),
        ));
    }
    watch_tx
        .send(SubnetTopology::new(
            transports
                .iter()
                .map(|(_, node_id, addr)| (*node_id, *addr)),
            0.into(),
            1.into(),
        ))
        .unwrap();

    let test_transport = transports.get(0).unwrap().0.clone();

    rt.block_on(async { tokio::time::sleep(Duration::from_secs(5)).await });
    let num_request_per_iter = (transports.len() as u64 - 1) * PARALLEL_REQUESTS;
    group.throughput(Throughput::Elements(num_request_per_iter));
    group.bench_with_input("Number of messages", &test_transport, |b, transport| {
        b.to_async(&rt).iter_batched(
            || {
                let mut futs = Vec::new();
                for _ in 0..PARALLEL_REQUESTS {
                    let transport_c = transport.clone();
                    futs.push(async move {
                        for peer in transport_c.peers() {
                            let t = transport_c.clone();
                            t.rpc(
                                &peer,
                                Request::builder()
                                    .uri("/")
                                    .body(Bytes::from(vec![0; REQUEST_SIZE_BYTES as usize]))
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        }
                    })
                }
                futs
            },
            |futs| async {
                let mut js = JoinSet::new();
                for f in futs {
                    js.spawn(f);
                }
                while let Some(a) = js.join_next().await {
                    a.unwrap();
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_transport);
criterion_main!(benches);
