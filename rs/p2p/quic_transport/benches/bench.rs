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

const NUM_NODES: u64 = 2;
const PARALLEL_REQUESTS: u64 = 1000;
const REQUEST_SIZE_BYTES: u64 = 64;
const RESPONSE_SIZE_BYTES: u64 = 32;

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

fn bench_transport(criterion: &mut Criterion<criterion_time::ProcessTime>) {
    let log = no_op_logger();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
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
    let peers: Vec<NodeId> = transports
        .iter()
        .skip(1)
        .map(|(_, node_id, _)| *node_id)
        .collect();

    rt.block_on(async { tokio::time::sleep(Duration::from_secs(5)).await });
    let num_request_per_iter = (transports.len() as u64 - 1) * PARALLEL_REQUESTS;
    group.throughput(Throughput::Elements(num_request_per_iter));
    // group.throughput(Throughput::Bytes(num_request_per_iter * REQUEST_SIZE_BYTES));
    group.bench_with_input("RPC", &test_transport, |b, transport| {
        // Generate all the futures in advance including the request to not measure setup time.
        b.to_async(&rt).iter_batched(
            || {
                let mut futs = Vec::new();
                for _ in 0..PARALLEL_REQUESTS {
                    let transport_c = transport.clone();
                    for peer in peers.iter() {
                        let bytes = Bytes::from(vec![0; REQUEST_SIZE_BYTES as usize]);
                        let t = transport_c.clone();
                        let p = *peer;
                        futs.push(async move {
                            t.rpc(&p, Request::builder().uri("/").body(bytes).unwrap())
                                .await
                                .unwrap();
                        });
                    }
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
            BatchSize::PerIteration,
        );
    });
    group.bench_with_input("PUSH", &test_transport, |b, transport| {
        b.to_async(&rt).iter_batched(
            // Generate all the futures in advance including the request to not measure setup time.
            || {
                let mut futs = Vec::new();
                for _ in 0..PARALLEL_REQUESTS {
                    let transport_c = transport.clone();
                    for peer in peers.iter() {
                        let bytes = Bytes::from(vec![0; REQUEST_SIZE_BYTES as usize]);
                        let t = transport_c.clone();
                        let p = *peer;
                        futs.push(async move {
                            t.push(&p, Request::builder().uri("/").body(bytes).unwrap())
                                .await
                                .unwrap();
                        });
                    }
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
            BatchSize::PerIteration,
        );
    });
    group.bench_with_input("PEERS", &test_transport, |b, transport| {
        b.to_async(&rt).iter(|| async {
            let _ = transport.peers();
        });
    });
    group.finish();
}


fn main() {
    let mut c = Criterion::default()
        .with_measurement(criterion_time::ProcessTime::UserTime)
        .warm_up_time(Duration::from_secs(10));

    bench_transport(&mut c);
    c.final_summary();
}
