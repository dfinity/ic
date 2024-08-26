use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::http::Request;
use axum::{routing::any, Router};
use bytes::Bytes;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
    Throughput,
};
use ic_base_types::NodeId;
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::{
    create_registry_handle, temp_crypto_component_with_tls_keys, RegistryConsensusHandle,
};
use ic_quic_transport::{create_udp_socket, QuicTransport, SubnetTopology, Transport};
use ic_types_test_utils::ids::node_test_id;
use tokio::{
    runtime::{Handle, Runtime},
    sync::watch,
    task::JoinSet,
};

/// Benchmark tests RPS and throughput from one to NUM_NODES-1 with PARALLEL_REQUESTS number of requests at once.
/// Adjust these values to test different scenarios.
const NUM_NODES: u64 = 13;
const PARALLEL_REQUESTS: u64 = 10;
const REQUEST_SIZE_BYTES: u64 = 1000000;
const RESPONSE_SIZE_BYTES: u64 = 10;

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
    registry_handle.registry_client.reload();
    registry_handle.registry_client.update_to_latest_version();

    let transport = Arc::new(QuicTransport::start(
        &log,
        &MetricsRegistry::default(),
        &rt,
        tls,
        registry_handle.registry_client.clone(),
        node_id,
        watch_rx,
        create_udp_socket(&rt, node_addr),
        Router::new().route("/", any(pong)),
    ));
    (transport, node_id, node_addr)
}

async fn all_peers_up(transport: Arc<dyn Transport>, peers: Vec<NodeId>) {
    loop {
        let mut one_peer_down = false;
        for peer in &peers {
            if transport
                .push(
                    peer,
                    Request::builder().uri("/").body(Bytes::new()).unwrap(),
                )
                .await
                .is_err()
            {
                one_peer_down = true
            }
        }
        if !one_peer_down {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn bench_transport(criterion: &mut Criterion) {
    let log = no_op_logger();
    let rt = tokio::runtime::Runtime::new().unwrap();

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

    let test_transport = transports.first().unwrap().0.clone();
    let peers: Vec<NodeId> = transports
        .iter()
        .skip(1)
        .map(|(_, node_id, _)| *node_id)
        .collect();

    rt.block_on(all_peers_up(test_transport.clone(), peers.clone()));
    let num_request_per_iter = (transports.len() as u64 - 1) * PARALLEL_REQUESTS;

    println!(
        "Number of requests per iteration: {}",
        pretty_print(num_request_per_iter)
    );
    println!(
        "Transferred request data per iteration: {} Bytes",
        pretty_print(num_request_per_iter * REQUEST_SIZE_BYTES)
    );
    println!(
        "Transferred request data per iteration per peer: {} Bytes",
        pretty_print(num_request_per_iter * REQUEST_SIZE_BYTES / NUM_NODES)
    );
    println!(
        "Transferred response data per iteration: {} Bytes",
        pretty_print(num_request_per_iter * RESPONSE_SIZE_BYTES)
    );
    println!(
        "Transferred response data per iteration per peer: {} Bytes",
        pretty_print(num_request_per_iter * RESPONSE_SIZE_BYTES / NUM_NODES)
    );

    let mut group = criterion.benchmark_group("quic-transport-send-rps");
    // Measurement config
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(20);

    // Measure throughput in requests/s
    group.throughput(Throughput::Elements(num_request_per_iter));
    bench_inner(&mut group, &rt, test_transport.clone(), peers.clone(), true);
    group.finish();

    let mut group = criterion.benchmark_group("quic-transport-send-throughput");
    // Measurement config
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(20);

    // Measure throughput in Bytes/s
    group.throughput(Throughput::Bytes(
        num_request_per_iter * REQUEST_SIZE_BYTES + RESPONSE_SIZE_BYTES,
    ));
    bench_inner(
        &mut group,
        &rt,
        test_transport.clone(),
        peers.clone(),
        false,
    );
    group.finish();
}

fn bench_inner(
    group: &mut BenchmarkGroup<WallTime>,
    rt: &Runtime,
    test_transport: Arc<dyn Transport>,
    peers: Vec<NodeId>,
    test_peers: bool,
) {
    group.bench_with_input("RPC", &test_transport, |b, transport| {
        // Generate all the futures in advance including the request to not measure setup time.
        b.to_async(rt).iter_batched(
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
            BatchSize::SmallInput,
        );
    });
    group.bench_with_input("PUSH", &test_transport, |b, transport| {
        b.to_async(rt).iter_batched(
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
            BatchSize::SmallInput,
        );
    });
    if test_peers {
        group.bench_with_input("PEERS", &test_transport, |b, transport| {
            b.to_async(rt).iter(|| async {
                let _ = transport.peers();
            });
        });
    }
}

fn pretty_print(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let mut counter = 0;

    for c in s.chars().rev() {
        counter += 1;
        result.insert(0, c);
        if counter % 3 == 0 && counter != s.len() {
            result.insert(0, ',');
        }
    }

    result
}

criterion_group!(benches, bench_transport);
criterion_main!(benches);
