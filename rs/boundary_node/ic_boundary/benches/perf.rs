use std::{net::SocketAddr, time::Duration};

use candid::Principal;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use ic_bn_lib::http::server;
use ic_types::messages::{Blob, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery};
use rand::prelude::*;
use tokio_util::sync::CancellationToken;

use ic_boundary::test_utils::setup_test_router;

fn gen_request(cli: &reqwest::Client, addr: &SocketAddr, bytes_size: usize) -> reqwest::Request {
    let mut rng = rand::thread_rng();

    let canister_id: u64 = rng.gen_range(0..100_000_000);
    let canister_id = Principal::from_slice(canister_id.to_be_bytes().as_slice());

    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "foobar".to_string(),
            arg: Blob("a".repeat(bytes_size).as_bytes().to_vec()),
            sender: Blob(Principal::anonymous().as_slice().to_vec()),
            nonce: None,
            ingress_expiry: 1234,
        },
    };

    let envelope = HttpRequestEnvelope::<HttpQueryContent> {
        content,
        sender_delegation: None,
        sender_pubkey: None,
        sender_sig: None,
    };

    let body = serde_cbor::to_vec(&envelope).unwrap();

    cli.post(format!("http://{addr}/api/v2/canister/{canister_id}/query"))
        .body(body)
        .build()
        .unwrap()
}

fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ic_boundary_router");
    group.throughput(Throughput::Elements(1));
    group.significance_level(0.1);
    group.sample_size(250);
    group.measurement_time(Duration::from_secs(15));

    let (app, _) = setup_test_router(true, true, 40, 15, 16384, None);

    let server_opts = server::Options {
        backlog: 256,
        http1_header_read_timeout: Duration::from_secs(15),
        http2_max_streams: 1000,
        http2_keepalive_interval: Duration::from_secs(60),
        http2_keepalive_timeout: Duration::from_secs(30),
        grace_period: Duration::from_secs(60),
        max_requests_per_conn: Some(1000),
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    runtime.spawn(async move {
        let listener =
            server::Listener::new(server::Addr::Tcp("127.0.0.1:0".parse().unwrap()), 1024).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = server::Server::new_with_registry(
            server::Addr::Tcp("127.0.0.1:0".parse().unwrap()),
            app,
            server_opts,
            &prometheus::Registry::new(),
            None,
        );

        tx.send(addr).unwrap();
        server
            .serve_with_listener(listener, CancellationToken::new())
            .await
            .expect("server error");
    });

    let addr = runtime.block_on(async { rx.await.unwrap() });

    let cli = reqwest::ClientBuilder::new().build().unwrap();

    for req_size in [1024, 4096, 8192, 16384].iter() {
        group.bench_with_input(
            BenchmarkId::new("response_time_vs_request_size_bytes", req_size),
            req_size,
            |b, &size| {
                b.to_async(&runtime).iter_batched(
                    || gen_request(&cli, &addr, size),
                    |req| async {
                        let resp = cli.execute(req).await.unwrap();
                        resp.text().await.unwrap();
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
