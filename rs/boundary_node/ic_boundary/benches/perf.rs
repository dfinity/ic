use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};

use axum::Server;
use candid::Principal;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use ic_types::messages::{Blob, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery};
use rand::prelude::*;

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

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    runtime.spawn(async move {
        let server = Server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());
        tx.send(()).unwrap();
        server.await.expect("server error");
    });

    runtime.block_on(async {
        rx.await.unwrap();
    });

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

// Don't remove, sometimes useful for manual measurements
#[allow(dead_code)]
#[tokio::main]
async fn main2() {
    use std::time::Instant;

    let (app, _) = setup_test_router(false, false, 100, 50, 16384, None); // 16k is > than 97% IC responses
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let server = Server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());
        tx.send(()).unwrap();
        server.await.expect("server error");
    });

    rx.await.unwrap();

    let cli = reqwest::ClientBuilder::new().build().unwrap();

    let n = 1;
    let start = Instant::now();

    for _ in 0..n {
        let req = gen_request(&cli, &addr, 1024);
        let resp = cli.execute(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        resp.text().await.unwrap();
    }

    println!("{:?}", start.elapsed() / n);
}
