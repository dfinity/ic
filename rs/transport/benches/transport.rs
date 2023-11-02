use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use futures::FutureExt;
use ic_interfaces_transport::{TransportChannelId, TransportEvent, TransportPayload};
use ic_logger::replica_logger::no_op_logger;
use ic_transport_test_utils::{
    RegistryAndDataProvider, TestPeerBuilder, TestTopology, TestTopologyBuilder, NODE_ID_1,
    NODE_ID_2,
};
use std::sync::{mpsc::TryRecvError, Arc};
use tokio::{
    select,
    sync::{
        mpsc::{self, Sender},
        Notify,
    },
};
use tower_test::mock::Handle;

/// Measure transport throughput from the sender side. Only `transport.send` that return `Ok`
/// are counted. Because `transport.send` can fail if the queue is full, which we shouldn't
/// count towards the throughput.
fn send_bench(criterion: &mut Criterion) {
    // 128B, 1Kb, 10Kb, 100Kb, 1Mb
    let payload_sizes = [128, 1024, 10 * 1024, 100 * 1024, 1024 * 1024];
    let payloads = payload_sizes
        .into_iter()
        .map(|s| TransportPayload(vec![0_u8; s]))
        .collect::<Vec<_>>();

    send_bench_inner(criterion, payloads.clone(), false, 1000);
    send_bench_inner(criterion, payloads, true, 1000);
}

fn setup_send_test_topology(
    rt: tokio::runtime::Handle,
    use_h2: bool,
    send_queue_size: usize,
) -> (TestTopology, Sender<()>, Sender<()>) {
    let registry_data = RegistryAndDataProvider::new();

    let (stop_peer1_tx, mut stop_peer1_rx) = mpsc::channel(1);
    let peer1_expectations = |mut handle: Handle<TransportEvent, ()>| {
        async move {
            loop {
                select! {
                    _ = stop_peer1_rx.recv() => break,
                    req = handle.next_request() => {
                        if let Some((_,resp)) = req {
                            resp.send_response(());
                        }
                    },
                }
            }
        }
        .boxed()
    };
    let (stop_peer2_tx, mut stop_peer2_rx) = mpsc::channel(1);
    let peer2_expectations = |mut handle: Handle<TransportEvent, ()>| {
        async move {
            loop {
                select! {
                    _ = stop_peer2_rx.recv() => break,
                    req = handle.next_request() => {
                        if let Some((_,resp)) = req {
                            resp.send_response(());
                        }
                    },
                }
            }
        }
        .boxed()
    };

    let peer1 = TestPeerBuilder::new(NODE_ID_1, rt.clone(), registry_data.clone(), no_op_logger())
        .h2(use_h2)
        .send_queue_size(send_queue_size)
        .build();

    let peer2 = TestPeerBuilder::new(NODE_ID_2, rt.clone(), registry_data.clone(), no_op_logger())
        .h2(use_h2)
        .send_queue_size(send_queue_size)
        .build();

    (
        TestTopologyBuilder::new(registry_data, rt)
            .add_node(peer1, peer1_expectations)
            .add_node(peer2, peer2_expectations)
            .full_mesh(),
        stop_peer1_tx,
        stop_peer2_tx,
    )
}

#[allow(clippy::type_complexity)]
fn setup_receive_test_topology(
    rt: tokio::runtime::Handle,
    use_h2: bool,
    send_queue_size: usize,
) -> (
    TestTopology,
    (Arc<Notify>, Sender<()>),
    (Arc<Notify>, Sender<()>),
) {
    let registry_data = RegistryAndDataProvider::new();

    let (stop_peer1_tx, mut stop_peer1_rx) = mpsc::channel(1);
    let msg_counter_peer1 = Arc::new(Notify::new());
    let msg_counter_peer1_c = msg_counter_peer1.clone();
    let peer1_expectations = |mut handle: Handle<TransportEvent, ()>| {
        async move {
            loop {
                select! {
                    _ = stop_peer1_rx.recv() => break,
                    req = handle.next_request() => {
                        match req {
                            Some((TransportEvent::Message(_), resp)) => {
                                msg_counter_peer1_c.notify_one();
                                resp.send_response(());
                            }
                            Some((_, resp)) => {
                                resp.send_response(());
                            }
                            None => {}
                        }
                    },
                }
            }
        }
        .boxed()
    };
    let (stop_peer2_tx, mut stop_peer2_rx) = mpsc::channel(1);
    let msg_counter_peer2 = Arc::new(Notify::new());
    let msg_counter_peer2_c = msg_counter_peer2.clone();
    let peer2_expectations = |mut handle: Handle<TransportEvent, ()>| {
        async move {
            loop {
                select! {
                    _ = stop_peer2_rx.recv() => break,
                    req = handle.next_request() => {
                        match req {
                            Some((TransportEvent::Message(_), resp)) => {
                                msg_counter_peer2_c.notify_one();
                                resp.send_response(());
                            }
                            Some((_, resp)) => {
                                resp.send_response(());
                            }
                            None => {}
                        }
                    },
                }
            }
        }
        .boxed()
    };

    let peer1 = TestPeerBuilder::new(NODE_ID_1, rt.clone(), registry_data.clone(), no_op_logger())
        .h2(use_h2)
        .send_queue_size(send_queue_size)
        .build();

    let peer2 = TestPeerBuilder::new(NODE_ID_2, rt.clone(), registry_data.clone(), no_op_logger())
        .h2(use_h2)
        .send_queue_size(send_queue_size)
        .build();

    (
        TestTopologyBuilder::new(registry_data, rt)
            .add_node(peer1, peer1_expectations)
            .add_node(peer2, peer2_expectations)
            .full_mesh(),
        (msg_counter_peer1, stop_peer1_tx),
        (msg_counter_peer2, stop_peer2_tx),
    )
}

fn send_bench_inner(
    criterion: &mut Criterion,
    payloads: Vec<TransportPayload>,
    use_h2: bool,
    send_queue_size: usize,
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = criterion.benchmark_group(format!(
        "transport-send-throughput-h2-{}-sendqueue-{}",
        use_h2, send_queue_size
    ));
    for payload in payloads.into_iter() {
        let (mut topology, stop_peer1, stop_peer2) =
            setup_send_test_topology(rt.handle().clone(), use_h2, send_queue_size);

        group.throughput(Throughput::Bytes(payload.0.len() as u64));
        group.bench_with_input(
            format!("send throughput payload size={}", payload.0.len()),
            &payload,
            |b, p| {
                b.iter(|| {
                    // Wait till we can actually send a message. By retrying errors we avoid counting
                    // `QueueFull` as a successful send.
                    while topology
                        .send_payload(NODE_ID_2, NODE_ID_1, TransportChannelId::from(1), p.clone())
                        .is_err()
                    {}
                })
            },
        );
        topology.stop_peer_connection(NODE_ID_1, NODE_ID_2);
        topology.stop_peer_connection(NODE_ID_2, NODE_ID_1);
        stop_peer1.blocking_send(()).unwrap();
        stop_peer2.blocking_send(()).unwrap();
        topology.verify_all_peers_down();
    }
    group.finish();
}

/// Measure transport throughput between from the receiver side. Everytime event handler on
/// the receiver side is called we count it towards the throughput.
fn receive_bench(criterion: &mut Criterion) {
    // 128B, 1Kb, 10Kb, 100Kb, 1Mb
    let payload_sizes = [128, 1024, 10 * 1024, 100 * 1024, 1024 * 1024];
    let payloads = payload_sizes
        .into_iter()
        .map(|s| TransportPayload(vec![0_u8; s]))
        .collect::<Vec<_>>();

    receive_bench_inner(criterion, payloads.clone(), false, 1000);
    receive_bench_inner(criterion, payloads, true, 1000);
}

fn receive_bench_inner(
    criterion: &mut Criterion,
    payloads: Vec<TransportPayload>,
    use_h2: bool,
    send_queue_size: usize,
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = criterion.benchmark_group(format!(
        "transport-receive-throughput-h2-{}-sendqueue-{}",
        use_h2, send_queue_size
    ));
    for payload in payloads.into_iter() {
        group.throughput(Throughput::Bytes(payload.0.len() as u64));
        let (topology, (counter_peer1, stop_peer1), (_, stop_peer2)) =
            setup_receive_test_topology(rt.handle().clone(), use_h2, send_queue_size);

        let (tx, rx) = std::sync::mpsc::channel();
        let p_c = payload.clone();
        // Spawn thread that sends the payload in a loop.
        let jh = std::thread::spawn(move || {
            loop {
                match rx.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        break;
                    }
                    Err(TryRecvError::Empty) => {}
                }
                topology
                    .send_payload(
                        NODE_ID_2,
                        NODE_ID_1,
                        TransportChannelId::from(1),
                        p_c.clone(),
                    )
                    .ok();
            }
            topology
        });

        group.bench_function(
            format!("receive throughput payload size={}", payload.0.len()),
            // Wait for one payload to arrive.
            |b| b.to_async(&rt).iter(|| counter_peer1.notified()),
        );

        let _ = tx.send(());
        let mut topology = jh.join().unwrap();
        topology.stop_peer_connection(NODE_ID_1, NODE_ID_2);
        topology.stop_peer_connection(NODE_ID_2, NODE_ID_1);
        stop_peer1.blocking_send(()).unwrap();
        stop_peer2.blocking_send(()).unwrap();
        topology.verify_all_peers_down();
    }

    group.finish();
}

criterion_group!(benches, receive_bench, send_bench);
criterion_main!(benches);
