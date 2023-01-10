use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_transport::{
    Transport, TransportChannelId, TransportError, TransportEvent, TransportEventHandler,
    TransportPayload,
};
use ic_logger::ReplicaLogger;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_transport_test_utils::{
    basic_transport_message, basic_transport_message_v2, blocking_transport_message,
    create_mock_event_handler, get_free_localhost_port, large_transport_message, setup_test_peer,
    start_connection_between_two_peers, temp_crypto_component_with_tls_keys_in_registry,
    RegistryAndDataProvider, NODE_ID_1, NODE_ID_2, NODE_ID_3, NODE_ID_4, REG_V1,
    TRANSPORT_CHANNEL_ID,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Notify,
};
use tokio::time::Duration;

#[test]
fn test_basic_conn_legacy() {
    test_basic_conn_impl(false);
}

#[test]
fn test_basic_conn_h2() {
    test_basic_conn_impl(true);
}

// Test scenario: Two peers connect to each other, later one of them disconnects.
// Test expectation: Each peer should receive a PeerUp event, the peer that didn't
// issue the 'stop_connection' should receive a PeerDown event.
fn test_basic_conn_impl(use_h2: bool) {
    with_test_replica_logger(|logger| {
        let registry_version = REG_V1;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (event_handler_1, mut handle_1) = create_mock_event_handler();
        let (event_handler_2, mut handle_2) = create_mock_event_handler();
        let (_control_plane_1, control_plane_2) = start_connection_between_two_peers(
            rt.handle().clone(),
            logger,
            registry_version,
            10,
            event_handler_1,
            event_handler_2,
            NODE_ID_1,
            NODE_ID_2,
            use_h2,
        );

        rt.block_on(async {
            match handle_1.next_request().await {
                Some((TransportEvent::PeerUp(_), resp)) => {
                    resp.send_response(());
                }
                _ => panic!("Unexpected event"),
            }
            match handle_2.next_request().await {
                Some((TransportEvent::PeerUp(_), resp)) => {
                    resp.send_response(());
                }
                _ => panic!("Unexpected event"),
            }
        });
        control_plane_2.stop_connection(&NODE_ID_1);
        rt.block_on(async {
            match handle_1.next_request().await {
                Some((TransportEvent::PeerDown(_), resp)) => {
                    resp.send_response(());
                }
                _ => panic!("Unexpected event"),
            }
        });
    });
}

/*
Verifies that transport suffers "head of line problem" when peer is slow to consume messages.
- Peer A sends Peer B message, which will work fine.
- Then, B's event handler blocks to prevent B from reading additional messages.
- A sends a few more messages, but at this point queue will be full.
- Finally, we unblock B's event handler, and confirm all in-flight messages are delivered.
*/
#[test]
fn head_of_line_test_legacy() {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, _peer_a_receiver) = channel(5);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(5);

        let notify = Arc::new(Notify::new());
        let listener = notify.clone();

        // Create event handler that blocks on message
        let hol_event_handler =
            setup_blocking_event_handler(rt.handle().clone(), peer_b_sender, listener);

        let (_peer_a, _peer_b, messages_sent) = trigger_and_test_send_queue_full(
            rt.handle().clone(),
            logger,
            registry_version,
            1,
            event_handler_1,
            hol_event_handler,
            &mut peer_b_receiver,
            false,
        );

        // Unblock event handler and confirm in-flight messages are received.
        notify.notify_one();

        for _ in 1..=messages_sent {
            assert_eq!(
                peer_b_receiver.blocking_recv(),
                Some(basic_transport_message())
            );
        }
    });
}

/*
Establish connection with 2 peers, A and B.  Send message from A->B and B->A and confirm both are received
*/
#[test]
fn test_basic_message_send_legacy() {
    test_send_big_message_succeeds(false);
}

#[test]
fn test_basic_message_send_h2() {
    test_send_big_message_succeeds(true);
}

// StateSync may send chunks that are 100 MB big so we want to make sure a message of this size can be sent and received
// in both directions
fn test_send_big_message_succeeds(use_h2: bool) {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, mut peer_a_receiver) = channel(1);
        let peer_a_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(1);
        let peer_b_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_b_sender);

        let (peer_a, peer_b) = start_connection_between_two_peers(
            rt.handle().clone(),
            logger,
            registry_version,
            1,
            peer_a_event_handler,
            peer_b_event_handler,
            NODE_ID_1,
            NODE_ID_2,
            use_h2,
        );

        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

        // A sends message to B
        let res = peer_a.send(&NODE_ID_2, channel_id, large_transport_message());
        assert_eq!(res, Ok(()));
        assert_eq!(
            peer_b_receiver.blocking_recv(),
            Some(large_transport_message())
        );

        // B sends message to A
        let res2 = peer_b.send(&NODE_ID_1, channel_id, large_transport_message());
        assert_eq!(res2, Ok(()));
        assert_eq!(
            peer_a_receiver.blocking_recv(),
            Some(large_transport_message())
        );
    });
}

/*
Establish connection with 2 peers, A and B.  Confirm that connection stays alive even when
no messages are being sent. (In current implementation, this is ensured by heartbeats)
*/
#[test]
fn test_idle_connection_active_legacy() {
    test_idle_connection_active_impl(false);
}

#[test]
fn test_idle_connection_active_h2() {
    test_idle_connection_active_impl(true);
}

fn test_idle_connection_active_impl(use_h2: bool) {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, _peer_a_receiver) = channel(1);
        let peer_a_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(1);
        let peer_b_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_b_sender);

        let (peer_a, _peer_b) = start_connection_between_two_peers(
            rt.handle().clone(),
            logger,
            registry_version,
            1,
            peer_a_event_handler,
            peer_b_event_handler,
            NODE_ID_1,
            NODE_ID_2,
            use_h2,
        );
        std::thread::sleep(Duration::from_secs(20));

        let msg_1 = TransportPayload(vec![0xa; 1000000]);
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

        // A sends message to B to verify that the connection is still alive
        let res = peer_a.send(&NODE_ID_2, channel_id, msg_1.clone());
        assert_eq!(res, Ok(()));
        assert_eq!(peer_b_receiver.blocking_recv(), Some(msg_1));
    });
}

/*
Tests that clearing send queue unblocks queue from receiving more messages.
Set Peer B to block event handler so no messages are consumed
A sends messages until send queue full, confirm error
Call clear send queue
A sends another message, confirm queue can accept more messages
*/
#[test]
fn test_clear_send_queue_legacy() {
    test_clear_send_queue_impl(false);
}

#[test]
fn test_clear_send_queue_h2() {
    test_clear_send_queue_impl(true);
}

fn test_clear_send_queue_impl(use_h2: bool) {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, _peer_a_receiver) = channel(10);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(10);

        let listener = Arc::new(Notify::new());

        let hol_event_handler =
            setup_blocking_event_handler(rt.handle().clone(), peer_b_sender, listener);

        let queue_size = 10;

        let (peer_a, _peer_b, _messages_sent) = trigger_and_test_send_queue_full(
            rt.handle().clone(),
            logger,
            registry_version,
            queue_size,
            event_handler_1,
            hol_event_handler,
            &mut peer_b_receiver,
            use_h2,
        );

        peer_a.clear_send_queues(&NODE_ID_2);

        // Confirm that queue is completely clear by sending messages = queue size
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

        for _ in 0..queue_size {
            let res3 = peer_a.send(&NODE_ID_2, channel_id, basic_transport_message_v2());
            assert_eq!(res3, Ok(()));
        }
    });
}

/*
Tests that draining the send queue unblocks queue from receiving more messages.
Set Peer B to block event handler so no messages are consumed
A sends messages until send queue full, confirm error
Call clear send queue
A sends another message, confirm queue can accept more messages
*/
#[test]
fn test_drain_send_queue_legacy() {
    test_drain_send_queue_impl(false);
}

#[test]
fn test_drain_send_queue_h2() {
    test_drain_send_queue_impl(true);
}

fn test_drain_send_queue_impl(use_h2: bool) {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();
        let queue_size = 10;

        let (peer_a_sender, _peer_a_receiver) = channel(10);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(10);

        let listener = Arc::new(Notify::new());
        let notify = listener.clone();

        let hol_event_handler =
            setup_blocking_event_handler(rt.handle().clone(), peer_b_sender, listener);

        let (peer_a, _peer_b, messages_sent) = trigger_and_test_send_queue_full(
            rt.handle().clone(),
            logger,
            registry_version,
            queue_size,
            event_handler_1,
            hol_event_handler,
            &mut peer_b_receiver,
            use_h2,
        );

        // Unblock event handler to drain queue and confirm in-flight messages are received.
        notify.notify_one();

        for _ in 1..=messages_sent {
            assert_eq!(
                peer_b_receiver.blocking_recv(),
                Some(basic_transport_message())
            );
        }
        // Confirm that queue is clear by sending messages = queue size
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

        for _ in 0..queue_size {
            let res3 = peer_a.send(&NODE_ID_2, channel_id, basic_transport_message_v2());
            assert_eq!(res3, Ok(()));
            std::thread::sleep(Duration::from_millis(10));
        }
        for _ in 0..queue_size {
            assert_eq!(
                peer_b_receiver.blocking_recv(),
                Some(basic_transport_message_v2())
            );
        }
    });
}

/*
Test connection and message sending at a larger scale:
Creates peer A and connect it to 3 other peers (B-D)
Send a high volume of messages from all nodes to A
*/
#[test]
fn test_multiple_connections_to_single_peer_legacy() {
    test_multiple_connections_to_single_peer_impl(false);
}

#[test]
fn test_multiple_connections_to_single_peer_h2() {
    test_multiple_connections_to_single_peer_impl(true);
}

fn test_multiple_connections_to_single_peer_impl(use_h2: bool) {
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();

        let mut nodes = create_n_peers(
            vec![NODE_ID_1, NODE_ID_2, NODE_ID_3, NODE_ID_4],
            rt.handle().clone(),
            logger,
            50,
            use_h2,
        );
        let remainder = nodes.split_off(1);
        connect_nodes_to_central_node(&nodes[0], &remainder);

        let mut successful_sends = 0;
        let sends_per_peer = 500;
        for node_data in remainder {
            let node_b = node_data.0;
            let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);
            for _ in 1..=sends_per_peer {
                if node_b
                    .send(&NODE_ID_1, channel_id, basic_transport_message())
                    .is_ok()
                {
                    successful_sends += 1;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        for _ in 1..=successful_sends {
            assert_eq!(nodes[0].3.blocking_recv(), Some(basic_transport_message()));
        }
    });
}

// helper functions
type PeerData<T> = (Arc<dyn Transport>, SocketAddr, NodeId, Receiver<T>);

fn create_n_peers(
    peer_ids: Vec<NodeId>,
    rt_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    channel_size: usize,
    use_h2: bool,
) -> Vec<PeerData<TransportPayload>> {
    let registry_version = REG_V1;
    let mut registry_and_data = RegistryAndDataProvider::new();

    let crypto_factory = |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
        Arc::new(temp_crypto_component_with_tls_keys_in_registry(
            registry_and_data,
            node_id,
        )) as Arc<dyn TlsHandshake + Send + Sync>
    };

    let mut nodes = vec![];

    for peer_id in peer_ids {
        let (peer_i_sender, peer_i_receiver) = channel(channel_size);
        let event_handler_i = setup_message_ack_event_handler(rt_handle.clone(), peer_i_sender);

        let (peer, addr) = setup_test_peer(
            logger.clone(),
            rt_handle.clone(),
            peer_id,
            get_free_localhost_port().expect("Failed to get free localhost port"),
            registry_version,
            &mut registry_and_data,
            crypto_factory,
            event_handler_i,
            use_h2,
        );
        nodes.push((peer, addr, peer_id, peer_i_receiver));
    }
    registry_and_data.registry.update_to_latest_version();
    nodes
}

// creates connection between central node and each 'peer'
fn connect_nodes_to_central_node<T>(central_node_data: &PeerData<T>, peer_data: &Vec<PeerData<T>>) {
    let (central_node, central_node_addr, central_node_id, _) = central_node_data;

    for peer_data_i in peer_data {
        let (peer_i, peer_i_addr, peer_i_id, _) = peer_data_i;

        central_node.start_connection(peer_i_id, *peer_i_addr, REG_V1);
        peer_i.start_connection(central_node_id, *central_node_addr, REG_V1);
    }
}

// helper functions
fn setup_message_ack_event_handler(
    rt: tokio::runtime::Handle,
    connected: Sender<TransportPayload>,
) -> TransportEventHandler {
    let (event_handler, mut handle) = create_mock_event_handler();

    rt.spawn(async move {
        while let Some(res) = handle.next_request().await {
            let (event, rsp) = res;
            match event {
                TransportEvent::Message(msg) => {
                    connected.send(msg.payload).await.expect("Channel busy");
                }
                TransportEvent::PeerUp(_) => {}
                TransportEvent::PeerDown(_) => {}
            };
            rsp.send_response(());
        }
    });
    event_handler
}

fn setup_blocking_event_handler(
    rt: tokio::runtime::Handle,
    sender: Sender<TransportPayload>,
    listener: Arc<Notify>,
) -> TransportEventHandler {
    let (event_handler, mut handle) = create_mock_event_handler();

    rt.spawn(async move {
        while let Some(res) = handle.next_request().await {
            let (event, rsp) = res;
            match event {
                TransportEvent::Message(msg) => {
                    sender
                        .send(msg.payload.clone())
                        .await
                        .expect("Channel busy");
                    // This will block the read task
                    if msg.payload == blocking_transport_message() {
                        listener.notified().await;
                    }
                }
                TransportEvent::PeerUp(_) => {}
                TransportEvent::PeerDown(_) => {}
            }
            rsp.send_response(());
        }
    });
    event_handler
}

fn trigger_and_test_send_queue_full(
    rt_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    registry_version: RegistryVersion,
    send_queue_size: usize,
    event_handler_a: TransportEventHandler,
    event_handler_b: TransportEventHandler,
    peer_b_receiver: &mut Receiver<TransportPayload>,
    use_h2: bool,
) -> (Arc<dyn Transport>, Arc<dyn Transport>, i32) {
    let (peer_a, _peer_b) = start_connection_between_two_peers(
        rt_handle,
        logger,
        registry_version,
        send_queue_size,
        event_handler_a,
        event_handler_b,
        NODE_ID_1,
        NODE_ID_2,
        use_h2,
    );
    let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

    // A sends message to B
    let res = peer_a.send(&NODE_ID_2, channel_id, blocking_transport_message());
    assert_eq!(res, Ok(()));
    assert_eq!(
        peer_b_receiver.blocking_recv(),
        Some(blocking_transport_message())
    );
    // Send messages from A->B until TCP Queue is full
    let _basic_msg = basic_transport_message();
    let mut messages_sent = 0;
    loop {
        if let Err(TransportError::SendQueueFull(_basic_msg)) =
            peer_a.send(&NODE_ID_2, channel_id, basic_transport_message())
        {
            break;
        }
        messages_sent += 1;
        std::thread::sleep(Duration::from_millis(10));
    }
    let res2 = peer_a.send(&NODE_ID_2, channel_id, basic_transport_message());
    assert_eq!(
        res2,
        Err(TransportError::SendQueueFull(basic_transport_message()))
    );

    (peer_a, _peer_b, messages_sent)
}

fn setup_peer_up_ack_event_handler(
    rt: tokio::runtime::Handle,
    connected: Sender<bool>,
) -> TransportEventHandler {
    let (event_handler, mut handle) = create_mock_event_handler();
    rt.spawn(async move {
        while let Some(req) = handle.next_request().await {
            let (event, rsp) = req;
            if let TransportEvent::PeerUp(_) = event {
                connected
                    .try_send(true)
                    .expect("Channel capacity should not be reached");
            }
            rsp.send_response(());
        }
    });
    event_handler
}
