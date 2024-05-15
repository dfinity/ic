use hyper::{
    client::{connect::HttpConnector, Client},
    Body, Error, Method, Request, Response, StatusCode,
};
use ic_config::metrics::{Config, Exporter};
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_metrics::registry::MetricsRegistry;
use ic_test_utilities_logger::with_test_replica_logger;
use prometheus::{
    core::{Collector, Desc},
    proto::MetricFamily,
};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::mpsc::{channel, Sender},
    time::sleep,
};
use tower::util::ServiceExt;

// Get a free port on this host to which we can connect transport to.
fn get_free_localhost_port() -> std::io::Result<SocketAddr> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(false)?;
    socket.set_reuseaddr(false)?;
    socket.bind("127.0.0.1:0".parse().unwrap())?;
    socket.local_addr()
}

async fn send_request(
    client: &Client<HttpConnector, Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Error> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}", addr))
        .body(Body::from(""))
        .expect("Building the request failed.");

    client.request(req).await
}

/// Once no bytes are read for the duration of 'connection_read_timeout_seconds', then
/// the connection is dropped.
#[tokio::test]
async fn test_connection_read_timeout() {
    with_test_replica_logger(|log| async move {
        let rt_handle = tokio::runtime::Handle::current();
        let addr = get_free_localhost_port().unwrap();
        let config = Config {
            exporter: Exporter::Http(addr),
            connection_read_timeout_seconds: 2,
            ..Default::default()
        };
        let metrics_registry = MetricsRegistry::default();
        let _metrics_endpoint = MetricsHttpEndpoint::new(
            rt_handle,
            config.clone(),
            metrics_registry,
            &log.inner_logger.root,
        );

        let target_stream = TcpStream::connect(addr).await.unwrap();

        let (mut request_sender, connection) =
            hyper::client::conn::handshake(target_stream).await.unwrap();

        // Spawn a task to poll the connection and drive the HTTP state.
        tokio::spawn(async move {
            connection.await.unwrap();
        });

        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}", addr))
            .body(Body::from(""))
            .expect("Building the request failed.");
        let response = request_sender.send_request(request).await.unwrap();
        assert!(response.status() == StatusCode::OK);

        sleep(Duration::from_secs(
            config.connection_read_timeout_seconds + 1,
        ))
        .await;
        assert!(request_sender.ready().await.err().unwrap().is_closed());
    })
    .await
}

#[derive(Clone)]
struct BlockingCollector {
    test_desc: Desc,
    sender: Sender<()>,
    collect_calls: Arc<AtomicUsize>,
}

impl BlockingCollector {
    fn new(sender: Sender<()>) -> Self {
        let mut hm = std::collections::HashMap::new();
        let _ = hm.insert("x".to_string(), "y".to_string());
        let test_desc =
            Desc::new("a".to_string(), "b".to_string(), vec!["c".to_string()], hm).unwrap();
        let collect_calls = Arc::new(AtomicUsize::new(0));

        Self {
            test_desc,
            sender,
            collect_calls,
        }
    }
}

impl Collector for BlockingCollector {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.test_desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        self.collect_calls.fetch_add(1, Ordering::SeqCst);
        let tx = self.sender.clone();
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| {
            tx.blocking_send(()).unwrap();
        });
        vec![]
    }
}

/// Test once the number of in-flight requests reaches 'max_concurrent_requests', a 429 should
/// be returned for new requests.
#[tokio::test(flavor = "multi_thread")]
async fn test_load_shedding() {
    with_test_replica_logger(|log| async move {
        let rt_handle = tokio::runtime::Handle::current();
        let addr = get_free_localhost_port().unwrap();
        let config = Config {
            exporter: Exporter::Http(addr),
            ..Default::default()
        };
        let metrics_registry = MetricsRegistry::default();
        let (tx, mut rx) = channel(1);
        let blocking_collector = metrics_registry.register(BlockingCollector::new(tx));
        let _metrics_endpoint = MetricsHttpEndpoint::new(
            rt_handle,
            config.clone(),
            metrics_registry,
            &log.inner_logger.root,
        );

        // Use a single client so we don't hit the max TCP connetions limit.
        let client = Client::builder()
            .http2_only(true)
            .retry_canceled_requests(false)
            .http2_max_concurrent_reset_streams(config.max_concurrent_requests * 2)
            .build_http();

        let mut set = tokio::task::JoinSet::new();

        assert_eq!(
            send_request(&client, addr).await.unwrap().status(),
            StatusCode::OK
        );
        // Reset the counter to 0 after we confirmed there is a listening socket.
        blocking_collector.collect_calls.store(0, Ordering::SeqCst);
        // Send 'max_concurrent_requests' and block their progress.
        for _i in 0..config.max_concurrent_requests {
            set.spawn({
                let client = client.clone();
                async move {
                    assert_eq!(
                        send_request(&client, addr).await.unwrap().status(),
                        StatusCode::OK
                    );
                }
            });
        }

        // What until all requests reached the blocking/sync point.
        while blocking_collector.collect_calls.load(Ordering::SeqCst)
            != config.max_concurrent_requests
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            send_request(&client, addr).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // Unblock and join the tasks that have sent the initial requests.
        for _i in 0..config.max_concurrent_requests + 1 {
            rx.recv().await.unwrap();
        }
        for _i in 0..config.max_concurrent_requests {
            set.join_next().await.unwrap().unwrap();
        }
    })
    .await
}

/// If the downstream service is stuck return 504.
#[tokio::test(flavor = "multi_thread")]
async fn test_request_timeout() {
    with_test_replica_logger(|log| async move {
        let rt_handle = tokio::runtime::Handle::current();
        let addr = get_free_localhost_port().unwrap();
        let config = Config {
            exporter: Exporter::Http(addr),
            request_timeout_seconds: 2,
            ..Default::default()
        };
        let metrics_registry = MetricsRegistry::default();
        let (tx, mut rx) = channel(1);
        let _blocking_collector = metrics_registry.register(BlockingCollector::new(tx));
        let _metrics_endpoint = MetricsHttpEndpoint::new(
            rt_handle,
            config.clone(),
            metrics_registry,
            &log.inner_logger.root,
        );

        // Use a single client so we don't hit the max TCP connetions limit.
        let client = Client::builder()
            .http2_only(true)
            .retry_canceled_requests(false)
            .http2_max_concurrent_reset_streams(config.max_concurrent_requests * 2)
            .build_http();

        assert_eq!(
            send_request(&client, addr).await.unwrap().status(),
            StatusCode::OK
        );

        assert_eq!(
            send_request(&client, addr).await.unwrap().status(),
            StatusCode::GATEWAY_TIMEOUT
        );
        rx.recv().await.unwrap();
        rx.recv().await.unwrap();
    })
    .await
}

// Test if slow downstream services don't cause connection drop.
#[tokio::test(flavor = "multi_thread")]
async fn test_connection_is_alive_with_slow_downstream() {
    with_test_replica_logger(|log| async move {
        let rt_handle = tokio::runtime::Handle::current();
        let addr = get_free_localhost_port().unwrap();
        let config = Config {
            exporter: Exporter::Http(addr),
            request_timeout_seconds: 2,
            connection_read_timeout_seconds: 3,
            ..Default::default()
        };
        let metrics_registry = MetricsRegistry::default();
        let (tx, mut rx) = channel(1);
        let _blocking_collector = metrics_registry.register(BlockingCollector::new(tx));
        let _metrics_endpoint = MetricsHttpEndpoint::new(
            rt_handle,
            config.clone(),
            metrics_registry,
            &log.inner_logger.root,
        );

        // Use a single client so we don't hit the max TCP connetions limit.
        let client = Client::builder()
            .http2_only(true)
            .retry_canceled_requests(false)
            .http2_max_concurrent_reset_streams(config.max_concurrent_requests * 2)
            .build_http();

        assert_eq!(
            send_request(&client, addr).await.unwrap().status(),
            StatusCode::OK
        );
        let n = config.connection_read_timeout_seconds / config.request_timeout_seconds + 2;
        for _i in 0..n {
            assert_eq!(
                send_request(&client, addr).await.unwrap().status(),
                StatusCode::GATEWAY_TIMEOUT
            );
        }
        for _i in 0..n + 1 {
            rx.recv().await.unwrap();
        }
    })
    .await
}
