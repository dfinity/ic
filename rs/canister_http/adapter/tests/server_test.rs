use fast_socks5::server::{Config as SocksConfig, Socks5Server};
use futures::{StreamExt, TryFutureExt};
use http::StatusCode;
use hyper::{
    client::{connect::Connect, HttpConnector},
    Client,
};
use hyper_socks2::SocksConnector;
use ic_canister_http_adapter::CanisterHttp;
use ic_canister_http_service::{
    canister_http_service_client::CanisterHttpServiceClient,
    canister_http_service_server::CanisterHttpServiceServer, CanisterHttpSendRequest, HttpHeader,
};
use ic_logger::replica_logger::no_op_logger;
use std::convert::TryFrom;
use std::{convert::Infallible, net::SocketAddr};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Server, Uri};
use tower::service_fn;
use unix::UnixListenerDrop;
use uuid::Uuid;
use wiremock::{
    http::HeaderValue,
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_canister_http_server() {
    // Setup local mock server.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Setup unix domain socket and start gRPC server on one side of the UDS.
    let canister_http = setup_grpc_server_with_http_client();
    let channel = setup_loop_channel_unix(canister_http).await;

    // Create gRPC client that communicated with gRPC server through UDS channel.
    let mut client = CanisterHttpServiceClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request(format!(
        "{}/hello",
        &mock_server.uri()
    )));

    let response = client.canister_http_send(request).await;
    assert!(response.is_ok());
    assert_eq!(
        response.unwrap().into_inner().status,
        StatusCode::OK.as_u16() as u32
    );
}

#[tokio::test]
async fn test_nonascii_header() {
    let mock_server = MockServer::start().await;
    // Create invalid header. Needs unsafe to bypass parsing.
    unsafe {
        Mock::given(method("GET"))
            .and(path("/hello"))
            .respond_with(ResponseTemplate::new(200).insert_header(
                "invalid-ascii-value",
                HeaderValue::from_bytes_unchecked("x√ab c".as_bytes().to_vec()),
            ))
            .mount(&mock_server)
            .await;
    }

    let canister_http = setup_grpc_server_with_http_client();
    let channel = setup_loop_channel_unix(canister_http).await;

    let mut client = CanisterHttpServiceClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request(format!(
        "{}/hello",
        &mock_server.uri()
    )));

    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_missing_protocol() {
    // Test that missing http protocol specification returns error.
    let canister_http = setup_grpc_server_with_http_client();
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = CanisterHttpServiceClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request("127.0.0.1".to_string()));

    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_bad_socks() {
    // Try to connect through failing proxy.
    let canister_http =
        setup_grpc_server_with_socks_client(Uri::from_static("socks5://doesnotexist:8088"));
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = CanisterHttpServiceClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request("https://127.0.0.1".to_string()));

    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_socks() {
    // Spawn socks proxy on localhost and connect thourgh poxy.
    let canister_http =
        setup_grpc_server_with_socks_client(Uri::from_static("socks5://127.0.0.1:8088"));
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = CanisterHttpServiceClient::new(channel);

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    tokio::task::spawn(async move {
        spawn_socks5_server("127.0.0.1:8088".to_string()).await;
    });

    let request = tonic::Request::new(build_http_canister_request(format!(
        "{}/hello",
        &mock_server.uri()
    )));
    let response = client.canister_http_send(request).await;
    assert!(response.is_ok());
}

// DNS returns multiple addresses and only one is valid. The proxy connector should fallback to the working one.
#[tokio::test]
async fn test_socks_fallback() {
    // Setup dns resolver for connecting to socks proxy. Only 127.0.0.1:8089 is working
    let resolver = tower::service_fn(|_name| async move {
        Ok::<_, Infallible>(
            vec![
                SocketAddr::from(([127, 0, 0, 9], 8089)),
                SocketAddr::from(([127, 0, 0, 8], 8089)),
                SocketAddr::from(([127, 0, 0, 7], 8089)),
                SocketAddr::from(([127, 0, 0, 6], 8089)),
                SocketAddr::from(([127, 0, 0, 5], 8089)),
                SocketAddr::from(([127, 0, 0, 4], 8089)),
                SocketAddr::from(([127, 0, 0, 3], 8089)),
                SocketAddr::from(([127, 0, 0, 2], 8089)),
                SocketAddr::from(([127, 0, 0, 1], 8089)),
            ]
            .into_iter(),
        )
    });

    // Create socks connector. This test case uses the custom resolver to mimic the boundary nodes.
    // The boundary node domain should resolve to multiple domain names and the connector should fallback if some are not working.
    let mut connector = HttpConnector::new_with_resolver(resolver);
    connector.enforce_http(false);
    let proxy = SocksConnector {
        proxy_addr: Uri::from_static("socks5://somesocks.com:8089"),
        auth: None,
        connector,
    };

    let http_client = Client::builder().build::<_, hyper::Body>(proxy);
    let canister_http = CanisterHttp::new(http_client, no_op_logger());

    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = CanisterHttpServiceClient::new(channel);

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Spawn socks prox on 127.0.0.1:8089
    tokio::task::spawn(async move {
        spawn_socks5_server("127.0.0.1:8089".to_string()).await;
    });
    let request = tonic::Request::new(build_http_canister_request(format!(
        "{}/hello",
        &mock_server.uri()
    )));
    let response = client.canister_http_send(request).await;
    assert!(response.is_ok());
}

// TODO: increase functionality of this function (NET-883)
fn build_http_canister_request(url: String) -> CanisterHttpSendRequest {
    let headers = vec![HttpHeader {
        name: "User-Agent".to_string(),
        value: "test".to_string(),
    }];

    CanisterHttpSendRequest {
        url,
        body: "".to_string().into_bytes(),
        headers,
    }
}

fn setup_grpc_server_with_http_client() -> CanisterHttp<HttpConnector> {
    CanisterHttp::new(Client::new(), no_op_logger())
}

fn setup_grpc_server_with_socks_client(uri: Uri) -> CanisterHttp<SocksConnector<HttpConnector>> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let proxy = SocksConnector {
        proxy_addr: uri, // scheme is required by HttpConnector
        auth: None,
        connector,
    };

    let https_client = Client::builder().build::<_, hyper::Body>(proxy);
    CanisterHttp::new(https_client, no_op_logger())
}

async fn spawn_socks5_server(listen_addr: String) {
    let mut listener = Socks5Server::bind(listen_addr).await.unwrap();
    let socks_config = SocksConfig::default();
    listener.set_config(socks_config.clone());
    let mut incoming = listener.incoming();
    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                tokio::task::spawn(async move {
                    if socket.upgrade_to_socks5().await.is_err() {
                        eprintln!("Socks5 proxy failed to serve....");
                    }
                });
            }
            Err(_) => {
                eprintln!("Socks5 proxy server stopped....");
            }
        }
    }
}

async fn setup_loop_channel_unix<C: Clone + Connect + Send + Sync + 'static>(
    canister_http: CanisterHttp<C>,
) -> Channel {
    let uuid = Uuid::new_v4();
    let path = "/tmp/canister-http-test-".to_string() + &uuid.to_string();

    // anonymous type that implements stream trait with item type: Result<UnixStream, Error>.
    let incoming = {
        let uds = UnixListenerDrop::bind(path.clone()).unwrap();

        async_stream::stream! {
            loop {
                let item = uds.accept().map_ok(|(st, _)| unix::UnixStream(st)).await;
                yield item;
            }
        }
    };

    // spawn gRPC server
    tokio::spawn(async move {
        Server::builder()
            .add_service(CanisterHttpServiceServer::new(canister_http))
            .serve_with_incoming(incoming)
            .await
            .expect("server shutdown")
    });

    // port can be ignored
    let channel = Endpoint::try_from("http://[::]:50151")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            // Connect to a Uds socket
            UnixStream::connect(path.clone())
        }))
        .await
        .unwrap();

    channel
}
// implements unix listener that removes socket file when done
// adapter does not need this because the socket is managed by systemd
mod unix {
    use std::path::{Path, PathBuf};
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::unix::SocketAddr;
    use tonic::transport::server::Connected;

    pub struct UnixListenerDrop {
        path: PathBuf,
        listener: tokio::net::UnixListener,
    }

    impl UnixListenerDrop {
        pub fn bind(path: impl AsRef<Path>) -> std::io::Result<Self> {
            let path = path.as_ref().to_owned();
            tokio::net::UnixListener::bind(&path)
                .map(|listener| UnixListenerDrop { path, listener })
        }
        pub async fn accept(&self) -> tokio::io::Result<(tokio::net::UnixStream, SocketAddr)> {
            self.listener.accept().await
        }
    }

    impl Drop for UnixListenerDrop {
        fn drop(&mut self) {
            // There's no way to return a useful error here
            let _ = std::fs::remove_file(&self.path).unwrap();
        }
    }

    #[derive(Debug)]
    pub struct UnixStream(pub tokio::net::UnixStream);

    impl Connected for UnixStream {
        type ConnectInfo = UdsConnectInfo;

        fn connect_info(&self) -> Self::ConnectInfo {
            UdsConnectInfo {
                peer_addr: self.0.peer_addr().ok().map(Arc::new),
                peer_cred: self.0.peer_cred().ok(),
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct UdsConnectInfo {
        pub peer_addr: Option<Arc<tokio::net::unix::SocketAddr>>,
        pub peer_cred: Option<tokio::net::unix::UCred>,
    }

    impl AsyncRead for UnixStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for UnixStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}
