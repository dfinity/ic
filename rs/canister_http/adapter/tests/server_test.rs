use fast_socks5::server::{Config as SocksConfig, Socks5Server};
use futures::{StreamExt, TryFutureExt};
use http::StatusCode;
use hyper::{client::HttpConnector, Client};
use ic_canister_http_adapter::{AdapterServer, Config};
use ic_canister_http_service::{
    canister_http_service_client::CanisterHttpServiceClient, CanisterHttpSendRequest, HttpHeader,
};
use ic_logger::replica_logger::no_op_logger;
use std::convert::TryFrom;
use std::str::FromStr;
use std::{convert::Infallible, net::SocketAddr};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
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

    let server_config = Config {
        ..Default::default()
    };
    // Spawn grpc server and return client.
    let mut client = spawn_grpc_server(server_config);

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
async fn test_response_limit() {
    // Check if response with higher than allowed response limit is rejected.
    let server_config = Config {
        ..Default::default()
    };
    let mock_server = MockServer::start().await;
    // 2Mb and 1 byte. Will get limitet because 'Content-length' is too large.
    let payload: Vec<u8> = vec![0u8; server_config.http_request_size_limit_bytes + 1];
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload))
        .mount(&mock_server)
        .await;

    let mut client = spawn_grpc_server(server_config);
    let request = tonic::Request::new(build_http_canister_request(format!(
        "{}/hello",
        &mock_server.uri()
    )));
    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
    assert_eq!(
        response.as_ref().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert!(response
        .unwrap_err()
        .message()
        .contains(&"header exceeds http body size".to_string()));
}

#[tokio::test]
async fn test_request_timeout() {
    // Test that adapter times out for unresponsive but reachable webpages.
    let mock_server = MockServer::start().await;
    // 2Mb and 2 bytes. Will get limitet because 'Content-length' is too large.
    Mock::given(method("GET"))
        .and(path("/hello"))
        // Delay here is higher than request timeout below.
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(10)))
        .mount(&mock_server)
        .await;

    let server_config = Config {
        // Set connect timeout to high value to make sure request timeout is triggered.
        http_connect_timeout_secs: 6000,
        http_request_timeout_secs: 3,
        ..Default::default()
    };
    let mut client = spawn_grpc_server(server_config);
    let request = tonic::Request::new(build_http_canister_request(format!(
        "{}/hello",
        &mock_server.uri()
    )));
    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
    assert_eq!(
        response.as_ref().unwrap_err().code(),
        tonic::Code::Cancelled
    );
    assert!(response
        .unwrap_err()
        .message()
        .contains(&"Timeout expired".to_string()));
}

#[tokio::test]
async fn test_connect_timeout() {
    // Test that adapter hits connect timeout when connecting to unreachable host.
    let server_config = Config {
        http_connect_timeout_secs: 1,
        // Set to high value to make sure connnect timeout kicks in.
        http_request_timeout_secs: 6000,
        ..Default::default()
    };
    let mut client = spawn_grpc_server(server_config);

    // Non routable address that causes a connect timeout.
    let request = tonic::Request::new(build_http_canister_request(
        "http://10.255.255.1".to_string(),
    ));
    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
    assert_eq!(
        response.as_ref().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert!(response
        .unwrap_err()
        .message()
        .contains(&"deadline has elapsed".to_string()));
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

    let server_config = Config {
        ..Default::default()
    };
    let mut client = spawn_grpc_server(server_config);

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
    let server_config = Config {
        ..Default::default()
    };
    let mut client = spawn_grpc_server(server_config);

    let request = tonic::Request::new(build_http_canister_request("127.0.0.1".to_string()));
    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_bad_socks() {
    // Try to connect through failing proxy.
    let socks_url = "socks5://doesnotexist:8088".to_string();
    let server_config = Config {
        socks_proxy: Some(socks_url),
        ..Default::default()
    };
    // Spawn grpc server and return client.
    let mut client = spawn_grpc_server(server_config);

    let request = tonic::Request::new(build_http_canister_request("https://127.0.0.1".to_string()));

    let response = client.canister_http_send(request).await;
    assert!(response.is_err());
}

#[tokio::test]
async fn test_socks() {
    // Spawn socks proxy on localhost and connect thourgh poxy.
    let server_config = Config {
        socks_proxy: Some("socks5://127.0.0.1:8088".to_string()),
        ..Default::default()
    };
    // Spawn grpc server and return client.
    let mut client = spawn_grpc_server(server_config);

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

// DNS returns multiple addresses and only one is valid. The Http connector should fallback to the working one.
// This test only verifies the fallback behaviour of the hyper HttpConnector that is used in the adapter client.
#[tokio::test]
async fn test_socks_fallback() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let addr = mock_server.address().to_owned();

    // Setup dns resolver for connecting to socks proxy. Only 127.0.0.1:8089 is working
    let resolver = tower::service_fn(move |_name| async move {
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
                addr,
            ]
            .into_iter(),
        )
    });

    // Create socks connector. This test case uses the custom resolver to mimic the boundary nodes.
    // The boundary node domain should resolve to multiple domain names and the connector should fallback if some are not working.
    let connector = HttpConnector::new_with_resolver(resolver);
    let http_client = Client::builder().build::<_, hyper::Body>(connector);

    let response = http_client
        .get(Uri::from_str(&format!("{}/hello", &mock_server.uri())).unwrap())
        .await
        .unwrap();
    assert!(response.status() == 200);
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

// Spawn grpc server and return canister http client
fn spawn_grpc_server(config: Config) -> CanisterHttpServiceClient<Channel> {
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

    let server = AdapterServer::new(config, no_op_logger(), false);

    // spawn gRPC server
    tokio::spawn(async move { server.serve(incoming).await.expect("server shutdown") });

    // port can be ignored
    let channel = Endpoint::try_from("http://[::]:50151")
        .unwrap()
        .connect_with_connector_lazy(service_fn(move |_: Uri| {
            // Connect to a Uds socket
            UnixStream::connect(path.clone())
        }));

    CanisterHttpServiceClient::new(channel)
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
