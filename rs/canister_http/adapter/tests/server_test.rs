use fast_socks5::server::{Config as SocksConfig, Socks5Server};
use futures::{StreamExt, TryFutureExt};
use http::StatusCode;
use hyper::{
    client::{connect::Connect, HttpConnector},
    Client,
};
use hyper_socks2::SocksConnector;
use hyper_tls::HttpsConnector;
use ic_canister_http_adapter::{CanisterHttp, Config};
use ic_canister_http_adapter_service::{
    http_adapter_client::HttpAdapterClient, http_adapter_server::HttpAdapterServer,
    CanisterHttpRequest, HttpHeader,
};
use ic_logger::{new_replica_logger_from_config, ReplicaLogger};
use std::convert::TryFrom;
use std::{convert::Infallible, net::SocketAddr};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Server, Uri};
use tower::service_fn;
use unix::UnixListenerDrop;
use uuid::Uuid;

#[tokio::test]
async fn test_https() {
    // setup unix domain socket and start gRPC server on one side of the UDS
    let config = Config::default();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let canister_http = setup_grpc_server_with_https_client(logger.clone());
    let channel = setup_loop_channel_unix(canister_http).await;

    // create gRPC client that communicated with gRPC server through UDS channel
    let mut client = HttpAdapterClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request(
        "https://www.google.com".to_string(),
    ));

    let response = client.send_http_request(request).await;

    assert!(response.is_ok());
    assert_eq!(
        response.unwrap().into_inner().status,
        StatusCode::OK.as_u16() as u32
    );
}

#[tokio::test]
async fn test_http() {
    let config = Config::default();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let canister_http = setup_grpc_server_with_https_client(logger.clone());
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = HttpAdapterClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request(
        "http://www.bing.com".to_string(),
    ));

    // HTTP adapter enforces HTTPS. HTTP connection requests are rejected.
    let response = client.send_http_request(request).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn test_no_http() {
    let config = Config::default();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let canister_http = setup_grpc_server_with_https_client(logger.clone());
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = HttpAdapterClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request("www.google.com".to_string()));

    let response = client.send_http_request(request).await;
    assert!(response.is_err());
}

// Try to connect through failing proxy.
#[tokio::test]
async fn test_bad_socks() {
    let config = Config::default();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let canister_http = setup_grpc_server_with_socks_client(
        Uri::from_static("socks5://doesnotexist:8088"),
        logger.clone(),
    );
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = HttpAdapterClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request(
        "https://www.google.com".to_string(),
    ));

    let response = client.send_http_request(request).await;
    assert!(response.is_err());
}

// Spawn socks proxy on localhost and connect thourgh poxy.
#[tokio::test]
async fn test_socks() {
    let config = Config::default();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let canister_http = setup_grpc_server_with_socks_client(
        Uri::from_static("socks5://127.0.0.1:8088"),
        logger.clone(),
    );
    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = HttpAdapterClient::new(channel);

    tokio::task::spawn(async move {
        spawn_socks5_server("127.0.0.1:8088".to_string()).await;
    });

    let request = tonic::Request::new(build_http_canister_request(
        "https://www.google.com".to_string(),
    ));
    let response = client.send_http_request(request).await;
    assert!(response.is_ok());
}

// DNS returns multiple addresses and only one is valid. The proxy connector should fallback to the working one.
#[tokio::test]
async fn test_socks_fallback() {
    let config = Config::default();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

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

    let mut https = HttpsConnector::new_with_connector(proxy);
    https.https_only(true);
    let https_client = Client::builder().build::<_, hyper::Body>(https);
    let canister_http = CanisterHttp::new(https_client, logger.clone());

    let channel = setup_loop_channel_unix(canister_http).await;
    let mut client = HttpAdapterClient::new(channel);

    // Spawn socks prox on 127.0.0.1:8089
    tokio::task::spawn(async move {
        spawn_socks5_server("127.0.0.1:8089".to_string()).await;
    });
    let request = tonic::Request::new(build_http_canister_request(
        "https://www.bing.com".to_string(),
    ));
    let response = client.send_http_request(request).await;
    assert!(response.is_ok());
}

// TODO: increase functionality of this function (NET-883)
fn build_http_canister_request(url: String) -> CanisterHttpRequest {
    let headers = vec![HttpHeader {
        name: "User-Agent".to_string(),
        value: "test".to_string(),
    }];

    CanisterHttpRequest {
        url,
        body: "".to_string().into_bytes(),
        headers,
    }
}

fn setup_grpc_server_with_https_client(
    logger: ReplicaLogger,
) -> CanisterHttp<HttpsConnector<HttpConnector>> {
    let mut https = HttpsConnector::new();
    https.https_only(true);
    let https_client = Client::builder().build::<_, hyper::Body>(https);
    CanisterHttp::new(https_client, logger)
}

fn setup_grpc_server_with_socks_client(
    uri: Uri,
    logger: ReplicaLogger,
) -> CanisterHttp<HttpsConnector<SocksConnector<HttpConnector>>> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let proxy = SocksConnector {
        proxy_addr: uri, // scheme is required by HttpConnector
        auth: None,
        connector,
    };

    let mut https = HttpsConnector::new_with_connector(proxy);
    https.https_only(true);
    let https_client = Client::builder().build::<_, hyper::Body>(https);
    CanisterHttp::new(https_client, logger)
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
            .add_service(HttpAdapterServer::new(canister_http))
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
