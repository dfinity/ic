// These tests rely on being able to set SSL_CERT_FILE environment variable to trust
// a self signed certificate.
// We use `hyper-rustls` which uses Rustls, which supports the SSL_CERT_FILE variable.
mod test {
    use futures::TryFutureExt;
    use ic_https_outcalls_adapter::{AdapterServer, Config};
    use ic_https_outcalls_service::{
        canister_http_service_client::CanisterHttpServiceClient, CanisterHttpSendRequest,
        HttpMethod,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use once_cell::sync::OnceCell;
    use std::convert::TryFrom;
    use std::env;
    use std::io::Write;
    use tempfile::TempDir;
    use tokio::net::UnixStream;
    use tonic::transport::{Channel, Endpoint, Uri};
    use tower::service_fn;
    use unix::UnixListenerDrop;
    use uuid::Uuid;
    use warp::{
        filters::BoxedFilter,
        http::{header::HeaderValue, Response, StatusCode},
        Filter,
    };

    #[cfg(feature = "http")]
    use std::net::IpAddr;

    // Selfsigned localhost cert
    const CERT: &str = "
-----BEGIN CERTIFICATE-----
MIIBUjCB+aADAgECAgkA0o0zHUCaNowwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwW
cmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEw
MTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABKFLbf6iV/TZxpVezAru8FxA45RrIJb+Cy00
+lZ0SUjiGjOOl7DwOUoLHK0RIOEisq9fccZRWCvvgTp/3hkZgXajGDAWMBQGA1Ud
EQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiAx6PyM2bCvJhkSOWdp
ovZtltEexwXglIabATfV0rbH2wIhAPC8Dpm4seHz+NzU7ci8PGbFmaNsz5cnaYIW
4hzjIv//
-----END CERTIFICATE-----
";

    // Corresponding private key
    const KEY: &str = "
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgob29X4H4m2XOkSZE
7ZxcVthhssKkdRD+cMgD+wPseKShRANCAAShS23+olf02caVXswK7vBcQOOUayCW
/gstNPpWdElI4hozjpew8DlKCxytESDhIrKvX3HGUVgr74E6f94ZGYF2
-----END PRIVATE KEY-----
";

    // Variable that stores the directory of our cert/key files.
    // This is a oncecell because we don't want each test to call
    // `generate_certs` and generate a race on the SSL_CERT_FILE
    // environment variable and the cert/key file.
    static CERT_INIT: OnceCell<TempDir> = OnceCell::new();

    fn generate_certs() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        // Store self signed cert
        let cert_file_path = dir.path().join("cert.crt");
        let mut cert_file = std::fs::File::create(cert_file_path).unwrap();
        writeln!(cert_file, "{}", CERT).unwrap();
        let key_file_path = dir.path().join("key.pem");
        let mut key_file = std::fs::File::create(key_file_path).unwrap();
        writeln!(key_file, "{}", KEY).unwrap();

        // The Nix environment with OpenSSL set NIX_SSL_CERT_FILE which seems to take presedence over SSL_CERT_FILE.
        // https://github.com/NixOS/nixpkgs/blob/master/pkgs/development/libraries/openssl/1.1/nix-ssl-cert-file.patch
        // SSL_CERT_FILE is respected by OpenSSL and Rustls.
        // Rustlts: https://github.com/rustls/rustls/issues/540
        // OpenSSL: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_default_verify_paths.html
        env::set_var("SSL_CERT_FILE", dir.path().join("cert.crt"));
        env::remove_var("NIX_SSL_CERT_FILE");
        dir
    }

    fn warp_server() -> BoxedFilter<(impl warp::Reply,)> {
        let basic_post = warp::post()
            .and(warp::path("post"))
            .and(warp::body::json())
            .map(|req: u64| Response::builder().body(req.to_string()));

        let basic_get = warp::get()
            .and(warp::path("get"))
            .map(|| warp::reply::json(&"Hello"));
        let invalid_header = warp::get().and(warp::path("invalid")).map(|| unsafe {
            Response::builder()
                .header(
                    "invalid-ascii-value",
                    HeaderValue::from_maybe_shared_unchecked("x√ab c".as_bytes()),
                )
                .body("hi")
        });

        let get_response_size = warp::get()
            .and(warp::path("size"))
            .and(warp::body::json())
            .map(|req: usize| Response::builder().body(vec![0u8; req]));

        let get_delay = warp::get()
            .and(warp::path("delay"))
            .and(warp::body::json())
            .and_then(|req: u64| async move {
                tokio::time::sleep(std::time::Duration::from_secs(req)).await;
                Ok::<_, warp::Rejection>(warp::reply::reply())
            });

        let basic_head = warp::head().and(warp::path("head")).map(warp::reply::reply);

        basic_post
            .or(basic_get)
            .or(basic_head)
            .or(get_response_size)
            .or(get_delay)
            .or(invalid_header)
            .boxed()
    }

    fn start_server(cert_dir: &TempDir) -> String {
        let (addr, fut) = warp::serve(warp_server())
            .tls()
            .cert_path(cert_dir.path().join("cert.crt"))
            .key_path(cert_dir.path().join("key.pem"))
            .bind_ephemeral(([127, 0, 0, 1], 0));

        tokio::spawn(fut);
        format!("localhost:{}", addr.port())
    }

    #[cfg(feature = "http")]
    fn start_http_server(ip: IpAddr) -> String {
        let (addr, fut) = warp::serve(warp_server()).bind_ephemeral((ip, 0));

        tokio::spawn(fut);
        format!("{}:{}", ip, addr.port())
    }

    #[tokio::test]
    async fn test_canister_http_server() {
        let server_config = Config {
            ..Default::default()
        };
        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/get", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });
        let response = client.canister_http_send(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[cfg(not(feature = "http"))]
    #[tokio::test]
    async fn test_canister_http_http_protocol() {
        // Check that error is returned if a `http` url is specified.
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("http://{}/get", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });
        let response = client.canister_http_send(request).await;
        assert_eq!(
            response.as_ref().unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert!(response
            .unwrap_err()
            .message()
            .contains(&"Url need to specify https scheme".to_string()));
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn test_canister_http_http_protocol_allowed() {
        // Check that error is returned if a `http` url is specified.
        let server_config = Config {
            ..Default::default()
        };

        let url = start_http_server("127.0.0.1".parse().unwrap());
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("http://{}/get", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });
        let response = client.canister_http_send(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[tokio::test]
    async fn test_canister_http_server_post() {
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/post", &url),
            headers: Vec::new(),
            method: HttpMethod::Post as i32,
            body: "420".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });

        let response = client.canister_http_send(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
        assert_eq!(String::from_utf8_lossy(&http_response.content), "420");
    }

    #[tokio::test]
    async fn test_canister_http_server_head() {
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/head", &url),
            headers: Vec::new(),
            method: HttpMethod::Head as i32,
            body: "".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });

        let response = client.canister_http_send(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[tokio::test]
    async fn test_response_limit_exceeded() {
        // Check if response with higher than allowed response limit is rejected.
        let response_limit: u64 = 512;
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/size", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: format!("{}", response_limit + 1).as_bytes().to_vec(),
            max_response_size_bytes: response_limit,
            socks_proxy_allowed: false,
        });

        let response = client.canister_http_send(request).await;
        assert_eq!(
            response.as_ref().unwrap_err().code(),
            tonic::Code::OutOfRange
        );
        assert!(response
            .unwrap_err()
            .message()
            .contains(&"length limit exceeded".to_string()));
    }

    #[tokio::test]
    async fn test_within_response_limit() {
        let response_size: u64 = 512;
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/size", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: format!("{}", response_size).as_bytes().to_vec(),
            max_response_size_bytes: response_size * 2,
            socks_proxy_allowed: false,
        });

        let response = client.canister_http_send(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[tokio::test]
    async fn test_request_timeout() {
        // Check if response with higher than allowed response limit is rejected.
        let delay: u64 = 512;
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/delay", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: format!("{}", delay).as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });

        let response = client.canister_http_send(request).await;
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
            // Set to high value to make sure connect timeout kicks in.
            http_request_timeout_secs: 6000,
            ..Default::default()
        };

        let _url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        // Non routable address that causes a connect timeout.
        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: "https://10.255.255.1".to_string(),
            headers: Vec::new(),
            method: HttpMethod::Head as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 64,
            socks_proxy_allowed: false,
        });
        let response = client.canister_http_send(request).await;
        assert_eq!(
            response.as_ref().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        assert!(response
            .unwrap_err()
            .message()
            .contains(&"client error (Connect)".to_string()));
    }

    #[tokio::test]
    async fn test_nonascii_header() {
        let response_limit: u64 = 512;
        let server_config = Config {
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: format!("https://{}/invalid", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".as_bytes().to_vec(),
            max_response_size_bytes: response_limit,
            socks_proxy_allowed: false,
        });

        let response = client.canister_http_send(request).await;
        let _ = response.unwrap_err();
    }

    #[tokio::test]
    async fn test_missing_protocol() {
        // Test that missing http protocol specification returns error.
        let server_config = Config {
            ..Default::default()
        };

        let _url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(CanisterHttpSendRequest {
            url: "127.0.0.1".to_string(),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
        });
        let response = client.canister_http_send(request).await;
        let _ = response.unwrap_err();
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

        let server = AdapterServer::new(config, no_op_logger(), &MetricsRegistry::default());

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
                std::fs::remove_file(&self.path).unwrap();
            }
        }

        #[derive(Debug)]
        pub struct UnixStream(pub tokio::net::UnixStream);

        impl Connected for UnixStream {
            type ConnectInfo = ();

            fn connect_info(&self) -> Self::ConnectInfo {}
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

            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
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
}
