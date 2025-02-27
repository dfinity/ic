// These tests rely on being able to set SSL_CERT_FILE environment variable to trust
// a self signed certificate.
// We use `hyper-rustls` which uses Rustls, which supports the SSL_CERT_FILE variable.
mod test {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use ic_https_outcalls_adapter::{Config, IncomingSource};
    use ic_https_outcalls_service::{
        https_outcalls_service_client::HttpsOutcallsServiceClient, HttpMethod, HttpsOutcallRequest,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use once_cell::sync::OnceCell;
    use rstest::rstest;
    use rustls::{pki_types::Ipv6Addr, ServerConfig};
    use std::{collections::HashSet, convert::TryFrom, env, io::Write, path::Path, sync::Arc};
    use tempfile::TempDir;
    use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpSocket, TcpStream, UnixStream}};
    use tokio_rustls::TlsAcceptor;
    use tonic::transport::{Channel, Endpoint, Uri};
    use tower::service_fn;
    use uuid::Uuid;
    use warp::{
        filters::BoxedFilter, http::{header::HeaderValue, Response, StatusCode}, reject::Rejection, Filter
    };
    use socks5_impl::protocol::{handshake, Address, AsyncStreamOperation, AuthMethod, Command, Reply, Request as Socks5Request, Response as Socks5Response};
    use std::io;
    use std::net::SocketAddr;

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

    fn cert_path(cert_dir: &TempDir) -> impl AsRef<Path> {
        cert_dir.path().join("cert.crt")
    }

    fn key_path(cert_dir: &TempDir) -> impl AsRef<Path> {
        cert_dir.path().join("key.pem")
    }

    /// Spawns a minimal SOCKS5 server on `bind_addr` in the background (via `tokio::spawn`).
    /// Returns the actual local address (which includes the ephemeral port) that the server
    /// ended up binding to.  You can then pass `socks5://127.0.0.1:<port>` to your code.
    #[cfg(feature = "http")]
    pub async fn spawn_socks5_server(bind_addr: &str, url: String) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;

        // Spawn the server in the background
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _client_addr)) => {
                        let url = url.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, url).await {
                                eprintln!("[SOCKS5] Error in client handler: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[SOCKS5] Error accepting: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(local_addr)
    }

    #[cfg(feature = "http")]
    pub async fn handle_client(stream: TcpStream, url: String) -> io::Result<()> {
        // 1) Perform SOCKS5 handshake
        let mut stream = stream; // We'll do the handshake before splitting.
        println!("debuggg 10");
        let handshake_req = handshake::Request::retrieve_from_async_stream(&mut stream).await?;
        if handshake_req.evaluate_method(AuthMethod::NoAuth) {
            // Accept "no auth"
            handshake::Response::new(AuthMethod::NoAuth)
                .write_to_async_stream(&mut stream)
                .await?;
        } else {
            // If the client doesn't support "no auth", reject.
            handshake::Response::new(AuthMethod::NoAcceptableMethods)
                .write_to_async_stream(&mut stream)
                .await?;
            stream.shutdown().await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "No supported authentication method",
            ));
        }
        println!("debuggg 11");

        // 2) Read the SOCKS request (command + target)
        let _req = match Socks5Request::retrieve_from_async_stream(&mut stream).await {
            Ok(req) => req,
            Err(e) => {
                Socks5Response::new(Reply::GeneralFailure, Address::unspecified())
                    .write_to_async_stream(&mut stream)
                    .await?;
                stream.shutdown().await?;
                return Err(e);
            }
        };

        println!("debuggg 14 {} {}", _req.address, url);

        let remote_stream = TcpStream::connect(url.clone()).await?;
        
        println!("debuggg 15");

        // 6) Send "Succeeded" to the client
        let local_sock = remote_stream.local_addr()?;
        Socks5Response::new(Reply::Succeeded, Address::SocketAddress(local_sock))
            .write_to_async_stream(&mut stream)
            .await?;
        println!("debuggg 16");
        // 7) Split both streams with `into_split()`, not `split()`.
        //    `into_split()` consumes the `TcpStream` and returns owned halves.
        //    Owned halves implement `Send + 'static`, so they can be moved into spawn tasks.
        let (client_read, client_write) = stream.into_split();
        let (remote_read, remote_write) = remote_stream.into_split();

        // Forward client -> remote in a background task
        tokio::spawn(async move {
            let mut client_read = client_read;
            let mut remote_write = remote_write;
            let _ = tokio::io::copy(&mut client_read, &mut remote_write).await;
            let _ = remote_write.shutdown().await;
        });
        println!("debuggg 17");

        // Forward remote -> client in the current task
        {
            let mut remote_read = remote_read;
            let mut client_write = client_write;
            println!("debuggg 18");
            let _ = tokio::io::copy(&mut remote_read, &mut client_write).await;
            println!("debuggg 19");
            let _ = client_write.shutdown().await;
            println!("debuggg 20");
        }

        Ok(())
    }

    fn start_server(cert_dir: &TempDir) -> String {
        let (addr, fut) = warp::serve(warp_server())
            .tls()
            .cert_path(cert_path(cert_dir))
            .key_path(key_path(cert_dir))
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

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn test_canister_http_socks_server() {
        //TODO(mihailjianu): explain why we need http and not https. 
        let url = start_http_server("127.0.0.1".parse().unwrap());
        println!("debuggg url {}", url);

        let socks_addr = spawn_socks5_server("127.0.0.1:0", url.clone())
            .await
            .expect("Failed to bind socks");

        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            socks_proxy: format!("socks5://{}", socks_addr),
            //TODO(mihailjianu): start the socks server, and add it here. 
            ..Default::default()
        };
        let mut client = spawn_grpc_server(server_config);
        let unreachable_url = "10.255.255.1:9999";

        // Make request to unreachable url, and socks proxy is disabled. Request should fail.
        let application_subnet_request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("http://{}/get", &unreachable_url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });
        let response = client.https_outcall(application_subnet_request).await;
        assert!(response.is_err());

        // Make direct request to unreachable url. Need to rely on the socks proxy to make the correct request. 
        // Socks proxy is enabled
        let system_subnet_request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("http://{}/get", &unreachable_url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: true,
            ..Default::default()
        });
        let response = client.https_outcall(system_subnet_request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
        //TODO(mihailjianu): also add IT for the new socks proxy. 
    }

    #[tokio::test]
    async fn test_canister_http_server() {
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };
        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let ips: Vec<SocketAddr> = tokio::net::lookup_host(url.clone()).await.unwrap().collect();
        let mut ipv4_addr = None;
        let mut ipv6_addr = None;
        for ip in ips {
            println!("debuggg ip {}", ip);
            match ip {
                SocketAddr::V4(ipv4) => {
                    ipv4_addr = Some(ipv4.clone());
                }
                SocketAddr::V6(ipv6) => {
                    ipv6_addr = Some(ipv6.clone());
                }
            }
        }
        if ipv6_addr.is_none() {
            panic!("No ipv6 address found");
        }

        let ipv6_addr = ipv6_addr.unwrap();
        let ipv4_addr = ipv4_addr.unwrap();

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/get", url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });
        let response = client.https_outcall(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[cfg(not(feature = "http"))]
    #[tokio::test]
    async fn test_canister_http_http_protocol() {
        // Check that error is returned if a `http` url is specified.
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("http://{}/get", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });
        let response = client.https_outcall(request).await;
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
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_http_server("127.0.0.1".parse().unwrap());
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("http://{}/get", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });
        let response = client.https_outcall(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[tokio::test]
    async fn test_canister_http_server_post() {
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/post", &url),
            headers: Vec::new(),
            method: HttpMethod::Post as i32,
            body: "420".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });

        let response = client.https_outcall(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
        assert_eq!(String::from_utf8_lossy(&http_response.content), "420");
    }

    #[tokio::test]
    async fn test_canister_http_server_head() {
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/head", &url),
            headers: Vec::new(),
            method: HttpMethod::Head as i32,
            body: "".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });

        let response = client.https_outcall(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[tokio::test]
    async fn test_response_limit_exceeded() {
        // Check if response with higher than allowed response limit is rejected.
        let response_limit: u64 = 512;
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/size", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: format!("{}", response_limit + 1).as_bytes().to_vec(),
            max_response_size_bytes: response_limit,
            socks_proxy_allowed: false,
            ..Default::default()
        });

        let response = client.https_outcall(request).await;
        assert_eq!(
            response.as_ref().unwrap_err().code(),
            tonic::Code::OutOfRange
        );
        assert!(response
            .unwrap_err()
            .message()
            .contains(&"Http body exceeds size limit of".to_string()));
    }

    #[tokio::test]
    async fn test_within_response_limit() {
        let response_size: u64 = 512;
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/size", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: format!("{}", response_size).as_bytes().to_vec(),
            max_response_size_bytes: response_size * 2,
            socks_proxy_allowed: false,
            ..Default::default()
        });

        let response = client.https_outcall(request).await;
        let http_response = response.unwrap().into_inner();
        assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
    }

    #[tokio::test]
    async fn test_request_timeout() {
        // Check if response with higher than allowed response limit is rejected.
        let delay: u64 = 512;
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/delay", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: format!("{}", delay).as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });

        let response = client.https_outcall(request).await;
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
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            http_connect_timeout_secs: 1,
            // Set to high value to make sure connect timeout kicks in.
            http_request_timeout_secs: 6000,
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let _url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        // Non routable address that causes a connect timeout.
        let request = tonic::Request::new(HttpsOutcallRequest {
            url: "https://10.255.255.1".to_string(),
            headers: Vec::new(),
            method: HttpMethod::Head as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 64,
            socks_proxy_allowed: false,
            ..Default::default()
        });
        let response = client.https_outcall(request).await;
        assert_eq!(
            response.as_ref().unwrap_err().code(),
            tonic::Code::Unavailable
        );

        let response_error = response.unwrap_err();
        let actual_error_message = response_error.message();

        let expected_error_message = "Error(Connect, ConnectError(\"tcp connect error\", Custom { kind: TimedOut, error: Elapsed(()) }))";

        assert!(
            actual_error_message.contains(expected_error_message),
            "Expected error message to contain, {}, got: {}",
            expected_error_message,
            actual_error_message
        );
    }

    #[tokio::test]
    async fn test_nonascii_header() {
        let response_limit: u64 = 512;
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: format!("https://{}/invalid", &url),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".as_bytes().to_vec(),
            max_response_size_bytes: response_limit,
            socks_proxy_allowed: false,
            ..Default::default()
        });

        let response = client.https_outcall(request).await;
        let _ = response.unwrap_err();
    }

    #[tokio::test]
    async fn test_missing_protocol() {
        // Test that missing http protocol specification returns error.
        let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
        let server_config = Config {
            incoming_source: IncomingSource::Path(path.into()),
            ..Default::default()
        };

        let _url = start_server(CERT_INIT.get_or_init(generate_certs));
        let mut client = spawn_grpc_server(server_config);

        let request = tonic::Request::new(HttpsOutcallRequest {
            url: "127.0.0.1".to_string(),
            headers: Vec::new(),
            method: HttpMethod::Get as i32,
            body: "hello".to_string().as_bytes().to_vec(),
            max_response_size_bytes: 512,
            socks_proxy_allowed: false,
            ..Default::default()
        });
        let response = client.https_outcall(request).await;
        let _ = response.unwrap_err();
    }

    #[rstest]
    #[case(hyper::Version::HTTP_2, vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()])]
    #[case(hyper::Version::HTTP_2, vec![b"h2".to_vec(), b"http/1.1".to_vec()])]
    #[case(hyper::Version::HTTP_2, vec![b"h2".to_vec()])]
    #[case(hyper::Version::HTTP_11, vec![b"http/1.1".to_vec()])]
    /// Tests that the outcalls adapter enables HTTP/2 and HTTP/1.1. The test spawns a server that
    /// responds with OK if the HTTP protocol corresponds to the negotiated ALPN protocol.
    fn test_http_protocols_are_supported_and_alpn_header_is_set(
        #[case] expected_negotiated_http_protocol: hyper::Version,
        #[case] server_advertised_alpn_protocols: Vec<Vec<u8>>,
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let socket = TcpSocket::new_v4().unwrap();
                socket.set_reuseport(false).unwrap();
                socket.set_reuseaddr(false).unwrap();
                socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let listener = socket.listen(1024).unwrap();

                let addr = listener.local_addr().unwrap();

                let server_config = {
                    let cert_dir = CERT_INIT.get_or_init(generate_certs);
                    let cert_path = cert_path(cert_dir);
                    let key_path = key_path(cert_dir);

                    let cert_file = tokio::fs::read(cert_path).await.unwrap();
                    let certs = rustls_pemfile::certs(&mut cert_file.as_ref())
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();

                    let key_file = tokio::fs::read(key_path).await.unwrap();
                    let key = rustls_pemfile::private_key(&mut key_file.as_ref())
                        .unwrap()
                        .unwrap();

                    let mut server_config = ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();

                    server_config.alpn_protocols = server_advertised_alpn_protocols;

                    server_config
                };

                // Spawn a server that responds with OK if the HTTP protocol corresponds to the negotiated
                // ALPN protocol.
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |req: Request<hyper::body::Incoming>| async move {
                            let status = if req.version() == expected_negotiated_http_protocol {
                                hyper::StatusCode::OK
                            } else {
                                hyper::StatusCode::BAD_REQUEST
                            };

                            Ok::<_, String>(
                                http::response::Response::builder()
                                    .status(status)
                                    .body(Full::<Bytes>::from(""))
                                    .unwrap(),
                            )
                        },
                    );

                    let (tcp_stream, _socket) = listener.accept().await.unwrap();

                    let tls_stream = TlsAcceptor::from(Arc::new(server_config))
                        .accept(tcp_stream)
                        .await
                        .unwrap();

                    let stream = TokioIo::new(tls_stream);

                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .http2()
                        .serve_connection_with_upgrades(stream, service)
                        .await
                });

                let path = "/tmp/canister-http-test-".to_string() + &Uuid::new_v4().to_string();
                let server_config = Config {
                    incoming_source: IncomingSource::Path(path.into()),
                    ..Default::default()
                };
                let mut client = spawn_grpc_server(server_config);

                let request = tonic::Request::new(HttpsOutcallRequest {
                    url: format!("https://localhost:{}", addr.port()),
                    headers: Vec::new(),
                    method: HttpMethod::Get as i32,
                    body: "hello".to_string().as_bytes().to_vec(),
                    max_response_size_bytes: 512,
                    socks_proxy_allowed: false,
                    ..Default::default()
                });

                let response = client.https_outcall(request).await;

                let http_response = response.unwrap().into_inner();
                assert_eq!(http_response.status, StatusCode::OK.as_u16() as u32);
            });
    }

    // Spawn grpc server and return canister http client
    fn spawn_grpc_server(config: Config) -> HttpsOutcallsServiceClient<Channel> {
        ic_https_outcalls_adapter::start_server(
            &no_op_logger(),
            &MetricsRegistry::default(),
            &tokio::runtime::Handle::current(),
            config.clone(),
        );
        if let IncomingSource::Path(path) = config.incoming_source {
            // port can be ignored
            let channel = Endpoint::try_from("http://[::]:50151")
                .unwrap()
                .connect_with_connector_lazy(service_fn(move |_: Uri| {
                    let path = path.clone();
                    async move {
                        // Connect to a Uds socket
                        Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                            UnixStream::connect(path).await?,
                        ))
                    }
                }));

            return HttpsOutcallsServiceClient::new(channel);
        }
        panic!("Bad incoming path.");
    }

    // implements unix listener that removes socket file when done
    // adapter does not need this because the socket is managed by systemd
    mod unix {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
        use tonic::transport::server::Connected;

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
