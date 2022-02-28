use futures::TryFutureExt;
use http::StatusCode;
use std::convert::TryFrom;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Server, Uri};
use tower::service_fn;
use uuid::Uuid;

use ic_canister_http_adapter::{
    proto::{
        http_adapter_client::HttpAdapterClient, http_adapter_server::HttpAdapterServer,
        CanisterHttpRequest, HttpHeader,
    },
    HttpFromCanister,
};
use unix::UnixListenerDrop;

#[tokio::test]
async fn test_https() {
    // setup unix domain socket and start gRPC server on one side of the UDS
    let channel = setup_loop_channel_unix().await;

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
    let channel = setup_loop_channel_unix().await;

    let mut client = HttpAdapterClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request(
        "http://www.bing.com".to_string(),
    ));

    let response = client.send_http_request(request).await;

    assert!(response.is_ok());
    assert_eq!(
        response.unwrap().into_inner().status,
        StatusCode::OK.as_u16() as u32
    );
}

#[tokio::test]
async fn test_no_http() {
    let channel = setup_loop_channel_unix().await;

    let mut client = HttpAdapterClient::new(channel);

    let request = tonic::Request::new(build_http_canister_request("www.google.com".to_string()));

    let response = client.send_http_request(request).await;
    assert!(response.is_err());
}

// TODO: increase functionality of this function (NET-883)
fn build_http_canister_request(url: String) -> CanisterHttpRequest {
    let headers = vec![HttpHeader {
        name: "User-Agent".to_string(),
        value: "test".as_bytes().to_vec(),
    }];

    CanisterHttpRequest {
        url,
        body: "".to_string().into_bytes(),
        headers,
    }
}

async fn setup_loop_channel_unix() -> Channel {
    let uuid = Uuid::new_v4();
    let path = "/tmp/canister-http-test-".to_string() + &uuid.to_string();

    let canister_http = HttpFromCanister::new();

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
