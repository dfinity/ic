use std::{
    borrow::Cow,
    mem::take,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::anyhow;
use bytes::Bytes;
use clap::Parser;
use futures_util::{future::Either, Future};
use http::{
    header::{Entry, CONTENT_SECURITY_POLICY},
    HeaderValue, Uri, Version,
};
use http_body::Body;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
    service::service_fn,
    upgrade::Upgraded,
    Method, Request, Response,
};
use once_cell::sync::Lazy;
use regex::bytes::Regex;
use tokio::{
    io::copy_bidirectional,
    net::{lookup_host, TcpListener, TcpStream},
};
use tracing::{error, info, Instrument, Span};

mod support;
use support::{ServerBuilder, TokioExecutor, TokioIo};

#[derive(Parser)]
pub struct Cli {
    /// Port to listen for HTTPS
    #[clap(long, default_value = "8443")]
    pub listen_port: u16,

    /// `host:port` to direct all traffic to. If `port`` is set to 0, the
    /// client requested port will be used.
    #[clap(long, default_value = "127.0.0.1")]
    pub target_host: String,

    /// Should we modify the Content-Security-Policy
    #[clap(long, default_value = "false")]
    pub modify_csp: bool,
}

// To try this example:
// 1. cargo run
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8443
//    $ export https_proxy=http://127.0.0.1:8443
// 3. send requests
//    $ curl -i https://ic0.app/
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .finish(),
    )?;

    let Cli {
        listen_port,
        mut target_host,
        modify_csp,
    } = Cli::parse();

    if !target_host.contains(':') {
        target_host += ":0";
    }

    let target_addr = lookup_host(&target_host)
        .await?
        .next()
        .ok_or_else(|| anyhow!("Failed to lookup `{target_host}`"))?;
    info!("Directing all traffic to {target_addr}");

    let ips = [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()];
    let tasks = ips.map(|ip| tokio::task::spawn(listen(ip, listen_port, target_addr, modify_csp)));
    for task in tasks {
        task.await??;
    }
    Ok(())
}

async fn listen(
    addr: IpAddr,
    port: u16,
    target_addr: SocketAddr,
    modify_csp: bool,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::from((addr, port));
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    loop {
        let (stream, _addr) = listener.accept().await?;
        let io = TokioIo::new(TokioIo::new(stream));
        let mut builder = ServerBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .preserve_header_case(true)
            .title_case_headers(true);

        tokio::task::spawn(async move {
            let conn = builder.serve_connection_with_upgrades(
                io,
                service_fn(move |req| proxy(req, target_addr, modify_csp)),
            );
            conn.await
        });
    }
}

#[tracing::instrument(level = "info", skip(target_addr))]
async fn proxy(
    mut req: Request<Incoming>,
    mut target_addr: SocketAddr,
    modify_csp: bool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if let Some(port) = host_port(req.uri()) {
            if target_addr.port() == 0 {
                target_addr.set_port(port)
            }
        }

        info!(message="creating tunnel to target", target=?target_addr);
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, target_addr).await {
                        error!("server io error: {e}");
                    }
                }
                Err(e) => error!("upgrade error: {e}"),
            }
        });

        Ok(Response::new(empty()))
    } else {
        let version = req.version();
        let port = req.uri().port_u16().unwrap_or(80);
        if target_addr.port() != 0 {
            target_addr.set_port(port)
        }
        let mut uri = take(req.uri_mut()).into_parts();
        uri.scheme = None;
        uri.authority = None;
        *req.uri_mut() = Uri::from_parts(uri).unwrap();

        info!(message="connecting to target", target=?target_addr);
        let stream = TcpStream::connect(target_addr).await.unwrap();
        let io = TokioIo::new(stream);

        let (mut sender, conn) = if [Version::HTTP_10, Version::HTTP_11].contains(&version) {
            let (sender, conn) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;
            (SendRequest::Http1(sender), Either::Left(conn))
        } else if version == Version::HTTP_2 {
            let (sender, conn) = http2::Builder::new(TokioExecutor::new())
                .handshake(io)
                .await?;
            (SendRequest::Http2(sender), Either::Right(conn))
        } else {
            let err = format!("Version {:?} is unknown", req.version());
            error!("{err}");
            let mut resp = Response::new(full(err));
            *resp.status_mut() = http::StatusCode::HTTP_VERSION_NOT_SUPPORTED;
            return Ok(resp);
        };

        tokio::task::spawn(
            async move {
                if let Err(err) = conn.await {
                    error!("Connection failed: {err:?}");
                }
            }
            .instrument(Span::current()),
        );

        let mut resp = sender.send_request(req).await?;
        if modify_csp {
            let headers = resp.headers_mut();
            if let Entry::Occupied(mut entry) = headers.entry(CONTENT_SECURITY_POLICY) {
                for e in entry.iter_mut() {
                    if let Cow::Owned(v) = remove_csp(e.as_bytes()) {
                        *e = HeaderValue::from_maybe_shared(Bytes::from(v)).unwrap();
                    }
                }
            }
        }
        Ok(resp.map(|b| b.boxed()))
    }
}

fn remove_csp(haystack: &[u8]) -> Cow<[u8]> {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?<pre>.*)upgrade-insecure-requests;?(?<post>.*)"#).unwrap());
    RE.replace(haystack, b"$pre$post")
}

fn host_port(uri: &http::Uri) -> Option<u16> {
    uri.authority().and_then(|auth| auth.port_u16())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, addr: SocketAddr) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) = copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    info!("client wrote {from_client} bytes and received {from_server} bytes");

    Ok(())
}

enum SendRequest<B> {
    Http1(http1::SendRequest<B>),
    Http2(http2::SendRequest<B>),
}

impl<B: Body + 'static> SendRequest<B> {
    pub fn send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = hyper::Result<Response<Incoming>>> {
        match self {
            Self::Http1(http1) => Either::Left(http1.send_request(req)),
            Self::Http2(http2) => Either::Right(http2.send_request(req)),
        }
    }
}
