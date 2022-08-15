#![deny(missing_docs)]
//! The dashboard crate introduces a Trait for a simplest HTTP dashboard
//! that could be implemented and used by other crates.

use async_trait::async_trait;
use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

/// A simplest HTTP dashboard that listens to a port and responds to GET
/// requests on a single thread.
#[async_trait]
pub trait Dashboard {
    /// Starts listening on the port and calls handle_connection on each
    /// incoming stream, *one-by-one*.
    async fn listen(&self, exit_signal: Arc<RwLock<bool>>) {
        // Listen on [::] so that we accept both IPv4 and IPv6 connections.
        // See NET-524 for more details.
        let addr = SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            Self::port(),
        );
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                self.log_info(&format!("Failed to bind to socket {}: {}", addr, e));
                return;
            }
        };

        // Wait for incoming connections
        while !*exit_signal.read().await {
            if let Ok((stream, _)) = listener.accept().await {
                self.handle_connection(stream).await;
            }
        }
    }

    /// Checks the request. If it is a GET request on `/`, responds with the
    /// contents built by `build_response`. Otherwise respondes with 404.
    async fn handle_connection(&self, mut stream: TcpStream) {
        let mut buffer = [0; 512];
        if let Err(e) = stream.read(&mut buffer).await {
            self.log_info(&format!("Failed to read request: {}", e));
            return;
        }

        let get = b"GET / ";
        let response = match buffer.starts_with(get) {
            true => {
                let headers = "HTTP/1.1 200 OK\r\n\r\n";
                let contents = self.build_response().await;
                format!("{}{}", headers, contents)
            }
            false => {
                let request = match buffer.lines().next() {
                    Some(Ok(s)) => s,
                    _ => "parse error".to_string(),
                };
                let headers = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
                format!(
                    "{}Not found. Only {:?} is supported, found {:?}",
                    headers,
                    std::str::from_utf8(get).expect("can't fail"),
                    request
                )
            }
        };
        stream
            .write_all(response.as_bytes())
            .await
            .unwrap_or_else(|e| self.log_info(&format!("Failed to flush stream: {}", e)));
        stream
            .flush()
            .await
            .unwrap_or_else(|e| self.log_info(&format!("Failed to flush stream: {}", e)));
    }

    /// Returns the port reserved by the implementing component.
    fn port() -> u16;

    /// Builds the contents of the dashboard and returns it as `String`.
    async fn build_response(&self) -> String {
        "Default response must be overridden".to_string()
    }

    /// Adds an INFO level log using the implementation's logger.
    fn log_info(&self, log_line: &str);
}
