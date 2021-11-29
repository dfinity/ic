//! Test server

/// Reads the client payload from the socket and validates
/// the contents. Supports reading using:
///  1. Explicit polling
///  2. async/await
///
/// target/debug/server (polling mode)
/// target/debug/server --await (for await mode)
use clap::{App, Arg};
use futures::poll;
use futures::task::Poll;
use std::time::Duration;
use tokio::io::{split, AsyncRead, AsyncReadExt};
use tokio::net::TcpListener;
use tokio::time::delay_for;

use qos::payload::PayloadChecker;

type StreamReader = Box<dyn AsyncRead + Send + Unpin>;

struct SockReader {
    reader: StreamReader,
}

impl SockReader {
    fn new(reader: StreamReader) -> Self {
        Self { reader }
    }

    // Uses explicit polling of the read future.
    // Returns the number of bytes read, which may be <= bytes requested. If all the
    // requested bytes could not be read, the caller needs to call this again to read
    // the remaining payload.
    async fn read_using_poll(&mut self, payload: &mut [u8]) -> usize {
        let fut = self.reader.read(payload);
        match poll!(fut) {
            Poll::Ready(result) => match result {
                Ok(read) => {
                    if read < payload.len() {
                        println!(
                            "read_poll(): Poll::Ready/partial({}): read = {}, remaining = {}",
                            payload[0],
                            read,
                            payload.len() - read
                        );
                    } else {
                        println!(
                            "read_poll(): Poll::Ready/complete({}): read = {}",
                            payload[0], read,
                        );
                    }
                    read
                }
                Err(e) => {
                    panic!("read_poll(): Read failed: {:?}", e);
                }
            },
            Poll::Pending => {
                println!("read_poll(): complete({}): {}", payload[0], payload.len());
                0
            }
        }
    }

    // Uses the async/await mechanism for reading from the socket.
    // Returns the requested size always.
    async fn read_using_await(&mut self, payload: &mut [u8]) -> usize {
        match self.reader.read_exact(payload).await {
            Ok(_) => {
                println!(
                    "read_await(): complete({}): read = {}",
                    payload[0],
                    payload.len(),
                );
                payload.len()
            }
            Err(e) => panic!("Failed to read: {:?}", e),
        }
    }
}

async fn read_loop(mut reader: SockReader, mut checker: PayloadChecker, use_await: bool) {
    loop {
        let mut payload = [0; 1024 * 192];
        let mut total_read = 0;
        while total_read < payload.len() {
            let read = if use_await {
                reader.read_using_await(&mut payload[total_read..]).await
            } else {
                reader.read_using_poll(&mut payload[total_read..]).await
            };
            total_read += read;
            if total_read < payload.len() {
                println!(
                    "read_loop(): Incomplete, read = {}, total_read = {}",
                    read, total_read
                );
                tokio::task::yield_now().await;
            } else {
                checker.check(&payload);
                delay_for(Duration::from_secs(1)).await;
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("QoS test server")
        .about("QoS test server")
        .arg(
            Arg::with_name("await")
                .long("await")
                .help("Use async/await"),
        )
        .get_matches();

    let mut listener = TcpListener::bind("127.0.0.1:1234".to_string())
        .await
        .unwrap();

    let stream = match listener.accept().await {
        Ok((stream, addr)) => {
            println!(
                "new client: local = {:?}, peer = {:?}/{:?}",
                stream.local_addr(),
                stream.peer_addr(),
                addr
            );
            stream
        }
        Err(e) => panic!("couldn't get client: {:?}", e),
    };

    let (rd, _) = split(stream);
    let reader = SockReader::new(Box::new(rd));
    read_loop(reader, Default::default(), matches.is_present("await")).await;
}
