//! Test client

/// Generates payload and writes to the socket.
/// Supports reading using:
///  1. Explicit polling
///  2. async/await
///
/// target/debug/client (polling mode)
/// target/debug/client --await (for await mode)
use clap::{App, Arg};
use futures::poll;
use futures::task::Poll;
use tokio::io::{split, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use qos::payload::PayloadGenerator;

type StreamWriter = Box<dyn AsyncWrite + Send + Unpin>;

struct SockWriter {
    writer: StreamWriter,
}

impl SockWriter {
    fn new(writer: StreamWriter) -> Self {
        Self { writer }
    }

    // Uses explicit polling of the write future.
    // Returns the payload that could not be written to the socket. If any payload
    // is unwritten, caller needs to call this again to send the remaining payload.
    async fn write_using_poll(&mut self, mut payload: Vec<u8>) -> Option<Vec<u8>> {
        let count: Vec<u8> = payload
            .iter()
            .filter(|&v| *v == payload[0])
            .cloned()
            .collect::<Vec<u8>>();
        assert_eq!(count.len(), payload.len());

        let fut = self.writer.write(&payload);
        match poll!(fut) {
            Poll::Ready(result) => match result {
                Ok(sent) => {
                    if sent == payload.len() {
                        println!(
                            "write_poll(): Poll::Ready/complete({}): sent = {}",
                            payload[0], sent,
                        );
                        None
                    } else {
                        println!(
                            "write_poll(): Poll::Ready/partial({}): sent = {}, remaining = {}",
                            payload[0],
                            sent,
                            payload.len() - sent
                        );
                        Some(payload.split_off(sent))
                    }
                }
                Err(e) => {
                    panic!("write_poll(): Write failed: {:?} {}", e, payload[0]);
                }
            },
            Poll::Pending => {
                println!(
                    "write_poll(): Poll::Pending({}): {}",
                    payload[0],
                    payload.len()
                );
                Some(payload)
            }
        }
    }

    // Uses the async/await mechanism for writing to the socket.
    // Returns None always, as the complete payload is written.
    async fn write_using_await(&mut self, payload: Vec<u8>) -> Option<Vec<u8>> {
        let count: Vec<u8> = payload
            .iter()
            .filter(|&v| *v == payload[0])
            .cloned()
            .collect::<Vec<u8>>();
        assert_eq!(count.len(), payload.len());
        match self.writer.write_all(&payload).await {
            Ok(_) => {
                println!(
                    "write_await(): complete({}): sent = {}",
                    payload[0],
                    payload.len(),
                );
                None
            }
            Err(e) => panic!("Failed to write: {}", e),
        }
    }
}

async fn write_loop(mut writer: SockWriter, mut generator: PayloadGenerator, use_await: bool) {
    loop {
        let mut payload = generator.generate();
        let pat = payload[0];
        loop {
            let result = if use_await {
                writer.write_using_await(payload).await
            } else {
                writer.write_using_poll(payload).await
            };
            match result {
                Some(remaining) => {
                    println!(
                        "write_loop(): Incomplete, remaining({}): {}",
                        pat,
                        remaining.len()
                    );
                    payload = remaining;
                    tokio::task::yield_now().await;
                }
                None => {
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("QoS test client")
        .about("QoS test client")
        .arg(
            Arg::with_name("await")
                .long("await")
                .help("Use async/await"),
        )
        .get_matches();

    // Connect to the server
    let stream = TcpStream::connect("127.0.0.1:1234").await.unwrap();
    println!(
        "Connected to server: local = {:?}, peer = {:?}",
        stream.local_addr(),
        stream.peer_addr()
    );

    let (_, wr) = split(stream);
    let writer = SockWriter::new(Box::new(wr));
    write_loop(writer, Default::default(), matches.is_present("await")).await;
}
