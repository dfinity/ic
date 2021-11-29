//! Test server.

use std::time::Duration;
use tokio::io::split;
use tokio::net::TcpListener;
use tokio::time::delay_for;

//use qos::await_rw::AwaitReader;
use qos::interface::{ErrorCode, Payload, StreamReader};
use qos::payload::PayloadChecker;
use qos::poll_rw::PollReader;

async fn read_payload(reader: &mut dyn StreamReader) -> Payload {
    loop {
        match reader.receive().await {
            Ok(p) => return p,
            Err(ErrorCode::ReadEmpty) => {
                println!("read_payload(): Read empty ...");
                delay_for(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("read_payload(): read failed: {:?}", e),
        }
    }
}

async fn read_loop(reader: &mut dyn StreamReader, mut checker: PayloadChecker) {
    loop {
        let payload = read_payload(reader).await;
        checker.check(&payload);
    }
}

#[tokio::main]
async fn main() {
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
    let mut reader = PollReader::new(Box::new(rd));
    read_loop(&mut reader, Default::default()).await;
}
