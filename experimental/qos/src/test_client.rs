//! Test client.

use std::time::Duration;
use tokio::io::split;
use tokio::net::TcpStream;
use tokio::time::delay_for;

//use qos::await_rw::AwaitWriter;
use qos::interface::{ErrorCode, StreamWriter};
use qos::payload::PayloadGenerator;
//use qos::poll_rw::PollWriter;
use qos::actor_rw::WriteActorFE;

async fn write_loop(writer: &mut dyn StreamWriter, mut generator: PayloadGenerator) {
    loop {
        let mut payload = generator.generate();
        let pat = payload[0];

        loop {
            match writer.send(payload).await {
                Ok(_) => {
                    println!("write_loop(): success: {}", pat);
                    break;
                }
                Err(ErrorCode::SendFull(p)) => {
                    println!("write_loop(): SendFull {}", pat);
                    delay_for(Duration::from_secs(1)).await;
                    payload = p;
                }
                Err(e) => panic!("write_loop(): failed: {:?}", e),
            }
        }
    }
}

//#[tokio::main]
#[actix_rt::main]
async fn main() {
    // Connect to the server
    let stream = TcpStream::connect("127.0.0.1:1234").await.unwrap();
    println!(
        "Connected to server: local = {:?}, peer = {:?}",
        stream.local_addr(),
        stream.peer_addr()
    );

    let (_, wr) = split(stream);
    let mut writer = WriteActorFE::new(Box::new(wr));
    write_loop(&mut writer, Default::default()).await;
}
