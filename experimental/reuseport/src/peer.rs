use net2::unix::UnixTcpBuilderExt;
use net2::TcpBuilder;
use rand::Rng;
use std::error::Error;
use std::net::{Shutdown, SocketAddrV4, TcpStream};
use std::{io, thread, time};

const IP_ADDRESS: &'static str = "127.0.0.1";

/// Trivial network server/client. Listens for connections from other peers, and
/// periodically (every 1-10 seconds) connects to a random peer. No data is
/// exchanged, just the connection.
///
/// Takes 2..n command line args
///
/// - First arg is the port it should listen on
/// - Second and subsequent args are ports it should connect to
///
/// E.g.,
///
///   ./peer 10000 10001 10002
///
/// Will listen on port 10000 for incoming connections, and will periodically
/// attempt to connect to peers on ports 10001 and 10002
fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: peer my-port peer-port ...");
        return Ok(());
    }

    // Parse command line arguments
    let mut port_args: Vec<u16> = args
        .split_off(1)
        .iter()
        .map(|s| s.parse::<u16>().unwrap())
        .collect();
    let port = port_args[0];
    let peer_ports = port_args.split_off(1);

    // Listen on our own port on a thread
    let listen_socket = create_listen_socket(port)?;
    let listener = listen_socket.listen(1)?;

    println!("peer: listening on {}:{}", IP_ADDRESS, port);

    let listen_thread = thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((stream, addr)) => {
                    println!("peer: {} received a connection from {:?}", port, addr);
                    let _ = stream.shutdown(Shutdown::Both);
                }
                _ => { /* If this was a real server, error handling here ... */ }
            }
        }
    });

    // Thread that sleeps for 1..10 seconds, picks a peer at random to connect
    // to, and connects to it.
    let connect_thread = thread::spawn(move || {
        let mut rng = rand::thread_rng();
        loop {
            let sleep_secs = rng.gen_range(1, 11);
            thread::sleep(time::Duration::from_secs(sleep_secs));

            let peer_index = rng.gen_range(0, &peer_ports.len());
            let peer_port = peer_ports[peer_index];
            let peer_addr = format!("{}:{}", IP_ADDRESS, peer_port);

            let _ = TcpStream::connect(peer_addr);
        }
    });

    let _ = listen_thread.join();
    let _ = connect_thread.join();

    Ok(())
}

fn create_listen_socket(port: u16) -> io::Result<TcpBuilder> {
    let socket = TcpBuilder::new_v4()?;
    socket.reuse_address(true)?;
    socket.reuse_port(true)?;
    let addr = format!("{}:{}", IP_ADDRESS, port).parse().unwrap();
    socket.bind(SocketAddrV4::from(addr))?;
    Ok(socket)
}
