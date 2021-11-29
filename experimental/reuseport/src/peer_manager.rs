use net2::unix::UnixTcpBuilderExt;
use net2::TcpBuilder;
use std::collections::HashSet;
use std::error::Error;
use std::net::SocketAddrV4;
use std::process::{Child, Command};
use std::{thread, time};

const IP_ADDRESS: &'static str = "127.0.0.1";

/// Details about each peer.
struct Peer {
    /// Port it should listen on
    port: u16,

    /// Ports of peers it should connect to
    peer_ports: Vec<u16>,

    /// Socket allocated to this peer
    ///
    /// This is not used, but it has to remain in scope, otherwise the value
    /// is dropped, the socket is closed, and another process could be
    /// allocated the same port. See comments later for more details.
    ///
    /// This is only an `Option` so that it can easily be set to `None` later.
    _socket: Option<TcpBuilder>,
}

/// Trivial peer manager. Allocates N ports, one per peer, and then starts
/// each peer with command line arguments indicating which port to listen on
/// and which ports to connect to.
///
/// Takes one command line arg, the number of peers to start (e.g., 3).
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: peer_manager num-peers");
        return Ok(());
    }
    let num_peers = args[1].parse::<u8>()?;

    let mut peers: Vec<Peer> = vec![];
    let mut peer_ports: HashSet<u16> = HashSet::new();

    for _ in 0..num_peers {
        // Bind to a random port
        let socket = TcpBuilder::new_v4()?;
        socket.reuse_address(true)?;
        socket.reuse_port(true)?;
        let _ = socket.bind(SocketAddrV4::from(format!("{}:0", IP_ADDRESS).parse()?));
        let port = socket.local_addr()?.port();

        println!("peer_manager: allocated {}", port);

        // Save the port number for later
        peer_ports.insert(port);

        // Build the peer.
        let peer = Peer {
            port,
            peer_ports: vec![],
            // Save the socket. If this is not done then it falls out of scope
            // at the end of this block, the socket is closed, and the port
            // becomes usable by another process, which we expressly want to
            // avoid.
            _socket: Some(socket),
        };

        peers.push(peer);
    }

    // At this point the ports are still allocated, so nothing else can take
    // them (assuming it doesn't also set SO_REUSEPORT).
    //
    // The code here allows you to verify this. Adjust the length of the
    // timeout in the `thread::sleep` call on line 105 from 1 ms to e.g.,
    // 20_0000 ms. Then build and re-run this program, with a second terminal
    // handy.
    //
    // When the code reaches this point it will print the `netstat` command.
    // (verified on OSX). Run that in the second terminal while this code is
    // sleeping, and verify that you see all the allocated ports in the
    // `CLOSED` state.
    //
    // Then, edit this file, and on line 64 change the value assigned to
    // `_socket` from `Some(socket)` to `None`.
    //
    // Now re-build and re-run this program. The socket left scope and was
    // dropped on line 68, so the port was closed. When you run the netstat
    // command printed this time you'll see that the ports aren't bound
    // (there will be no output).

    // Print a message to allow the person running this to verify that the ports
    // are still allocated before any of the children start.
    println!("peer_manager: You can verify the ports are bound by running");
    println!(
        "netstat -a -n | grep -E '({})'  # expect to see CLOSED",
        peer_ports
            .iter()
            .map(|&n| n.to_string())
            .collect::<Vec<String>>()
            .join("|")
    );

    thread::sleep(time::Duration::from_millis(1));

    // Construct the list of peer ports for each peer. Put all the ports in a
    // set, remove the port allocated to this peer, and the ones left are the
    // ports it should connect to.
    for mut peer in &mut peers {
        let mut ports = peer_ports.clone();
        ports.remove(&peer.port);
        peer.peer_ports = ports.iter().map(|n| *n).collect();
    }

    for peer in &peers {
        println!(
            "peer_manager: peer on {} connects to -> {:?}",
            peer.port, peer.peer_ports
        );
    }

    // Launch the `peer` processes with the correct command line arguments
    let mut children: Vec<Child> = vec![];

    for peer in &mut peers {
        let mut cmd = Command::new("./peer");
        cmd.arg(format!("{}", peer.port));
        for peer_port in &peer.peer_ports {
            cmd.arg(format!("{}", peer_port));
        }
        children.push(cmd.spawn()?);
    }

    for mut child in children {
        let _ = child.wait();
    }

    Ok(())
}
