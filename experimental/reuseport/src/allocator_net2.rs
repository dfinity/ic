use net2::unix::UnixTcpBuilderExt;
use net2::TcpBuilder;
use std::error::Error;
use std::net::SocketAddr;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    let socket = TcpBuilder::new_v4()?;
    socket.reuse_address(true)?;
    socket.reuse_port(true)?;
    socket.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;

    let local_addr = socket.local_addr()?;
    let local_ip = local_addr.ip();
    let local_port = local_addr.port();

    println!("Allocator: {}:{}", local_ip, local_port);

    Command::new("./client_net2")
        .arg(local_port.to_string())
        .status()?;

    Ok(())
}
