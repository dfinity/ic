use nix::sys::socket::{
    self, sockopt::ReuseAddr, sockopt::ReusePort, AddressFamily, InetAddr, IpAddr, SockAddr,
    SockFlag, SockProtocol, SockType,
};
use std::error::Error;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    // nix::sys::socket is a bit stone knives and bearskins...
    let socket = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )?;
    socket::setsockopt(socket, ReuseAddr, &true)?;
    socket::setsockopt(socket, ReusePort, &true)?;

    let addr = InetAddr::new(IpAddr::new_v4(127, 0, 0, 1), 0);
    socket::bind(socket, &SockAddr::new_inet(addr))?;

    let local_addr = socket::getsockname(socket)?;

    let local_addr = match local_addr {
        SockAddr::Inet(addr) => addr,
        _ => panic!("Unexpected IP address type"),
    };

    let local_ip = local_addr.ip();
    let local_port = local_addr.port();

    println!("Allocator: {}:{}", local_ip, local_port);

    Command::new("./client_nix")
        .arg(local_port.to_string())
        .status()?;

    Ok(())
}
