use nix::sys::socket::Shutdown;
use nix::sys::socket::{
    self, sockopt::ReuseAddr, sockopt::ReusePort, AddressFamily, InetAddr, IpAddr, SockAddr,
    SockFlag, SockProtocol, SockType,
};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Treat the first arg as the port
    let port = std::env::args().nth(1).unwrap();
    let addr = format!("127.0.0.1:{}", port);

    println!("Client listening to: {}", addr);

    let socket = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )?;
    socket::setsockopt(socket, ReuseAddr, &true)?;
    socket::setsockopt(socket, ReusePort, &true)?;

    let addr = InetAddr::new(IpAddr::new_v4(127, 0, 0, 1), port.parse()?);
    socket::bind(socket, &SockAddr::new_inet(addr))?;

    socket::listen(socket, 1)?;

    loop {
        let conn = socket::accept(socket)?;
        println!("Client received a connection");
        socket::shutdown(conn, Shutdown::Both)?;
    }
}
