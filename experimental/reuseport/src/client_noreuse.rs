use net2::TcpBuilder;
use std::error::Error;
use std::net::{Shutdown, SocketAddr};

fn main() -> Result<(), Box<dyn Error>> {
    let port = std::env::args().nth(1).unwrap();
    let addr = format!("127.0.0.1:{}", port);

    println!("Client listening to: {}", addr);

    let socket = TcpBuilder::new_v4()?;
    socket.bind(SocketAddr::from(([127, 0, 0, 1], port.parse()?)))?;
    let listener = socket.listen(1)?;

    loop {
        match listener.accept() {
            Ok((_socket, _addr)) => {
                println!("Client received a connection");
                _socket.shutdown(Shutdown::Both)?;
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}
