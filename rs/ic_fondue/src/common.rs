use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

/// Port numbers are u16's
pub type Port = u16;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Command {
    Get,
    Set(usize),
}

impl FromStr for Command {
    type Err = bool;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq("get") {
            Ok(Command::Get)
        } else if let Some(rest) = s.strip_prefix("set(").and_then(|s| s.strip_suffix(")")) {
            if let Ok(num) = usize::from_str(rest) {
                Ok(Command::Set(num))
            } else {
                Err(false)
            }
        } else {
            Err(true)
        }
    }
}

pub fn send_command_to(sock: &UdpSocket, cmd: Command, addr: SocketAddr) {
    sock.send_to(&bincode::serialize(&cmd).unwrap(), addr)
        .unwrap();
}

pub fn client(dest: Port, cmd: Command) -> Option<Command> {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind");
    send_command_to(
        &sock,
        cmd.clone(),
        format!("127.0.0.1:{}", dest)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap(),
    );

    let mut buf = [0u8; 128];
    if let Command::Get = cmd {
        sock.set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        let (_n, src_addr) = sock.recv_from(&mut buf).expect("Didn't receive data");
        match bincode::deserialize::<Command>(&buf) {
            Err(_err) => {
                println!("Error: can't parse data from {}", src_addr);
                None
            }
            Ok(data) => Some(data),
        }
    } else {
        None
    }
}
