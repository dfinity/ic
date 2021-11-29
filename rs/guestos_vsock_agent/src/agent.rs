use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use vsock_agent::{VsockAddr, VsockStream};

#[derive(Debug)]
enum Error {
    Io(String),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error.to_string())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Self {
        Error::Io(format!("serde_json error: {}", error.to_string()))
    }
}

// The value for IOCTL_VM_SOCKETS_GET_LOCAL_CID is defined at
// https://elixir.bootlin.com/linux/latest/ident/IOCTL_VM_SOCKETS_GET_LOCAL_CID
// But not easily accessible from Rust.

fn get_local_cid() -> Result<u32, Error> {
    // With local (guest) CID we're able to identify the message sender on the
    // receiver (host)
    let mut cid = 0;
    let ioctl_vm_sockets_get_local_cid = 0x7b9;

    unsafe {
        let f = File::open("/dev/vsock")
            .map_err(|err| Error::Io(format!("could not open /dev/vsock: {}", err)))?;
        let fd: RawFd = f.as_raw_fd();

        let local_cid = libc::ioctl(fd, ioctl_vm_sockets_get_local_cid, &mut cid);
        if local_cid < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(cid as u32)
        }
    }
}

fn send_msg(message: &str, cid: u32, port: u32) -> Result<(), Error> {
    let addr = VsockAddr { cid, port };
    let mut conn = VsockStream::connect(addr)?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    conn.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let local_cid = get_local_cid()?;
    let request = serde_json::json!({
        "sender_cid": format!("{}", local_cid),
        "message": message
    });
    let req_vec = serde_json::to_vec(&request)?;

    conn.write_all(&req_vec)?;

    let mut buffer = String::new();
    conn.read_to_string(&mut buffer)?;
    println!("got a response: {}", buffer);
    Ok(())
}

fn send_msg_to_host(message: &str, port: u32) -> Result<(), Error> {
    // VMADDR_CID_ANY (-1U) means any address for binding
    // VMADDR_CID_HYPERVISOR (0) is for services built into the hypervisor
    // VMADDR_CID_LOCAL (1) is the well-known address for local communication
    // (loopback) VMADDR_CID_HOST (2) is the well-known address of the host.
    // https://man7.org/linux/man-pages/man7/vsock.7.html
    let cid_host = 2;
    send_msg(message, cid_host, port)
}

use clap::{App, Arg};

fn main() -> Result<(), Error> {
    let matches = App::new("Host notifier")
        .version("0.1.0")
        .author("DFINITY Stiftung (c) 2021")
        .about("Sends messages to the VM host (Hypervisor) over Vsock")
        .arg(
            Arg::with_name("attach-hsm")
                .long("attach-hsm")
                .help("Request the HSM device to be attached"),
        )
        .arg(
            Arg::with_name("detach-hsm")
                .long("detach-hsm")
                .help("Request the HSM device to be detached"),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("Sets a custom port")
                .takes_value(true)
                .default_value("19090"),
        )
        .get_matches();

    let port = clap::value_t_or_exit!(matches.value_of("port"), u32);

    if matches.is_present("attach-hsm") {
        return send_msg_to_host("attach-hsm", port);
    }

    if matches.is_present("detach-hsm") {
        return send_msg_to_host("detach-hsm", port);
    }

    Ok(())
}
