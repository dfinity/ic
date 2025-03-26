use crate::host::agent::dispatch;
use crate::protocol::{parse_request, Request, Response};
use std::io::{Error, ErrorKind, Read, Result, Write};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

const DEFAULT_PORT: u32 = 19090;

/// Runs the vsock server and awaits incoming vsock connections.
pub fn run_server() -> Result<()> {
    let vsock_listener: VsockListener = create_vsock_listener()?;

    println!("Listening for vsock connection.\n");

    for stream in vsock_listener.incoming() {
        let mut stream: VsockStream = stream?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        std::thread::spawn(move || -> Result<()> { process_connection(&mut stream) });
    }

    Ok(())
}

fn create_vsock_listener() -> Result<VsockListener> {
    let addr = VsockAddr::new(VMADDR_CID_ANY, DEFAULT_PORT);
    VsockListener::bind(&addr)
}

fn process_connection(stream: &mut VsockStream) -> Result<()> {
    let request = match get_request(stream) {
        Ok(request) => request,
        Err(err) => {
            send_response(stream, &Err(err.to_string()))?;
            return Err(err);
        }
    };
    println!("Received vsock request: {}", request);

    if let Err(err) = verify_sender_cid(stream, request.guest_cid) {
        send_response(stream, &Err(err.to_string()))?;
        return Err(err);
    };

    let response: Response = dispatch(&request.command);

    send_response(stream, &response)
}

fn get_request(stream: &mut VsockStream) -> Result<Request> {
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    let json_request: String = match std::str::from_utf8(&buffer[..bytes_read]) {
        Ok(json_str_request) => json_str_request.to_string(),
        Err(error) => {
            println!("Error converting bytes to string: {}", error);
            return Err(Error::new(ErrorKind::InvalidData, error));
        }
    };

    parse_request(json_request.as_str()).map_err(|e| Error::new(ErrorKind::InvalidInput, e))
}

// As a sanity check, we request that the sender adds its own CID to the message, and that CID must match the CID in the stream peer address.
fn verify_sender_cid(stream: &mut VsockStream, guest_cid: u32) -> Result<()> {
    let peer_address = match stream.peer_addr() {
        Ok(peer_address) => peer_address,
        Err(err) => {
            let error = format!("Error: could not verify the sender_cid. {}", err);
            return Err(Error::new(ErrorKind::InvalidData, error));
        }
    };

    if peer_address.cid() == guest_cid {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            "The actual sender CID did not match the sender CID in the request object",
        ))
    }
}

fn send_response(stream: &mut VsockStream, response: &Response) -> Result<()> {
    let json_response = serde_json::to_string(&response)?;
    stream.write_all(json_response.as_bytes())?;

    Ok(())
}
