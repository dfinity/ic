mod client;
use crate::protocol::{Command, Request, Response};

/// Send a command to the host vsock server
pub fn send_command(command: Command, port: u32) -> Response {
    let guest_cid = vsock::get_local_cid().map_err(|e| e.to_string())?;

    let request = Request { guest_cid, command };

    client::send_request_to_host_and_parse_response(&request, &port)
}
