mod client;
mod get_protocol_version;
use crate::protocol::{Command, Request, Response, VsockProtocol};

/// Send a command to the host vsock server
pub fn send_command(command: Command, port: u32) -> Response {
    let guest_cid = vsock::get_local_cid().map_err(|e| e.to_string())?;

    let request = Request { guest_cid, command };

    let protocol_version: VsockProtocol = get_protocol_version::get_protocol_version(&port)?;

    client::send_request_to_host_and_parse_response(&request, &port, &protocol_version)
}
