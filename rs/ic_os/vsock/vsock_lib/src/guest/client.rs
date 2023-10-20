use crate::protocol::{
    get_v0_request_vec, parse_response, Command, Payload, Request, Response, VsockProtocol,
};
use std::io::{Read, Write};
use vsock::{VsockStream, VMADDR_CID_HOST};

// the length of HOSTOS_V0_VERSION matches the length of "real" hostOS versions, 64 characters
const HOSTOS_V0_VERSION: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn send_request_to_host_and_parse_response(
    request: &Request,
    port: &u32,
    protocol_version: &VsockProtocol,
) -> Response {
    if (request.command == Command::GetHostOSVersion) && (*protocol_version == VsockProtocol::V0) {
        // A V0 VsockProtocol means that we're communicating with hostos_vsock_v0, and hostos_vsock_v0 does not support the GetHostOSVersion command. In this case, we can early return HOSTOS_V0_VERSION. This allows the orchestrator to still call the GetHostOSVersion command on hostos_vsock_v0.
        return Ok(Payload::HostOSVersion(HOSTOS_V0_VERSION.to_string()));
    }

    let response_str = send_request_to_host(request, port, protocol_version)?;

    parse_response(response_str.as_str(), protocol_version)
}

pub fn send_request_to_host(
    request: &Request,
    port: &u32,
    protocol_version: &VsockProtocol,
) -> Result<String, String> {
    let mut stream = create_stream(port).map_err(|e| e.to_string())?;

    match protocol_version {
        VsockProtocol::V0 => {
            let request_vec = get_v0_request_vec(request)?;
            stream.write_all(&request_vec).map_err(|e| e.to_string())?;
        }
        VsockProtocol::V1 => {
            let json_request = serde_json::to_string(request).map_err(|e| e.to_string())?;
            stream
                .write_all(json_request.as_bytes())
                .map_err(|e| e.to_string())?;
        }
    };

    let read_result = read_response_from_host(&mut stream);

    // When sending an upgrade command to a V0 HostOS, we may hang up the
    // socket early. In this case, transform into a "good" result, and leave a
    // log about it.

    // When running an upgrade command...
    if let Command::Upgrade(_) = request.command {
        // ...targeting a V0 host agent...
        if *protocol_version == VsockProtocol::V0 {
            // ...and the result was an error...
            if let Result::Err(e) = &read_result {
                // ...if this was an IO Error...
                if let Some(e) = e.downcast_ref::<std::io::Error>() {
                    // ...where the other side hung up early...
                    if let std::io::ErrorKind::WouldBlock = e.kind() {
                        // ...report that we are ignoring the error...
                        eprintln!("Upgrade command to V0 host agent resulted in hangup error: `{e}`, ignoring.");

                        // ...and return `Ok`.
                        return Ok(
                            "{\"message\": \"accepted request\", \"status\": \"ok\"}".to_string()
                        );
                    }
                }
            }
        }
    }

    read_result.map_err(|e| e.to_string())
}

fn read_response_from_host(stream: &mut VsockStream) -> anyhow::Result<String> {
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;

    std::str::from_utf8(&buffer[..bytes_read])
        .map(|response| response.to_string())
        .map_err(|e| e.into())
}

fn create_stream(port: &u32) -> Result<VsockStream, std::io::Error> {
    let stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, *port)?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    Ok(stream)
}
