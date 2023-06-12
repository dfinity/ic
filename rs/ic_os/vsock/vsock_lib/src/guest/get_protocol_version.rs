use crate::guest::client::send_request_to_host;
use crate::protocol::{
    parse_response, Command, HostOSVsockVersion, Payload, Request, VsockProtocol,
};
use vsock::get_local_cid;

// The guest vsock is backwards compatible, so it must know if the host vsock agent is the old or new version (v0 or v1) so that it can use the correct protocol.
pub fn get_protocol_version(port: &u32) -> Result<VsockProtocol, String> {
    let response = send_protocol_request_to_host(port)?;
    parse_protocol_response(&response)
}

fn send_protocol_request_to_host(port: &u32) -> Result<String, String> {
    let guest_cid = get_local_cid().map_err(|e| e.to_string())?;

    let request = Request {
        guest_cid,
        command: Command::GetVsockProtocol,
    };

    send_request_to_host(&request, port, &VsockProtocol::V1)
}

// the host vsock may be host_v0 or host_v1, so we attempt to parse the response using protocol V1, and if that returns error, we attempt to parse using protocol V0
fn parse_protocol_response(response: &str) -> Result<VsockProtocol, String> {
    let parse_v1_response = |payload: Payload| -> Result<VsockProtocol, String> {
        match payload {
            Payload::HostOSVsockVersion(hostos_vsock_version) => {
                parse_v1_response_helper(hostos_vsock_version)
            }
            _ => Err(format!(
                "Logical error. Received invalid payload: {}",
                payload
            )),
        }
    };

    let parse_v0_response = |payload: Payload| -> Result<VsockProtocol, String> {
        match payload {
            Payload::NoPayload => Ok(VsockProtocol::V0),
            _ => Err("Could not parse response".to_string()),
        }
    };

    match parse_response(response, &VsockProtocol::V1) {
        Ok(payload) => parse_v1_response(payload),
        Err(_) => match parse_response(response, &VsockProtocol::V0) {
            Ok(payload) => parse_v0_response(payload),
            Err(_) => Err("Could not parse response".to_string()),
        },
    }
}

fn parse_v1_response_helper(
    hostos_vsock_version: HostOSVsockVersion,
) -> Result<VsockProtocol, String> {
    match hostos_vsock_version {
        HostOSVsockVersion {
            major: 1,
            minor: _,
            patch: _,
        } => Ok(VsockProtocol::V1),
        // this case should never happen
        HostOSVsockVersion {
            major: 0,
            minor: _,
            patch: _,
        } => Ok(VsockProtocol::V0),
        _ => {
            let error_string = format!(
                "Unnacceptable hostOS vsock version: {}",
                hostos_vsock_version
            );
            Err(error_string)
        }
    }
}
