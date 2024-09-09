use crate::protocol::{parse_response, Request, Response};
use std::io::{Read, Write};
use vsock::{VsockStream, VMADDR_CID_HOST};

pub fn send_request_to_host_and_parse_response(request: &Request, port: &u32) -> Response {
    let response_str = send_request_to_host(request, port)?;

    parse_response(response_str.as_str())
}

pub fn send_request_to_host(request: &Request, port: &u32) -> Result<String, String> {
    let mut stream = create_stream(port).map_err(|e| e.to_string())?;

    let json_request = serde_json::to_string(request).map_err(|e| e.to_string())?;
    stream
        .write_all(json_request.as_bytes())
        .map_err(|e| e.to_string())?;

    let read_result = read_response_from_host(&mut stream);

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
    // Set a long timeout, so HostOS has enough time to upgrade.
    stream.set_write_timeout(Some(std::time::Duration::from_secs(60 * 5)))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(60 * 5)))?;

    Ok(stream)
}
