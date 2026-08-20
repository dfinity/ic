use crate::protocol::structures::*;

/// Parse a response in a json string to a `Response` struct.
pub fn parse_response(json_str: &str) -> Response {
    if let Ok(response) = serde_json::from_str::<Response>(json_str) {
        return response;
    }
    Err("Unable to parse host response: ".to_string() + json_str)
}

/// Parse a request in a json string to `Request` struct.
pub fn parse_request(json_str: &str) -> Result<Request, String> {
    serde_json::from_str::<Request>(json_str)
        .map_err(|error| format!("Unable to parse guest request: {json_str}: {error}"))
}
