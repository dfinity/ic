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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": "attach-hsm"
            }),
            serde_json::to_value(&Request {
                guest_cid: 1,
                command: Command::AttachHSM
            })
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": "detach-hsm"
            }),
            serde_json::to_value(&Request {
                guest_cid: 1,
                command: Command::DetachHSM
            })
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": {
                    "notify": {
                        "count": 1i32,
                        "message": "Hello World",
                    }
                }
            }),
            serde_json::to_value(Request {
                guest_cid: 1,
                command: Command::Notify(NotifyData {
                    count: 1,
                    message: "Hello World".to_string(),
                })
            })
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": {
                    "upgrade": {
                        "url": "https://example.com",
                        "target-hash": "0x1111222233334444"
                    }
                }
            }),
            serde_json::to_value(Request {
                guest_cid: 1,
                command: Command::Upgrade(UpgradeData {
                    url: "https://example.com".to_string(),
                    target_hash: "0x1111222233334444".to_string()
                })
            })
            .unwrap()
        );
    }

    #[test]
    fn test_response_serialization() {
        let response: Response = Ok(Payload::NoPayload);
        assert_eq!(
            serde_json::json!({
                "Ok": "NoPayload",
            }),
            serde_json::to_value(response).unwrap()
        );

        let vsock_version: HostOSVsockVersion = HostOSVsockVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let response: Response = Ok(Payload::HostOSVsockVersion(vsock_version));

        let expected_json = serde_json::json!({
            "Ok": {
                "HostOSVsockVersion": {
                    "major": 1,
                    "minor": 0,
                    "patch": 0
                }
            }
        });
        assert_eq!(expected_json, serde_json::to_value(response).unwrap());

        let response: Response = Ok(Payload::HostOSVersion("VERSION".to_string()));
        let expected_json = serde_json::json!({
            "Ok": {
                "HostOSVersion": "VERSION",
            }
        });
        assert_eq!(expected_json, serde_json::to_value(response).unwrap());
    }

    #[test]
    fn test_parse_request() {
        // Test AttachHSM command
        let json_str = r#"{"sender_cid": 123, "message": "attach-hsm"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.command, Command::AttachHSM);

        // Test DetachHSM command
        let json_str = r#"{"sender_cid": 123, "message": "detach-hsm"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.command, Command::DetachHSM);

        // Test Upgrade command
        let json_str = r#"{"sender_cid": 123, "message": {"upgrade": {"url": "http://example.com/upgrade", "target-hash": "abcd1234hash"}}}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        match request.command {
            Command::Upgrade(data) => {
                assert_eq!(data.url, "http://example.com/upgrade");
                assert_eq!(data.target_hash, "abcd1234hash");
            }
            _ => panic!("Expected Upgrade command"),
        }

        // Test Notify command
        let json_str = r#"{"sender_cid": 123, "message": {"notify": {"message": "System update required", "count": 2}}}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        match request.command {
            Command::Notify(data) => {
                assert_eq!(data.count, 2);
                assert_eq!(data.message, "System update required");
            }
            _ => panic!("Expected Notify command"),
        }

        // Test GetVsockProtocol command
        let json_str = r#"{"sender_cid": 123, "message": "GetVsockProtocol"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        assert_eq!(request.command, Command::GetVsockProtocol);

        // Test GetHostOSVersion command
        let json_str = r#"{"sender_cid": 123, "message": "GetHostOSVersion"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        assert_eq!(request.command, Command::GetHostOSVersion);

        // Test malformed command
        let json_str = r#"{"sender_cid": 123, "message": "attach-hsm"#; // Missing closing brace
        let request = parse_request(json_str);
        assert!(request.is_err());
    }

    #[test]
    fn test_parse_response() {
        assert_eq!(
            Ok(Payload::NoPayload),
            parse_response("{\"Ok\":\"NoPayload\"}")
        );
        assert_eq!(
            Ok(Payload::HostOSVersion("123".to_string())),
            parse_response("{\"Ok\":{\"HostOSVersion\":\"123\"}}")
        );
        assert_eq!(
            Ok(Payload::HostOSVsockVersion(HostOSVsockVersion {
                major: 1,
                minor: 0,
                patch: 0,
            })),
            parse_response(
                "{\"Ok\":{\"HostOSVsockVersion\":{\"major\":1,\"minor\":0,\"patch\":0}}}"
            )
        );
        assert_eq!(
            Err("Unable to parse host response: Error response".to_string()),
            parse_response("Error response")
        );

        let json_str = r#"{"Ok":"NoPayload"#; // Missing closing brace
        let response = parse_response(json_str);
        assert!(response.is_err());
    }
}
