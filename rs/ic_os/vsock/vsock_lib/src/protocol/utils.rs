use crate::protocol::structures::*;
use regex::Regex;

/// Parses a response in a json string to a `Response` struct for protocol v0 or v1.
pub fn parse_response(json_str: &str, hostos_protocol: &VsockProtocol) -> Response {
    match hostos_protocol {
        VsockProtocol::V1 => {
            if let Ok(response) = serde_json::from_str::<Response>(json_str) {
                return response;
            }
            Err("Unable to parse host_v1 response: ".to_string() + json_str)
        }
        VsockProtocol::V0 => match json_str {
            "{\"message\": \"accepted request\", \"status\": \"ok\"}" => Ok(Payload::NoPayload),
            error => Err(error.to_string()),
        },
    }
}

/// Map a request in a json string to `Request` struct. Handles conversion of version 0 `LegacyRequest`.
pub fn parse_request(json_str: &str) -> Result<Request, String> {
    if let Ok(request) = serde_json::from_str::<Request>(json_str) {
        return Ok(request);
    }
    if let Ok(request) = serde_json::from_str::<LegacyRequest>(json_str) {
        if request.command.starts_with("attach-hsm") {
            let guest_cid = request
                .guest_cid
                .parse::<u32>()
                .map_err(|_| "could not convert cid to u32".to_string())?;
            return Ok(Request {
                guest_cid,
                command: Command::AttachHSM,
            });
        } else if request.command.starts_with("detach-hsm") {
            let guest_cid = request
                .guest_cid
                .parse::<u32>()
                .map_err(|_| "could not convert cid to u32".to_string())?;
            return Ok(Request {
                guest_cid,
                command: Command::DetachHSM,
            });
        } else if request.command.starts_with("set-node-id") {
            let re = Regex::new(r".*\[([^\]]*)\]").map_err(|_| "bad regex".to_string())?;
            let args = re
                .captures(&request.command)
                .ok_or_else(|| "bad captures".to_string())?;
            if args.len() != 2 {
                return Err("unable parse args: ".to_string() + json_str);
            }
            let guest_cid = request
                .guest_cid
                .parse::<u32>()
                .map_err(|_| "could not convert cid to u32".to_string())?;
            return Ok(Request {
                guest_cid,
                command: Command::SetNodeId(NodeIdData {
                    node_id: args[1].to_string(),
                }),
            });
        } else if request.command.starts_with("notify") {
            let re =
                Regex::new(r".*\[([^,\]]*),? *([^\]]*)\]").map_err(|_| "bad regex".to_string())?;
            let args = re
                .captures(&request.command)
                .ok_or_else(|| "bad captures".to_string())?;
            if args.len() != 3 {
                return Err("unable parse args: ".to_string() + json_str);
            }
            let guest_cid = request
                .guest_cid
                .parse::<u32>()
                .map_err(|_| "could not convert cid to u32".to_string())?;
            return Ok(Request {
                guest_cid,
                command: Command::Notify(NotifyData {
                    count: args[1]
                        .parse::<u32>()
                        .map_err(|_| "bad count".to_string())?,
                    message: args[2].to_string().trim().to_string(),
                }),
            });
        } else if request.command.starts_with("upgrade") {
            let re = Regex::new(r".*\[([^ ]*) *(.*)\].*").map_err(|_| "bad regex".to_string())?;
            let args = re
                .captures(&request.command)
                .ok_or_else(|| "bad captures".to_string())?;
            if args.len() != 3 {
                return Err("unable parse args: ".to_string() + json_str + &args.len().to_string());
            }
            let guest_cid = request
                .guest_cid
                .parse::<u32>()
                .map_err(|_| "could not convert cid to u32".to_string())?;
            return Ok(Request {
                guest_cid,
                command: Command::Upgrade(UpgradeData {
                    url: args[1].to_string(),
                    target_hash: args[2].to_string(),
                }),
            });
        } else {
            return Err("could not match legacy request to command: ".to_string() + json_str);
        };
    }
    Err("unable to parse: ".to_string() + json_str)
}

// Convert a v1 `Request` struct into a v0 request vector
pub fn get_v0_request_vec(request: &Request) -> Result<Vec<u8>, String> {
    let message = match &request.command {
        Command::AttachHSM => "attach-hsm".to_string(),
        Command::DetachHSM => "detach-hsm".to_string(),
        Command::SetNodeId(node_id) => format!("set-node-id[{}]", node_id.node_id),
        Command::Upgrade(upgrade_data) => {
            format!("upgrade[{} {}]", upgrade_data.url, upgrade_data.target_hash)
        }
        Command::Notify(notify_data) => {
            format!("notify[{}, {}]", notify_data.count, notify_data.message)
        }
        Command::GetVsockProtocol => {
            return Err("Cannot process GetVsockProtocol command for v0".to_string())
        }
        Command::GetHostOSVersion => {
            return Err("Cannot process GetHostOSVersion command for v0".to_string())
        }
    };

    let request = serde_json::json!({
        "sender_cid": request.guest_cid.to_string(),
        "message": message
    });

    // host_vsock_v0 uses JSON byte vector serialization whereas host_vsock_v1 uses string JSON serialization.
    let req_vec = serde_json::to_vec(&request).map_err(|e| e.to_string())?;

    Ok(req_vec)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_json() {
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
                    "set-node-id": {
                        "node-id": "node-id-1"
                    }
                }
            }),
            serde_json::to_value(Request {
                guest_cid: 1,
                command: Command::SetNodeId(NodeIdData {
                    node_id: "node-id-1".to_string()
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
    fn test_parse_request() {
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": "attach-hsm"
                }
            ),
            serde_json::to_value(
                parse_request(
                    r#"{
                                 "sender_cid": "1",
                                 "message": "attach-hsm"
                                 }
                                 "#
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": "detach-hsm"
                }
            ),
            serde_json::to_value(
                parse_request(
                    r#"{
                                 "sender_cid": "1",
                                 "message": "detach-hsm"
                                 }
                                 "#
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": {
                    "set-node-id": {
                        "node-id": "node-id-1"
                    }
                }
            }),
            serde_json::to_value(
                parse_request(
                    r#"{
                                 "sender_cid": "1",
                                 "message": "set-node-id [node-id-1]"
                                 }
                                 "#
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::json!({
                "sender_cid": 1u32,
                "message": {
                    "notify": {
                        "count": 2i32,
                        "message": "Hello World"
                    }
                }
            }),
            serde_json::to_value(
                parse_request(
                    r#"{
                                 "sender_cid": "1",
                                 "message": "notify [2, Hello World]"
                                 }
                                 "#
                )
                .unwrap()
            )
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
            serde_json::to_value(
                parse_request(
                    r#"{
                                 "sender_cid": "1",
                                 "message": "upgrade [https://example.com 0x1111222233334444]"
                                 }
                                 "#
                )
                .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_response() {
        assert_eq!(
            Ok(Payload::NoPayload),
            parse_response(
                "{\"message\": \"accepted request\", \"status\": \"ok\"}",
                &VsockProtocol::V0
            )
        );
        assert_eq!(
            Err("Error response".to_string()),
            parse_response("Error response", &VsockProtocol::V0)
        );
        assert_eq!(
            Ok(Payload::NoPayload),
            parse_response("{\"Ok\":\"NoPayload\"}", &VsockProtocol::V1)
        );
        assert_eq!(
            Ok(Payload::HostOSVersion("123".to_string())),
            parse_response("{\"Ok\":{\"HostOSVersion\":\"123\"}}", &VsockProtocol::V1)
        );
        assert_eq!(
            Ok(Payload::HostOSVsockVersion(HostOSVsockVersion {
                major: 1,
                minor: 0,
                patch: 0,
            })),
            parse_response(
                "{\"Ok\":{\"HostOSVsockVersion\":{\"major\":1,\"minor\":0,\"patch\":0}}}",
                &VsockProtocol::V1
            )
        );
        assert_eq!(
            Err("Unable to parse host_v1 response: Error response".to_string()),
            parse_response("Error response", &VsockProtocol::V1)
        );
    }
}
