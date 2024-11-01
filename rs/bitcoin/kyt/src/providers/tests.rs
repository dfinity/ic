use super::*;

#[test]
fn test_parse_authorization_header_from_url() {
    let result = parse_authorization_header_from_url("http://localhost:3030");
    assert!(matches!(result, Err(err) if err.contains("Missing username")));

    let result = parse_authorization_header_from_url("http://guest@localhost:3030");
    assert!(matches!(result, Err(err) if err.contains("Missing password")));

    let result = parse_authorization_header_from_url("http://guest:pass@localhost:3030");
    assert!(result.is_ok());
    let (url, header) = result.unwrap();
    assert_eq!(url.to_string(), "http://localhost:3030/");
    assert_eq!(
        header.value,
        format!("Basic {}", base64::encode("guest:pass"))
    );

    // The following would have failed if there was no url_decode
    let result = parse_authorization_header_from_url("http://guest:pa=ss@localhost:3030");
    assert!(result.is_ok());
    let (url, header) = result.unwrap();
    assert_eq!(url.to_string(), "http://localhost:3030/");
    assert_eq!(
        header.value,
        format!("Basic {}", base64::encode("guest:pa=ss"))
    );
}
