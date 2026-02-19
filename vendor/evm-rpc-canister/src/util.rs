use serde_json::Value;
use url::Host;

pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.starts_with("0x") {
        return None;
    }
    hex::decode(&hex[2..]).ok()
}

pub fn canonicalize_json(text: &[u8]) -> Option<Vec<u8>> {
    let json = serde_json::from_slice::<Value>(text).ok()?;
    serde_json::to_vec(&json).ok()
}

pub fn hostname_from_url(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|url| match url.host() {
        Some(Host::Domain(domain)) => {
            if !domain.contains(['{', '}']) {
                Some(domain.to_string())
            } else {
                None
            }
        }
        _ => None,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("aa"), None);
        assert_eq!(hex_to_bytes("0x"), Some(vec![]));
        assert_eq!(hex_to_bytes("0xAA"), Some(vec![0xAA]));
        assert_eq!(hex_to_bytes("0xaa"), Some(vec![0xAA]));
    }

    #[test]
    fn test_canonicalize_json() {
        assert_eq!(
            canonicalize_json(r#"{"A":1,"B":2}"#.as_bytes()).unwrap(),
            canonicalize_json(r#"{"B":2,"A":1}"#.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_hostname_from_url() {
        assert_eq!(
            hostname_from_url("https://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            hostname_from_url("https://example.com?k=v"),
            Some("example.com".to_string())
        );
        assert_eq!(
            hostname_from_url("https://example.com/{API_KEY}"),
            Some("example.com".to_string())
        );
        assert_eq!(
            hostname_from_url("https://example.com/path/{API_KEY}"),
            Some("example.com".to_string())
        );
        assert_eq!(
            hostname_from_url("https://example.com/path/{API_KEY}?k=v"),
            Some("example.com".to_string())
        );
        assert_eq!(hostname_from_url("https://{API_KEY}"), None);
        assert_eq!(hostname_from_url("https://{API_KEY}/path/"), None);
        assert_eq!(hostname_from_url("https://{API_KEY}.com"), None);
        assert_eq!(hostname_from_url("https://{API_KEY}.com/path/"), None);
        assert_eq!(hostname_from_url("https://example.{API_KEY}"), None);
        assert_eq!(hostname_from_url("https://example.{API_KEY}/path/"), None);
    }
}
