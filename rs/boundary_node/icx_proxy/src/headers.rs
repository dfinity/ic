use ic_utils::interfaces::http_request::HeaderField;
use lazy_regex::regex_captures;
use tracing::{trace, warn};

const MAX_LOG_CERT_NAME_SIZE: usize = 100;
const MAX_LOG_CERT_B64_SIZE: usize = 2000;

#[derive(Debug, PartialEq)]
pub struct HeadersData {
    pub certificate: Option<Result<Vec<u8>, ()>>,
    pub tree: Option<Result<Vec<u8>, ()>>,
    pub encoding: Option<String>,
}

const IC_CERTIFICATE_HEADER_NAME: &str = "Ic-Certificate";

pub fn extract_headers_data(headers: &[HeaderField]) -> HeadersData {
    let mut headers_data = HeadersData {
        certificate: None,
        tree: None,
        encoding: None,
    };

    for HeaderField(name, value) in headers {
        if name.eq_ignore_ascii_case(IC_CERTIFICATE_HEADER_NAME) {
            for field in value.split(',') {
                if let Some((_, name, b64_value)) = regex_captures!("^(.*)=:(.*):$", field.trim()) {
                    trace!(
                        ">> certificate {:.l1$}: {:.l2$}",
                        name,
                        b64_value,
                        l1 = MAX_LOG_CERT_NAME_SIZE,
                        l2 = MAX_LOG_CERT_B64_SIZE
                    );
                    let bytes = decode_hash_tree(name, Some(b64_value.to_string()));
                    if name == "certificate" {
                        headers_data.certificate = Some(match (headers_data.certificate, bytes) {
                            (None, bytes) => bytes,
                            (Some(Ok(certificate)), Ok(bytes)) => {
                                warn!("duplicate certificate field: {:?}", bytes);
                                Ok(certificate)
                            }
                            (Some(Ok(certificate)), Err(_)) => {
                                warn!("duplicate certificate field (failed to decode)");
                                Ok(certificate)
                            }
                            (Some(Err(_)), bytes) => {
                                warn!("duplicate certificate field (failed to decode)");
                                bytes
                            }
                        });
                    } else if name == "tree" {
                        headers_data.tree = Some(match (headers_data.tree, bytes) {
                            (None, bytes) => bytes,
                            (Some(Ok(tree)), Ok(bytes)) => {
                                warn!("duplicate tree field: {:?}", bytes);
                                Ok(tree)
                            }
                            (Some(Ok(tree)), Err(_)) => {
                                warn!("duplicate tree field (failed to decode)");
                                Ok(tree)
                            }
                            (Some(Err(_)), bytes) => {
                                warn!("duplicate tree field (failed to decode)");
                                bytes
                            }
                        });
                    }
                }
            }
        } else if name.eq_ignore_ascii_case("Content-Encoding") {
            let enc = value.trim().to_string();
            headers_data.encoding = Some(enc);
        }
    }

    headers_data
}

fn decode_hash_tree(name: &str, value: Option<String>) -> Result<Vec<u8>, ()> {
    match value {
        Some(tree) => base64::decode(&tree).map_err(|e| {
            warn!("Unable to decode {} from base64: {}", name, e);
        }),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use ic_utils::interfaces::http_request::HeaderField;

    use super::{extract_headers_data, HeadersData};

    #[test]
    fn extract_headers_data_simple() {
        let headers: Vec<HeaderField> = vec![];

        let out = extract_headers_data(&headers);

        assert_eq!(
            out,
            HeadersData {
                certificate: None,
                tree: None,
                encoding: None,
            }
        );
    }

    #[test]
    fn extract_headers_data_content_encoding() {
        let headers: Vec<HeaderField> = vec![HeaderField("Content-Encoding".into(), "test".into())];

        let out = extract_headers_data(&headers);

        assert_eq!(
            out,
            HeadersData {
                certificate: None,
                tree: None,
                encoding: Some(String::from("test")),
            }
        );
    }
}
