use std::net::SocketAddr;

use anyhow::{bail, Error};
use hyper::{
    http::uri::{PathAndQuery, Scheme},
    Uri,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainAddr {
    pub domain: Uri,
    pub addr: Option<SocketAddr>,
}

pub fn parse_domain_addr(value: &str) -> Result<DomainAddr, Error> {
    let mut value = match value.find('|') {
        None => DomainAddr {
            domain: value.parse()?,
            addr: None,
        },

        Some(0) => {
            bail!("domain-addr mapping missing domain '{value}'")
        }

        Some(index) => {
            let (domain, addr) = value.split_at(index);
            let addr = &addr[1..];

            DomainAddr {
                domain: domain.parse()?,
                addr: if !addr.is_empty() {
                    Some(addr.parse()?)
                } else {
                    None
                },
            }
        }
    };
    // Default to https
    if value.domain.scheme().is_none() {
        let mut domain = value.domain.into_parts();
        domain.scheme = Some(Scheme::HTTPS);
        domain.path_and_query = Some(
            domain
                .path_and_query
                .unwrap_or_else(|| PathAndQuery::from_static("")),
        );
        value.domain = Uri::from_parts(domain)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use crate::domain_addr::{parse_domain_addr, DomainAddr};
    use hyper::Uri;

    #[test]
    fn parse_domain_addr_fail() {
        let test_cases = &[
            "",    // invalid mapping
            "|",   // missing domain and addr
            "|b",  // missing domain
            "a|b", // invalid addr
        ];

        for tc in test_cases {
            let output = parse_domain_addr(tc);
            assert!(output.is_err());
        }
    }

    #[test]
    fn parse_domain_addr_ok() {
        struct TestCase {
            input: String,
            output: DomainAddr,
        }

        let test_cases = &[
            TestCase {
                input: String::from("http://a|127.0.0.1:80"),
                output: DomainAddr {
                    domain: Uri::from_static("http://a"),
                    addr: Some("127.0.0.1:80".parse().unwrap()),
                },
            },
            TestCase {
                input: String::from("a|"),
                output: DomainAddr {
                    domain: Uri::from_static("https://a"),
                    addr: None,
                },
            },
        ];

        for tc in test_cases {
            let output = parse_domain_addr(&tc.input);
            assert_eq!(output.unwrap(), tc.output);
        }
    }
}
