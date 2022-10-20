use std::net::SocketAddr;

use anyhow::{bail, Error};

#[derive(Clone, Debug, PartialEq)]
pub struct DomainAddr {
    pub domain: String,
    pub addr: SocketAddr,
}

pub fn parse_domain_addr(value: &str) -> Result<DomainAddr, Error> {
    match value.find('=') {
        None => {
            bail!("invalid domain-addr mapping '{value}'")
        }

        Some(0) => {
            bail!("domain-addr mapping missing domain '{value}'")
        }

        Some(index) if index == value.len() - 1 => {
            bail!("domain-addr mapping missing addr '{value}'")
        }

        Some(index) => {
            let (domain, addr) = value.split_at(index);

            let domain = domain.to_string();
            let addr: SocketAddr = addr[1..].parse()?;

            Ok(DomainAddr { domain, addr })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain_addr::{parse_domain_addr, DomainAddr};

    #[test]
    fn parse_domain_addr_fail() {
        let test_cases = &[
            "",    // invalid mapping
            "=",   // missing domain and addr
            "a=",  // missing addr
            "=b",  // missing domain
            "a=b", // invalid addr
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

        let test_cases = &[TestCase {
            input: String::from("a=127.0.0.1:80"),
            output: DomainAddr {
                domain: String::from("a"),
                addr: "127.0.0.1:80".parse().unwrap(),
            },
        }];

        for tc in test_cases {
            let output = parse_domain_addr(&tc.input);
            assert_eq!(output.unwrap(), tc.output);
        }
    }
}
