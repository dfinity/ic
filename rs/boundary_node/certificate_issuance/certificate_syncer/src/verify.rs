use anyhow::Context;
use mockall::automock;
use x509_parser::pem::parse_x509_pem;

use crate::import::Package;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),

    #[error("missing common name")]
    MissingCommonName,

    #[error("expected 1 common name, found {0}")]
    TooManyCommonNames(usize),
}

#[automock]
pub trait Parse: Sync + Send {
    fn parse(&self, data: &[u8]) -> Result<String, ParseError>;
}

pub struct Parser;

impl Parse for Parser {
    fn parse(&self, data: &[u8]) -> Result<String, ParseError> {
        let (_, pem) = parse_x509_pem(data).context("failed to parse pem")?;
        let cert = pem.parse_x509().context("failed to parse x509")?;

        let cns: Vec<String> = cert
            .subject()
            .iter_common_name()
            .filter_map(|cn| cn.as_str().ok().map(|s| s.to_string()))
            .collect();

        if cns.is_empty() {
            return Err(ParseError::MissingCommonName);
        }
        if cns.len() > 1 {
            return Err(ParseError::TooManyCommonNames(cns.len()));
        }

        Ok(cns[0].to_owned())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),

    #[error("invalid domain name: '{0}'")]
    InvalidDomainName(String),

    #[error("package failed verification, name '{0}' mismatched common name '{1}'")]
    CommonNameMismatch(String, String),
}

#[automock]
pub trait Verify: Sync + Send {
    fn verify(&self, pkg: &Package) -> Result<(), VerifyError>;
}

pub struct Verifier<P>(pub P);

impl<P: Parse> Verify for Verifier<P> {
    fn verify(&self, pkg: &Package) -> Result<(), VerifyError> {
        if !pkg
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
        {
            return Err(VerifyError::InvalidDomainName(pkg.name.to_owned()));
        }

        // Parse common name from public certificate
        let cn = self
            .0
            .parse(&pkg.pair.1)
            .context("failed to parse certificate")?;

        // Check that name and common-name match
        if pkg.name != cn {
            return Err(VerifyError::CommonNameMismatch(pkg.name.to_owned(), cn));
        }

        Ok(())
    }
}

pub struct WithVerify<T, V>(pub T, pub V);

#[cfg(test)]
mod tests {
    use candid::Principal;

    use crate::import::{Package, Pair};

    use super::{MockParse, Verifier, Verify, VerifyError};

    #[test]
    fn verify_ok() {
        let mut parser = MockParse::new();
        parser
            .expect_parse()
            .times(1)
            .returning(|_| Ok("name-0.com".into()));

        let verifier = Verifier(parser);

        let out = verifier.verify(&Package {
            name: "name-0.com".into(),
            canister: Principal::from_text("aaaaa-aa").unwrap(),
            pair: Pair(vec![], vec![]),
        });

        match out {
            Ok(()) => {}
            other => panic!("expected Ok but got {other:?}"),
        }
    }

    #[test]
    fn verify_mismatch() {
        let mut parser = MockParse::new();
        parser
            .expect_parse()
            .times(1)
            .returning(|_| Ok("name-2".into()));

        let verifier = Verifier(parser);

        let out = verifier.verify(&Package {
            name: "name-1".into(),
            canister: Principal::from_text("aaaaa-aa").unwrap(),
            pair: Pair(vec![], vec![]),
        });

        match out {
            Err(VerifyError::CommonNameMismatch(name, cn)) => {
                assert_eq!((name, cn), ("name-1".into(), "name-2".into()),);
            }
            other => panic!("expected CommonNameMismatch but got {other:?}"),
        }
    }

    #[test]
    fn verify_bad_domain() {
        let verifier = Verifier(MockParse::new());

        let out = verifier.verify(&Package {
            name: "bad_character".into(),
            canister: Principal::from_text("aaaaa-aa").unwrap(),
            pair: Pair(vec![], vec![]),
        });

        match out {
            Err(VerifyError::InvalidDomainName(name)) => {
                assert_eq!(name, String::from("bad_character"));
            }
            other => panic!("expected InvalidDomainName but got {other:?}"),
        }
    }
}
