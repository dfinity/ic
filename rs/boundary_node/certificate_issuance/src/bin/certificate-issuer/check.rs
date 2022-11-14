use std::io::{BufRead, Cursor};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::Principal;
use hyper::{Body, Request, StatusCode};
use trust_dns_resolver::{error::ResolveErrorKind, proto::rr::RecordType};

use crate::{dns::Resolve, http::HttpClient};

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("missing dns cname record from {src} to {dst}")]
    MissingDnsCname { src: String, dst: String },

    #[error("missing dns txt record from {src} to a canister id")]
    MissingDnsTxtCanisterId { src: String },

    #[error("more than one dns txt record for canister id")]
    MultipleDnsTxtCanisterId { src: String },

    #[error("invalid dns txt record from {src} to {id}")]
    InvalidDnsTxtCanisterId { src: String, id: String },

    #[error("failed to retrieve known domains from canister {id}")]
    KnownDomainsUnavailable { id: String },

    #[error("domain is missing from canister {id} list of known domains")]
    MissingKnownDomains { id: String },

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Check: Send + Sync {
    async fn check(&self, domain: &str) -> Result<Principal, CheckError>;
}

pub struct Checker {
    // configuration
    delegation_domain: String,
    application_domain: String,

    // dependencies
    resolver: Box<dyn Resolve>,
    http_client: Box<dyn HttpClient>,
}

impl Checker {
    pub fn new(
        delegation_domain: String,
        application_domain: String,
        resolver: Box<dyn Resolve>,
        http_client: Box<dyn HttpClient>,
    ) -> Self {
        Self {
            delegation_domain,
            application_domain,
            resolver,
            http_client,
        }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, domain: &str) -> Result<Principal, CheckError> {
        // Phase 1 - Ensure a challenge delegation CNAME record exists
        let cname_src = format!("_acme-challenge.{}.", domain);
        let cname_dst = format!("_acme-challenge.{}.{}.", domain, self.delegation_domain);

        self.resolver
            .lookup(&cname_src, RecordType::CNAME)
            .await
            .map_err(|err| match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => CheckError::MissingDnsCname {
                    src: cname_src.to_owned(),
                    dst: cname_dst.to_owned(),
                },
                _ => CheckError::UnexpectedError(anyhow!("failed to resolve CNAME: {err}")),
            })
            .and_then(|rs| {
                if !rs.iter().any(|r| r.to_string().eq(&cname_dst)) {
                    return Err(CheckError::MissingDnsCname {
                        src: cname_src.to_owned(),
                        dst: cname_dst.to_owned(),
                    });
                }

                Ok(())
            })?;

        // Phase 2 - Ensure a TXT record for a canister mapping exists
        let txt_src = format!("_canister-id.{}.", domain);

        let canister_id = self
            .resolver
            .lookup(&txt_src, RecordType::TXT)
            .await
            .map_err(|err| match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => CheckError::MissingDnsTxtCanisterId {
                    src: txt_src.to_owned(),
                },
                _ => CheckError::UnexpectedError(anyhow!("failed to resolve TXT record: {err}")),
            })
            .and_then(|rs| {
                if rs.iter().count() > 1 {
                    return Err(CheckError::MultipleDnsTxtCanisterId {
                        src: txt_src.to_owned(),
                    });
                }

                let id = rs
                    .into_iter()
                    .next()
                    .ok_or(CheckError::MissingDnsTxtCanisterId {
                        src: txt_src.to_owned(),
                    })?
                    .to_string();

                // Ensure valid ID
                let id = Principal::from_text(id.clone()).map_err(|_| {
                    CheckError::InvalidDnsTxtCanisterId {
                        src: txt_src.to_owned(),
                        id: id.to_owned(),
                    }
                })?;

                Ok(id)
            })?;

        // Phase 3 - Query the canister to ensure it allows being accessed via the requested domain
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "https://{}.{}/.well-known/custom-domains",
                canister_id, self.application_domain,
            ))
            .body(Body::empty())
            .context("failed to create http reqest")?;

        let mut response = self
            .http_client
            .request(req)
            .await
            .context("failed to make http request")?;

        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => {
                return Err(CheckError::MissingKnownDomains {
                    id: canister_id.to_string(),
                });
            }
            _ => {
                return Err(CheckError::KnownDomainsUnavailable {
                    id: canister_id.to_string(),
                });
            }
        }

        let bs = hyper::body::to_bytes(response.body_mut())
            .await
            .context("failed to consume response")?
            .to_vec();

        let lns: Vec<String> = Cursor::new(bs)
            .lines()
            .into_iter()
            .filter_map(Result::ok)
            .collect();

        if !lns.iter().any(|ln| ln.as_str().eq(domain)) {
            return Err(CheckError::MissingKnownDomains {
                id: canister_id.to_string(),
            });
        }

        // Phase 4 (Optional) - Ensure a CNAME for the domain exists pointing it at a valid endpoint

        Ok(canister_id)
    }
}
