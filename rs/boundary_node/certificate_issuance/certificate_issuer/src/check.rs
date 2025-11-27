use anyhow::anyhow;
use async_trait::async_trait;
use candid::Principal;
use flate2::bufread::GzDecoder;
use ic_agent::Agent;
use ic_http_certification::{HttpRequest, HttpResponse};
use ic_response_verification::{MIN_VERIFICATION_VERSION, verify_request_response_pair};
use ic_utils::{
    call::SyncCall,
    interfaces::http_request::{HeaderField, HttpRequestCanister},
};
use mockall::automock;
use std::{
    io::{BufRead, Read},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use trust_dns_resolver::{error::ResolveErrorKind, proto::rr::RecordType};

use crate::dns::Resolve;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("existing dns txt challenge record at {src}")]
    ExistingDnsTxtChallenge { src: String },

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

#[automock]
#[async_trait]
pub trait Check: Send + Sync {
    async fn check(&self, name: &str) -> Result<Principal, CheckError>;
}

pub struct Checker {
    // configuration
    delegation_domain: String,

    // dependencies
    resolver: Box<dyn Resolve>,

    // agent
    agent: Arc<Agent>,
}

impl Checker {
    pub fn new(delegation_domain: String, resolver: Box<dyn Resolve>, agent: Arc<Agent>) -> Self {
        Self {
            delegation_domain,
            resolver,
            agent,
        }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, name: &str) -> Result<Principal, CheckError> {
        // Phase 1 - Ensure NO existing TXT challenge record exists
        let txt_src = format!("_acme-challenge.{name}.");

        match self.resolver.lookup(&txt_src, RecordType::TXT).await {
            Ok(lookup) => {
                // If there's no TXT, resolver can also follow a CNAME.
                if lookup.record_iter().any(|rec| {
                    !rec.name()
                        .to_string()
                        .trim_end_matches('.')
                        .ends_with(&self.delegation_domain.trim_end_matches('.'))
                }) {
                    // There's an existing challenge response. Return error.
                    Err(CheckError::ExistingDnsTxtChallenge {
                        src: txt_src.to_owned(),
                    })
                } else {
                    // There's no challenge response, but the resolver followed the CNAME and we have a challenge response under our domain.
                    // This is ok, as we will just overwrite this record later.
                    Ok(())
                }
            }
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => Ok(()),
                _ => Err(CheckError::UnexpectedError(anyhow!(
                    "failed to resolve TXT: {err}"
                ))),
            },
        }?;

        // Phase 2 - Ensure a challenge delegation CNAME record exists
        let cname_src = format!("_acme-challenge.{name}.");
        let cname_dst = format!("_acme-challenge.{}.{}.", name, self.delegation_domain);

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

        // Phase 3 - Ensure a TXT record for a canister mapping exists
        let txt_src = format!("_canister-id.{name}.");

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

        // Phase 4 - Ensure canister mentions known domain.
        let request = HttpRequest::get("/.well-known/ic-domains").build();

        let (response,) = HttpRequestCanister::create(&self.agent, canister_id)
            .http_request(&request.method(), &request.url(), vec![], vec![], None)
            .call()
            .await
            .map_err(|_| CheckError::KnownDomainsUnavailable {
                id: canister_id.to_string(),
            })?;

        match response.status_code {
            200 => Ok(()),
            404 => Err(CheckError::MissingKnownDomains {
                id: canister_id.to_string(),
            }),
            _ => Err(CheckError::KnownDomainsUnavailable {
                id: canister_id.to_string(),
            }),
        }?;

        // Check response certification
        let response_for_verification = HttpResponse::ok(
            // body
            response.body.clone(),
            // headers
            response
                .headers
                .iter()
                .map(|field| (field.0.to_string(), field.1.to_string()))
                .collect::<Vec<(String, String)>>(),
        )
        .with_upgrade(response.upgrade.unwrap_or_default())
        .build();
        let max_cert_time_offset_ns = 300_000_000_000;
        let current_time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();
        let ic_public_key = &self.agent.read_root_key();
        verify_request_response_pair(
            request,
            response_for_verification,
            canister_id.as_slice(),
            current_time_ns,
            max_cert_time_offset_ns,
            ic_public_key,
            MIN_VERIFICATION_VERSION,
        )
        .map_err(|_| CheckError::KnownDomainsUnavailable {
            id: canister_id.to_string(),
        })?;

        // Decode body
        let enc = response
            .headers
            .iter()
            .find(|HeaderField(name, _)| name == "Content-Encoding")
            .map(|HeaderField(_, value)| value.as_ref());

        let body = match enc {
            // Identity
            None | Some("identity") => Ok(response.body),

            // Gzip
            Some("gzip") => {
                let mut buf = Vec::new();
                GzDecoder::new(response.body.as_ref())
                    .read_to_end(&mut buf)
                    .map_err(|err| {
                        CheckError::UnexpectedError(anyhow!(
                            "failed to decode gzipped response body: {err}"
                        ))
                    })?;
                Ok(buf)
            }

            // Other
            Some(enc) => Err(anyhow!("unsupported content-encoding: {}", enc)),
        }?;

        // Search for name in response body
        if !body.lines().any(|ln| match ln {
            Ok(ln) => ln.trim().eq(name),
            _ => false,
        }) {
            return Err(CheckError::MissingKnownDomains {
                id: canister_id.to_string(),
            });
        }

        Ok(canister_id)
    }
}
