use anyhow::anyhow;
use async_trait::async_trait;
use candid::Principal;
use ic_agent::Agent;
use ic_utils::{
    call::SyncCall,
    interfaces::http_request::{HttpRequestCanister, HttpResponse},
};
use mockall::automock;
use std::sync::Arc;
use trust_dns_resolver::{error::ResolveErrorKind, proto::rr::RecordType};

use crate::dns::Resolve;

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

fn has_well_known_file(response: &HttpResponse) -> bool {
    if response.body.is_empty() {
        return false;
    }

    let response_body = String::from_utf8(response.body.clone()).unwrap();

    let first_line = response_body.lines().next().unwrap();

    let first_char = first_line.chars().next().unwrap();

    !matches!(first_char, '<' | '{')
}

fn file_contents(response: &HttpResponse) -> Vec<String> {
    let mut file_contents = Vec::new();

    for line in String::from_utf8(response.body.clone()).unwrap().lines() {
        file_contents.push(line.to_string());
    }

    file_contents
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, name: &str) -> Result<Principal, CheckError> {
        // Phase 1 - Ensure a challenge delegation CNAME record exists
        let cname_src = format!("_acme-challenge.{}.", name);
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

        // Phase 2 - Ensure a TXT record for a canister mapping exists
        let txt_src = format!("_canister-id.{}.", name);

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

        let canister = HttpRequestCanister::create(self.agent.as_ref(), canister_id);
        let (response,) = canister
            .http_request("GET", "/.well-known/ic-domains", vec![], vec![])
            .call()
            .await
            .unwrap();

        match response.status_code {
            200 => {}
            404 => {
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

        if !has_well_known_file(&response) {
            return Err(CheckError::MissingKnownDomains {
                id: canister_id.to_string(),
            });
        }

        let lns = file_contents(&response).to_vec();

        if !lns.iter().any(|ln| ln.as_str().eq(name)) {
            return Err(CheckError::MissingKnownDomains {
                id: canister_id.to_string(),
            });
        }

        // Phase 4 (Optional) - Ensure a CNAME for the domain exists pointing it at a valid endpoint

        Ok(canister_id)
    }
}
