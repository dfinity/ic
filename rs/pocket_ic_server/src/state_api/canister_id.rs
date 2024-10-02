use crate::state_api::state::HandlerState;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use candid::Principal;
use fqdn::{fqdn, Fqdn, FQDN};
use hyper::{
    header::{HOST, REFERER},
    http::request::Parts,
    Uri,
};
use std::collections::BTreeMap;
use std::sync::Arc;

// ADAPTED from ic-gateway

/// Result of a domain lookup
#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct DomainLookup {
    pub domain: FQDN,
    pub canister_id: Option<Principal>,
    pub verify: bool,
}

// Resolves hostname to a canister id
pub(crate) trait ResolvesDomain: Send + Sync {
    fn resolve(&self, host: &Fqdn) -> Option<DomainLookup>;
}

#[derive(Clone)]
pub(crate) struct DomainResolver {
    domains_base: Vec<FQDN>,
    domains_all: BTreeMap<FQDN, DomainLookup>,
}

impl DomainResolver {
    pub(crate) fn new(domains_base: Vec<FQDN>) -> Self {
        fn domain(f: &Fqdn) -> FQDN {
            f.into()
        }

        let domains_base = domains_base
            .into_iter()
            .map(|x| domain(&x))
            .collect::<Vec<_>>();

        // Combine all domains
        let domains_all = domains_base.clone().into_iter().map(|x| {
            (
                x.clone(),
                DomainLookup {
                    domain: x,
                    canister_id: None,
                    verify: true,
                },
            )
        });

        Self {
            domains_all: domains_all.collect::<BTreeMap<_, _>>(),
            domains_base,
        }
    }

    // Tries to find the base domain that corresponds to the given host and resolve a canister id
    fn resolve_domain(&self, host: &Fqdn) -> Option<DomainLookup> {
        // First try to find an exact match
        // This covers base domains
        if let Some(v) = self.domains_all.get(host) {
            return Some(v.clone());
        }

        // Next we try to lookup dynamic subdomains like <canister>.ic0.app or <canister>.raw.ic0.app
        // Check if the host is a subdomain of any of our base domains.
        let domain = self
            .domains_base
            .iter()
            .find(|&x| host.is_subdomain_of(x))?;

        // Host can be 1 or 2 levels below base domain only: <id>.<domain> or <id>.raw.<domain>
        // Fail the lookup if it's deeper.
        let depth = host.labels().count() - domain.labels().count();
        if depth > 2 {
            return None;
        }

        // Check if it's a raw domain
        let raw = depth == 2;
        if raw && host.labels().nth(1) != Some("raw") {
            return None;
        }

        // Strip the optional prefix if any
        let label = host.labels().next()?.split("--").last()?;

        // Do not allow cases like <id>.foo.ic0.app where
        // the base subdomain is not raw or <id>.
        // TODO discuss
        let canister_id = if depth == 1 || raw {
            Principal::from_text(label).ok()
        } else {
            None
        };

        Some(DomainLookup {
            domain: domain.clone(),
            canister_id,
            verify: !raw,
        })
    }
}

impl ResolvesDomain for DomainResolver {
    fn resolve(&self, host: &Fqdn) -> Option<DomainLookup> {
        self.resolve_domain(host)
    }
}

// END ADAPTED from ic-gateway

// ADAPTED from icx-proxy

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct QueryParam(pub Principal);

#[async_trait]
impl FromRequestParts<Arc<HandlerState>> for QueryParam {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<HandlerState>,
    ) -> Result<Self, Self::Rejection> {
        FromRequestParts::from_request_parts(parts, state.resolver()).await
    }
}

#[async_trait]
impl FromRequestParts<DomainResolver> for QueryParam {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        _resolver: &DomainResolver,
    ) -> Result<Self, Self::Rejection> {
        const NO_PARAM: &str = "'canisterId' query parameter not found";
        const BAD_PARAM: &str = "'canisterId' failed to parse: Invalid Principal";

        let (_, canister_id) =
            form_urlencoded::parse(parts.uri.query().ok_or(NO_PARAM)?.as_bytes())
                .find(|(name, _)| name == "canisterId")
                .ok_or(NO_PARAM)?;

        Principal::from_text(canister_id.as_ref())
            .map(QueryParam)
            .map_err(|_| BAD_PARAM)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct HostHeader(pub Principal);

#[async_trait]
impl FromRequestParts<Arc<HandlerState>> for HostHeader {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<HandlerState>,
    ) -> Result<Self, Self::Rejection> {
        FromRequestParts::from_request_parts(parts, state.resolver()).await
    }
}

#[async_trait]
impl FromRequestParts<DomainResolver> for HostHeader {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        resolver: &DomainResolver,
    ) -> Result<Self, Self::Rejection> {
        const NO_HOST: &str = "No host in headers";
        const BAD_HOST: &str = "Host header did not contain a canister id or alias";

        let host = parts.headers.get(HOST).ok_or(NO_HOST)?;
        let host = host.to_str().map_err(|_| BAD_HOST)?;
        // Remove the port
        let host = host
            .rsplit_once(':')
            .map(|(host, _port)| host)
            .unwrap_or(host);
        resolver
            .resolve_domain(&fqdn!(host))
            .map(|d| d.canister_id)
            .ok_or(BAD_HOST)?
            .ok_or(BAD_HOST)
            .map(HostHeader)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct RefererHeaderHost(pub Principal);

#[async_trait]
impl FromRequestParts<Arc<HandlerState>> for RefererHeaderHost {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<HandlerState>,
    ) -> Result<Self, Self::Rejection> {
        FromRequestParts::from_request_parts(parts, state.resolver()).await
    }
}

#[async_trait]
impl FromRequestParts<DomainResolver> for RefererHeaderHost {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        resolver: &DomainResolver,
    ) -> Result<Self, Self::Rejection> {
        const NO_REFERER: &str = "No referer in headers";
        const BAD_REFERER: &str = "Referer header did not contain a canister id or alias";

        let referer = parts.headers.get(REFERER).ok_or(NO_REFERER)?;
        let referer = referer.to_str().map_err(|_| BAD_REFERER)?;
        let referer: Uri = referer.parse().map_err(|_| BAD_REFERER)?;
        let referer = referer.authority().ok_or(BAD_REFERER)?;
        resolver
            .resolve_domain(&fqdn!(referer.host()))
            .map(|d| d.canister_id)
            .ok_or(BAD_REFERER)?
            .ok_or(BAD_REFERER)
            .map(RefererHeaderHost)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct RefererHeaderQueryParam(pub Principal);

#[async_trait]
impl FromRequestParts<Arc<HandlerState>> for RefererHeaderQueryParam {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<HandlerState>,
    ) -> Result<Self, Self::Rejection> {
        FromRequestParts::from_request_parts(parts, state.resolver()).await
    }
}

#[async_trait]
impl FromRequestParts<DomainResolver> for RefererHeaderQueryParam {
    type Rejection = &'static str;

    async fn from_request_parts(
        parts: &mut Parts,
        _resolver: &DomainResolver,
    ) -> Result<Self, Self::Rejection> {
        const NO_REFERER: &str = "No referer in headers";
        const BAD_REFERER: &str = "Referer header did not contain a canister id or alias";
        const NO_PARAM: &str = "'canisterId' query parameter not found";
        const BAD_PARAM: &str = "'canisterId' failed to parse: Invalid Principal";

        let referer = parts.headers.get(REFERER).ok_or(NO_REFERER)?;
        let referer = referer.to_str().map_err(|_| BAD_REFERER)?;
        let referer: Uri = referer.parse().map_err(|_| BAD_REFERER)?;
        let (_, canister_id) = form_urlencoded::parse(referer.query().ok_or(NO_PARAM)?.as_bytes())
            .find(|(name, _)| name == "canisterId")
            .ok_or(NO_PARAM)?;

        Principal::from_text(canister_id.as_ref())
            .map(RefererHeaderQueryParam)
            .map_err(|_| BAD_PARAM)
    }
}

#[cfg(test)]
mod tests {
    use crate::state_api::canister_id::DomainResolver;
    use axum::extract::FromRequestParts;
    use fqdn::fqdn;
    use hyper::{header::HOST, http::request::Parts, Request};
    use ic_agent::export::Principal;
    use tokio::runtime::Runtime;

    use super::{HostHeader, QueryParam};

    #[test]
    fn simple_resolve() {
        let rt = Runtime::new().unwrap();
        let resolver = parse_config(vec!["little.domain.name"]);

        let mut req = build_req(
            Some("happy.little.domain.name"),
            "https://happy.little.domain.name/rrkah-fqaaa-aaaaa-aaaaq-cai",
        );
        assert!(rt
            .block_on(HostHeader::from_request_parts(&mut req, &resolver))
            .is_err());
        assert!(rt
            .block_on(QueryParam::from_request_parts(&mut req, &resolver))
            .is_err());

        let mut req = build_req(
            Some("rrkah-fqaaa-aaaaa-aaaaq-cai.little.domain.name"),
            "/r7inp-6aaaa-aaaaa-aaabq-cai",
        );
        assert_eq!(
            rt.block_on(HostHeader::from_request_parts(&mut req, &resolver)),
            Ok(HostHeader(principal("rrkah-fqaaa-aaaaa-aaaaq-cai")))
        );
        assert!(rt
            .block_on(QueryParam::from_request_parts(&mut req, &resolver))
            .is_err());
    }

    #[test]
    fn dfx() {
        let rt = Runtime::new().unwrap();
        let resolver = parse_config(vec!["localhost"]);

        let mut req = build_req(Some("rrkah-fqaaa-aaaaa-aaaaq-cai.localhost"), "/about");
        assert_eq!(
            rt.block_on(HostHeader::from_request_parts(&mut req, &resolver)),
            Ok(HostHeader(principal("rrkah-fqaaa-aaaaa-aaaaq-cai")))
        );
        assert!(rt
            .block_on(QueryParam::from_request_parts(&mut req, &resolver))
            .is_err());

        let mut req = build_req(
            Some("localhost"),
            "/about?canisterId=rrkah-fqaaa-aaaaa-aaaaq-cai",
        );
        assert!(rt
            .block_on(HostHeader::from_request_parts(&mut req, &resolver))
            .is_err());
        assert_eq!(
            rt.block_on(QueryParam::from_request_parts(&mut req, &resolver)),
            Ok(QueryParam(principal("rrkah-fqaaa-aaaaa-aaaaq-cai")))
        );
    }

    fn parse_config(suffixes: Vec<&str>) -> DomainResolver {
        DomainResolver::new(suffixes.into_iter().map(|s| fqdn!(s)).collect())
    }

    fn build_req(host: Option<&str>, uri: &str) -> Parts {
        let req = Request::builder().uri(uri);
        if let Some(host) = host {
            req.header(HOST, host)
        } else {
            req
        }
        .body(())
        .unwrap()
        .into_parts()
        .0
    }

    fn principal(v: &str) -> Principal {
        Principal::from_text(v).unwrap()
    }
}

// END ADAPTED from icx-proxy
