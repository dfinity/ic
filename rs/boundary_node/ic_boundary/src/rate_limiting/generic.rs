use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Error};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Extension, State},
    http::Request,
    middleware::Next,
    response::IntoResponse,
};
use candid::Principal;
use ic_canister_client::Agent;
use ic_types::CanisterId;
use rate_limits_api::v1::{Action, RateLimitRule, RequestType as RequestTypeRule};
use ratelimit::Ratelimiter;
use tracing::warn;

use super::fetcher::{
    CanisterConfigFetcherQuery, CanisterConfigFetcherUpdate, CanisterFetcher, FetchesConfig,
    FetchesRules, FileFetcher,
};

use crate::{
    core::Run,
    persist::RouteSubnet,
    routes::{ErrorCause, RateLimitCause, RequestContext, RequestType},
};

// Converts between different request types
// We can't use a single one because Ratelimit API crate needs to build on WASM and ic-bn-lib does not
fn convert_request_type(rt: RequestType) -> RequestTypeRule {
    match rt {
        RequestType::Query => RequestTypeRule::Query,
        RequestType::Call => RequestTypeRule::Call,
        RequestType::SyncCall => RequestTypeRule::SyncCall,
        RequestType::ReadState => RequestTypeRule::ReadState,
        RequestType::ReadStateSubnet => RequestTypeRule::ReadStateSubnet,
        _ => RequestTypeRule::Unknown,
    }
}

struct Bucket {
    rule: RateLimitRule,
    limiter: Option<Ratelimiter>,
}

impl PartialEq for Bucket {
    fn eq(&self, other: &Self) -> bool {
        self.rule == other.rule
    }
}
impl Eq for Bucket {}

pub struct Limiter {
    fetcher: Arc<dyn FetchesRules>,
    buckets: ArcSwap<Vec<Bucket>>,
}

impl Limiter {
    pub fn new_from_file(path: PathBuf) -> Self {
        let fetcher = Arc::new(FileFetcher(path));
        Self::new_with_fetcher(fetcher)
    }

    pub fn new_from_canister_query(canister_id: CanisterId, agent: Agent) -> Self {
        let config_fetcher = CanisterConfigFetcherQuery(agent, canister_id);
        Self::new_with_config_fetcher(Arc::new(config_fetcher))
    }

    pub fn new_from_canister_update(canister_id: CanisterId, agent: Agent) -> Self {
        let config_fetcher = CanisterConfigFetcherUpdate(agent, canister_id);
        Self::new_with_config_fetcher(Arc::new(config_fetcher))
    }

    fn new_with_config_fetcher(config_fetcher: Arc<dyn FetchesConfig>) -> Self {
        let fetcher = Arc::new(CanisterFetcher(config_fetcher));
        Self::new_with_fetcher(fetcher)
    }

    fn new_with_fetcher(fetcher: Arc<dyn FetchesRules>) -> Self {
        Self {
            fetcher,
            buckets: ArcSwap::new(Arc::new(vec![])),
        }
    }

    fn process_rules(rules: Vec<RateLimitRule>) -> Vec<Bucket> {
        rules
            .into_iter()
            .map(|rule| {
                let limiter = if let Action::Limit(limit, duration) = rule.limit {
                    Some(
                        Ratelimiter::builder(
                            1,
                            duration.checked_div(limit).unwrap_or(Duration::ZERO),
                        )
                        .max_tokens(limit as u64)
                        .initial_available(limit as u64)
                        .build()
                        .unwrap(),
                    )
                } else {
                    None
                };

                Bucket { rule, limiter }
            })
            .collect()
    }

    fn apply_rules(&self, rules: Vec<RateLimitRule>) -> bool {
        let new = Arc::new(Self::process_rules(rules));
        let old = self.buckets.load_full();

        if old != new {
            warn!("GenericLimiter: ruleset updated: {} rules", new.len());

            for b in new.as_ref() {
                warn!(
                    "GenericLimiter: subnet: {:?}, canister: {:?}, methods: {:?}, action: {:?}",
                    b.rule.subnet_id, b.rule.canister_id, b.rule.methods_regex, b.rule.limit,
                );
            }

            self.buckets.store(new);
            return true;
        }

        false
    }

    async fn refresh(&self) -> Result<(), Error> {
        let rules = self
            .fetcher
            .fetch_rules()
            .await
            .context("unable to fetch rules")?;

        self.apply_rules(rules);
        Ok(())
    }

    fn acquire_token(
        &self,
        subnet_id: Principal,
        canister_id: Option<Principal>,
        method: Option<&str>,
        request_type: RequestType,
    ) -> bool {
        for b in self.buckets.load_full().as_ref() {
            if let Some(v) = b.rule.subnet_id {
                if subnet_id != v {
                    continue;
                }
            }

            if let Some(v) = b.rule.canister_id {
                if let Some(x) = canister_id {
                    if x != v {
                        continue;
                    }
                }
            }

            if let Some(v) = &b.rule.request_types {
                if !v.contains(&convert_request_type(request_type)) {
                    continue;
                }
            }

            if let Some(rgx) = &b.rule.methods_regex {
                if let Some(v) = method {
                    if !rgx.is_match(v) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if let Some(r) = &b.limiter {
                return r.try_wait().is_ok();
            }

            // Always block
            return false;
        }

        // No rules / no match -> pass
        true
    }
}

#[async_trait]
impl Run for Arc<Limiter> {
    async fn run(&mut self) -> Result<(), Error> {
        if let Err(e) = self.refresh().await {
            warn!("Ratelimiter: unable to refresh: {e:#}");
        }
        Ok(())
    }
}

pub async fn middleware(
    State(state): State<Arc<Limiter>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet): Extension<Arc<RouteSubnet>>,
    canister_id: Option<Extension<CanisterId>>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    if !state.acquire_token(
        subnet.id,
        canister_id.map(|x| x.0.get().into()),
        ctx.method_name.as_deref(),
        ctx.request_type,
    ) {
        return Err(ErrorCause::RateLimited(RateLimitCause::Generic));
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod test {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_ratelimit() {
        let rules = indoc! {"
        - subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
          canister_id: aaaaa-aa
          methods_regex: ^.*$
          limit: 10/1h

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods_regex: ^(foo|bar)$
          limit: 20/1h

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods_regex: ^baz$
          limit: block

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          request_types: [call]
          limit: 10/1h

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          limit: 20/1h
        "};
        let rules: Vec<RateLimitRule> = serde_yaml::from_str(rules).unwrap();

        let limiter = Limiter::new_from_file("/tmp/foo".into());
        limiter.apply_rules(rules);

        let id1 = Principal::from_text("aaaaa-aa").unwrap();
        let id2 = Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap();
        let id3 = Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap();
        let subnet_id =
            Principal::from_text("3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe")
                .unwrap();
        let subnet_id2 =
            Principal::from_text("6pbhf-qzpdk-kuqbr-pklfa-5ehhf-jfjps-zsj6q-57nrl-kzhpd-mu7hc-vae")
                .unwrap();

        // Check id1 blocking with any method
        // 10 pass
        for _ in 0..10 {
            assert!(limiter.acquire_token(subnet_id, Some(id1), Some("foo"), RequestType::Query));
        }
        // then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(subnet_id, Some(id1), Some("bar"), RequestType::Query));
        }

        // Check id2 blocking with two methods
        // 20 pass
        // Another subnet_id which shouldn't have any difference
        for _ in 0..20 {
            assert!(limiter.acquire_token(subnet_id2, Some(id2), Some("foo"), RequestType::Query));
        }
        // Then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(subnet_id2, Some(id2), Some("bar"), RequestType::Query));
        }
        // Other methods should not block ever
        for _ in 0..100 {
            assert!(limiter.acquire_token(subnet_id2, Some(id2), Some("lol"), RequestType::Query));
        }
        for _ in 0..100 {
            assert!(limiter.acquire_token(subnet_id2, Some(id2), Some("rofl"), RequestType::Query));
        }

        // This method should be blocked always
        for _ in 0..100 {
            assert!(!limiter.acquire_token(subnet_id, Some(id2), Some("baz"), RequestType::Query));
        }

        // Check id3 blocking with any method and request type call
        // 10 pass
        for _ in 0..10 {
            assert!(limiter.acquire_token(subnet_id, Some(id3), Some("foo"), RequestType::Call));
        }
        // then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(subnet_id, Some(id3), Some("bar"), RequestType::Call));
        }

        // Then check id3 blocking with any method and request type query
        // 20 pass
        for _ in 0..20 {
            assert!(limiter.acquire_token(subnet_id, Some(id3), Some("baz"), RequestType::Query));
        }
        // then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(subnet_id, Some(id3), Some("zob"), RequestType::Query));
        }
    }
}
