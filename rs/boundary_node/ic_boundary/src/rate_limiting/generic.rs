use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Error};
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
use ic_bn_lib::http::ConnInfo;
use ic_canister_client::Agent;
use ic_types::CanisterId;
use ipnet::IpNet;
use rate_limits_api::v1::{Action, IpPrefixes, RateLimitRule, RequestType as RequestTypeRule};
use ratelimit::Ratelimiter;
use tracing::warn;

use super::{
    fetcher::{
        CanisterConfigFetcherQuery, CanisterConfigFetcherUpdate, CanisterFetcher, FetchesConfig,
        FetchesRules, FileFetcher,
    },
    sharded::ShardedRatelimiter,
};

use crate::{
    core::{Run, HOUR},
    persist::RouteSubnet,
    routes::{ErrorCause, RateLimitCause, RequestContext, RequestType},
};

pub fn create_ratelimiter(limit: u32, duration: Duration) -> Ratelimiter {
    Ratelimiter::builder(1, duration.checked_div(limit).unwrap_or(Duration::ZERO))
        .max_tokens(limit as u64)
        .initial_available(limit as u64)
        .build()
        .unwrap()
}

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

pub struct Context<'a> {
    subnet_id: Principal,
    canister_id: Option<Principal>,
    method: Option<&'a str>,
    request_type: RequestType,
    ip: IpAddr,
}

#[derive(Clone)]
enum Limiter {
    Single(Arc<Ratelimiter>),
    Sharded(Arc<ShardedRatelimiter<IpNet>>, IpPrefixes),
}

#[derive(Clone)]
struct Bucket {
    rule: RateLimitRule,
    limiter: Option<Limiter>,
}

impl PartialEq for Bucket {
    fn eq(&self, other: &Self) -> bool {
        self.rule == other.rule
    }
}
impl Eq for Bucket {}

impl Bucket {
    fn is_allowed(&self, ctx: &Context) -> Option<bool> {
        if let Some(v) = self.rule.subnet_id {
            if ctx.subnet_id != v {
                return None;
            }
        }

        if let Some(v) = self.rule.canister_id {
            if let Some(x) = ctx.canister_id {
                if x != v {
                    return None;
                }
            }
        }

        if let Some(v) = &self.rule.request_types {
            if !v.contains(&convert_request_type(ctx.request_type)) {
                return None;
            }
        }

        if let Some(rgx) = &self.rule.methods_regex {
            if let Some(v) = ctx.method {
                if !rgx.is_match(v) {
                    return None;
                }
            } else {
                return None;
            }
        }

        if let Some(v) = self.rule.ip {
            if !v.contains(&ctx.ip) {
                return None;
            }
        }

        if self.rule.limit == Action::Pass {
            return Some(true);
        } else if self.rule.limit == Action::Block {
            return Some(false);
        }

        if let Some(v) = &self.limiter {
            return Some(match v {
                Limiter::Single(v) => v.try_wait().is_ok(),
                Limiter::Sharded(v, prefix) => {
                    let prefix = match ctx.ip {
                        IpAddr::V4(_) => prefix.v4,
                        IpAddr::V6(_) => prefix.v6,
                    };

                    // We assume that the prefix is correct, assert is safe
                    let net = IpNet::new_assert(ctx.ip, prefix);
                    v.acquire(net, Instant::now())
                }
            });
        }

        // Should never get here
        unreachable!();
    }
}

pub struct GenericLimiter {
    fetcher: Arc<dyn FetchesRules>,
    buckets: ArcSwap<Vec<Bucket>>,
}

impl GenericLimiter {
    pub fn new_from_file(path: PathBuf) -> Self {
        let fetcher = Arc::new(FileFetcher(path));
        Self::new_with_fetcher(fetcher)
    }

    pub fn new_from_canister_query(canister_id: CanisterId, agent: Agent) -> Self {
        let config_fetcher = CanisterConfigFetcherQuery(agent, canister_id);
        Self::new_with_config_fetcher(Arc::new(config_fetcher), canister_id)
    }

    pub fn new_from_canister_update(canister_id: CanisterId, agent: Agent) -> Self {
        let config_fetcher = CanisterConfigFetcherUpdate(agent, canister_id);
        Self::new_with_config_fetcher(Arc::new(config_fetcher), canister_id)
    }

    fn new_with_config_fetcher(
        config_fetcher: Arc<dyn FetchesConfig>,
        canister_id: CanisterId,
    ) -> Self {
        let fetcher = Arc::new(CanisterFetcher(config_fetcher, canister_id));
        Self::new_with_fetcher(fetcher)
    }

    fn new_with_fetcher(fetcher: Arc<dyn FetchesRules>) -> Self {
        Self {
            fetcher,
            buckets: ArcSwap::new(Arc::new(vec![])),
        }
    }

    fn process_rules(rules: Vec<RateLimitRule>, old: &Arc<Vec<Bucket>>) -> Vec<Bucket> {
        rules
            .into_iter()
            .enumerate()
            .map(|(idx, rule)| {
                // Check if the same rules exists in the same position.
                // If yes, then copy over the old limiter to avoid resetting it.
                if let Some(v) = old.get(idx) {
                    if v.rule == rule {
                        return v.clone();
                    }
                }

                let limiter = if let Action::Limit(limit, duration) = &rule.limit {
                    Some(if let Some(v) = &rule.ip_prefix_group {
                        Limiter::Sharded(
                            Arc::new(ShardedRatelimiter::new(*limit, *duration, HOUR)),
                            *v,
                        )
                    } else {
                        Limiter::Single(Arc::new(create_ratelimiter(*limit, *duration)))
                    })
                } else {
                    None
                };

                Bucket { rule, limiter }
            })
            .collect()
    }

    fn apply_rules(&self, rules: Vec<RateLimitRule>) -> bool {
        let old = self.buckets.load_full();
        let new = Arc::new(Self::process_rules(rules, &old));

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

    fn acquire_token(&self, ctx: Context) -> bool {
        for b in self.buckets.load_full().as_ref() {
            if let Some(v) = b.is_allowed(&ctx) {
                return v;
            }
        }

        // No rules / no match -> pass
        true
    }
}

#[async_trait]
impl Run for Arc<GenericLimiter> {
    async fn run(&mut self) -> Result<(), Error> {
        if let Err(e) = self.refresh().await {
            warn!("GenericLimiter: unable to refresh: {e:#}");
        }
        Ok(())
    }
}

pub async fn middleware(
    State(state): State<Arc<GenericLimiter>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet): Extension<Arc<RouteSubnet>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    canister_id: Option<Extension<CanisterId>>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let ctx = Context {
        subnet_id: subnet.id,
        canister_id: canister_id.map(|x| x.0.get().into()),
        method: ctx.method_name.as_deref(),
        request_type: ctx.request_type,
        ip: conn_info.remote_addr.ip(),
    };

    if !state.acquire_token(ctx) {
        return Err(ErrorCause::RateLimited(RateLimitCause::Generic));
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod test {
    use crate::principal;

    use super::*;
    use indoc::indoc;
    use std::str::FromStr;

    #[test]
    fn test_ratelimit() {
        let rules = indoc! {"
        - canister_id: pawub-syaaa-aaaam-qb7zq-cai
          limit: pass

        - canister_id: pawub-syaaa-aaaam-qb7zq-cai
          limit: block

        - subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
          canister_id: aaaaa-aa
          methods_regex: ^.*$
          limit: 10/1h

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          ip: 10.0.0.0/24
          methods_regex: ^(foo|bar)$
          limit: 20/1h

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods_regex: ^baz$
          limit: block

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          ip: 10.0.0.0/8
          request_types: [call]
          limit: 10/1h

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          request_types: [read_state]
          ip_prefix_group:
            v4: 24
            v6: 64
          limit: 10/1h

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          limit: 20/1h
        "};
        let rules: Vec<RateLimitRule> = serde_yaml::from_str(rules).unwrap();

        let limiter = GenericLimiter::new_from_file("/tmp/foo".into());
        limiter.apply_rules(rules);

        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.0.1").unwrap();

        let id1 = principal!("aaaaa-aa");
        let id2 = principal!("5s2ji-faaaa-aaaaa-qaaaq-cai");
        let id3 = principal!("qoctq-giaaa-aaaaa-aaaea-cai");
        let id4 = principal!("pawub-syaaa-aaaam-qb7zq-cai");

        let subnet_id =
            principal!("3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe");
        let subnet_id2 =
            principal!("6pbhf-qzpdk-kuqbr-pklfa-5ehhf-jfjps-zsj6q-57nrl-kzhpd-mu7hc-vae");

        // Check that pass action for this canister always allows
        for _ in 0..100 {
            assert!(limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id4),
                method: None,
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // Check id1 blocking with any method
        // 10 pass
        for _ in 0..10 {
            assert!(limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id1),
                method: Some("foo"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id1),
                method: Some("bar"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // Check id2 blocking with two methods
        // 20 pass
        // Another subnet_id which shouldn't have any difference
        for _ in 0..20 {
            assert!(limiter.acquire_token(Context {
                subnet_id: subnet_id2,
                canister_id: Some(id2),
                method: Some("foo"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // Then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(Context {
                subnet_id: subnet_id2,
                canister_id: Some(id2),
                method: Some("bar"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }
        // Other methods should not block ever
        for _ in 0..100 {
            assert!(limiter.acquire_token(Context {
                subnet_id: subnet_id2,
                canister_id: Some(id2),
                method: Some("lol"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }
        for _ in 0..100 {
            assert!(limiter.acquire_token(Context {
                subnet_id: subnet_id2,
                canister_id: Some(id2),
                method: Some("rofl"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // This method should be blocked always
        for _ in 0..100 {
            assert!(!limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id2),
                method: Some("baz"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // Check id3 blocking with any method and request type call
        // 10 pass
        for _ in 0..10 {
            assert!(limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: Some("rofl"),
                request_type: RequestType::Call,
                ip: ip1,
            }));
        }
        // then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: Some("bar"),
                request_type: RequestType::Call,
                ip: ip1,
            }));
        }

        // Then check id3 blocking with any method and request type query
        // 20 pass
        for _ in 0..20 {
            assert!(limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: Some("baz"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }
        // then all blocked
        for _ in 0..100 {
            assert!(!limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: Some("zob"),
                request_type: RequestType::Query,
                ip: ip1,
            }));
        }

        // Check per-ip-subnet blocking
        // IP1
        // 10 pass
        for _ in 0..10 {
            assert!(limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: None,
                request_type: RequestType::ReadState,
                ip: ip1,
            }));
        }
        // Then all blocked
        for _ in 0..10 {
            assert!(!limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: None,
                request_type: RequestType::ReadState,
                ip: ip1,
            }));
        }
        // IP2
        // 10 pass
        for _ in 0..10 {
            assert!(limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: None,
                request_type: RequestType::ReadState,
                ip: ip2,
            }));
        }
        // Then all blocked
        for _ in 0..10 {
            assert!(!limiter.acquire_token(Context {
                subnet_id,
                canister_id: Some(id3),
                method: None,
                request_type: RequestType::ReadState,
                ip: ip2,
            }));
        }
    }
}
