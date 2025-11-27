use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
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
use ic_agent::Agent;
use ic_bn_lib::prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};
use ic_bn_lib_common::{traits::Run, types::http::ConnInfo};
use ic_types::CanisterId;
use ipnet::IpNet;
use rate_limits_api::v1::{Action, IpPrefixes, RateLimitRule, RequestType as RequestTypeRule};
use ratelimit::Ratelimiter;
use strum::{Display, IntoStaticStr};
#[allow(clippy::disallowed_types)]
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{
    fetcher::{
        CanisterConfigFetcherQuery, CanisterConfigFetcherUpdate, CanisterFetcher, FetchesConfig,
        FetchesRules, FileFetcher,
    },
    sharded::{ShardedRatelimiter, create_ratelimiter},
};

use crate::{
    errors::{ErrorCause, RateLimitCause},
    http::RequestType,
    routes::RequestContext,
    snapshot::{RegistrySnapshot, Subnet},
};

// Converts between different request types
// We can't use a single one because Ratelimit API crate needs to build on WASM and ic-bn-lib does not
fn convert_request_type(rt: RequestType) -> RequestTypeRule {
    match rt {
        RequestType::QueryV2 => RequestTypeRule::QueryV2,
        RequestType::QueryV3 => RequestTypeRule::QueryV3,
        RequestType::CallV2 => RequestTypeRule::CallV2,
        RequestType::CallV3 => RequestTypeRule::CallV3,
        RequestType::CallV4 => RequestTypeRule::CallV4,
        RequestType::ReadStateV2 => RequestTypeRule::ReadStateV2,
        RequestType::ReadStateV3 => RequestTypeRule::ReadStateV3,
        RequestType::ReadStateSubnetV2 => RequestTypeRule::ReadStateSubnetV2,
        RequestType::ReadStateSubnetV3 => RequestTypeRule::ReadStateSubnetV3,
        _ => RequestTypeRule::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, IntoStaticStr)]
enum Decision {
    Pass,
    Block,
    Limit,
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
    fn evaluate(&self, ctx: &Context) -> Option<Decision> {
        if let Some(v) = self.rule.subnet_id
            && ctx.subnet_id != v
        {
            return None;
        }

        if let Some(v) = self.rule.canister_id
            && let Some(x) = ctx.canister_id
            && x != v
        {
            return None;
        }

        if let Some(v) = &self.rule.request_types
            && !v.contains(&convert_request_type(ctx.request_type))
        {
            return None;
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

        if let Some(v) = self.rule.ip
            && !v.contains(&ctx.ip)
        {
            return None;
        }

        if self.rule.limit == Action::Pass {
            return Some(Decision::Pass);
        } else if self.rule.limit == Action::Block {
            return Some(Decision::Block);
        }

        if let Some(limiter) = &self.limiter {
            let allowed = match limiter {
                Limiter::Single(v) => v.try_wait().is_ok(),
                Limiter::Sharded(v, prefix) => {
                    let prefix = match ctx.ip {
                        IpAddr::V4(_) => prefix.v4,
                        IpAddr::V6(_) => prefix.v6,
                    };

                    // We assume that the prefix is correct, assert is safe
                    let net = IpNet::new_assert(ctx.ip, prefix);
                    v.acquire(net)
                }
            };

            return Some(if allowed {
                Decision::Pass
            } else {
                Decision::Limit
            });
        }

        // Should never get here
        unreachable!();
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Options {
    pub tti: Duration,
    pub max_shards: u64,
    pub poll_interval: Duration,
    pub autoscale: bool,
}

struct Metrics {
    scale: IntGauge,
    last_successful_fetch: IntGauge,
    active_rules: IntGauge,
    fetches: IntCounterVec,
    decisions: IntCounterVec,
    shards_count: IntGauge,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        Self {
            scale: register_int_gauge_with_registry!(
                format!("generic_limiter_scale"),
                format!("Current scale that's applied to the rules"),
                registry,
            )
            .unwrap(),

            last_successful_fetch: register_int_gauge_with_registry!(
                format!("generic_limiter_last_successful_fetch"),
                format!("How many seconds ago the last successful fetch happened"),
                registry
            )
            .unwrap(),

            active_rules: register_int_gauge_with_registry!(
                format!("generic_limiter_rules"),
                format!("Number of rules currently installed"),
                registry
            )
            .unwrap(),

            fetches: register_int_counter_vec_with_registry!(
                format!("generic_limiter_fetches"),
                format!("Count of rule fetches and their outcome"),
                &["result"],
                registry
            )
            .unwrap(),

            decisions: register_int_counter_vec_with_registry!(
                format!("generic_limiter_decisions"),
                format!("Count of decisions made by the ratelimiter"),
                &["decision"],
                registry
            )
            .unwrap(),

            shards_count: register_int_gauge_with_registry!(
                format!("generic_limiter_shards_count"),
                format!("Number of dynamic shards if the corresponding rules are used"),
                registry,
            )
            .unwrap(),
        }
    }
}

pub struct GenericLimiter {
    fetcher: Arc<dyn FetchesRules>,
    buckets: ArcSwap<Vec<Bucket>>,
    active_rules: ArcSwap<Vec<RateLimitRule>>,
    scale: AtomicU32,
    #[allow(clippy::disallowed_types)]
    channel_snapshot: Mutex<watch::Receiver<Option<Arc<RegistrySnapshot>>>>,
    #[allow(clippy::disallowed_types)]
    last_refresh: Mutex<Instant>,
    opts: Options,
    metrics: Metrics,
}

impl GenericLimiter {
    pub fn new_from_file(
        path: PathBuf,
        opts: Options,
        channel_snapshot: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
        registry: &Registry,
    ) -> Self {
        let fetcher = Arc::new(FileFetcher(path));
        Self::new_with_fetcher(fetcher, opts, channel_snapshot, registry)
    }

    pub fn new_from_canister(
        canister_id: CanisterId,
        agent: Agent,
        opts: Options,
        use_update_call: bool,
        channel_snapshot: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
        registry: &Registry,
    ) -> Self {
        let config_fetcher: Arc<dyn FetchesConfig> = if use_update_call {
            Arc::new(CanisterConfigFetcherUpdate(agent, canister_id))
        } else {
            Arc::new(CanisterConfigFetcherQuery(agent, canister_id))
        };

        let fetcher = Arc::new(CanisterFetcher(config_fetcher));
        Self::new_with_fetcher(fetcher, opts, channel_snapshot, registry)
    }

    fn new_with_fetcher(
        fetcher: Arc<dyn FetchesRules>,
        opts: Options,
        channel_snapshot: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
        registry: &Registry,
    ) -> Self {
        Self {
            fetcher,
            buckets: ArcSwap::new(Arc::new(vec![])),
            active_rules: ArcSwap::new(Arc::new(vec![])),
            opts,
            #[allow(clippy::disallowed_types)]
            last_refresh: Mutex::new(Instant::now()),
            scale: AtomicU32::new(1),
            #[allow(clippy::disallowed_types)]
            channel_snapshot: Mutex::new(channel_snapshot),
            metrics: Metrics::new(registry),
        }
    }

    fn process_rules(
        &self,
        rules: Vec<RateLimitRule>,
        old: &Arc<Vec<Bucket>>,
        scale: u32,
    ) -> Vec<Bucket> {
        rules
            .into_iter()
            .enumerate()
            .map(|(idx, mut rule)| {
                // Scale the rule limit accordingly
                if let Action::Limit(n, d) = rule.limit {
                    // Make sure the limit doesn't go below 1
                    let limit = (n / scale).max(1);
                    rule.limit = Action::Limit(limit, d);
                }

                // Check if the same rule exists in the same position.
                // If yes, then copy over the old limiter to avoid resetting it.
                if let Some(v) = old.get(idx)
                    && v.rule == rule
                {
                    return v.clone();
                }

                let limiter = if let Action::Limit(limit, duration) = &rule.limit {
                    Some(if let Some(v) = &rule.ip_prefix_group {
                        Limiter::Sharded(
                            Arc::new(ShardedRatelimiter::new(
                                *limit,
                                *limit,
                                *duration,
                                self.opts.tti,
                                self.opts.max_shards,
                            )),
                            *v,
                        )
                    } else {
                        Limiter::Single(Arc::new(create_ratelimiter(*limit, *limit, *duration)))
                    })
                } else {
                    None
                };

                Bucket { rule, limiter }
            })
            .collect()
    }

    fn apply_rules(&self, rules: Vec<RateLimitRule>, scale: u32) -> bool {
        let old = self.buckets.load_full();
        let new = Arc::new(self.process_rules(rules, &old, scale));

        if old != new {
            warn!(
                "GenericLimiter: ruleset updated: {} rules (scale {scale})",
                new.len()
            );

            for b in new.as_ref() {
                warn!("GenericLimiter: {}", b.rule);
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

        self.metrics.active_rules.set(rules.len() as i64);

        self.apply_rules(rules.clone(), self.scale.load(Ordering::SeqCst));

        // Store the new copy of the rules as a golden copy for future recalculation
        self.active_rules.store(Arc::new(rules));
        *self.last_refresh.lock().await = Instant::now();

        Ok(())
    }

    fn evaluate(&self, ctx: Context) -> Decision {
        // Always allow access from localhost.
        // This makes sure that ic-boundary & colocated services will always be able to query anything.
        if ctx.ip.is_loopback() {
            return Decision::Pass;
        }

        for b in self.buckets.load_full().as_ref() {
            if let Some(v) = b.evaluate(&ctx) {
                return v;
            }
        }

        // No rules / no match -> pass
        Decision::Pass
    }

    /// Count the number of shards in sharded limiters (if there are any)
    fn shards_count(&self) -> u64 {
        self.buckets
            .load_full()
            .iter()
            .filter_map(|x| {
                if let Some(Limiter::Sharded(v, _)) = &x.limiter {
                    Some(v.shards_count())
                } else {
                    None
                }
            })
            .sum()
    }
}

#[async_trait]
impl Run for GenericLimiter {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(self.opts.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut channel = self.channel_snapshot.lock().await;

        loop {
            tokio::select! {
                biased;

                _ = token.cancelled() => {
                    return Ok(());
                }

                Ok(()) = channel.changed(), if self.opts.autoscale => {
                    let snapshot = channel.borrow_and_update().clone();

                    if let Some(v) = snapshot {
                        // Store the count of API BNs as a scale and make sure it's >= 1
                        let scale = v.api_bns.len().max(1) as u32;
                        self.scale.store(scale, Ordering::SeqCst);
                        self.metrics.scale.set(scale as i64);
                        warn!("GenericLimiter: got a new registry snapshot, recalculating with scale {scale}");

                        // Recalculate the rules based on the potentially new scale
                        self.apply_rules(self.active_rules.load().as_ref().clone(), scale);
                    }
                }

                _ = interval.tick() => {
                    let r = self.refresh().await;
                    self.metrics.fetches.with_label_values(&[if r.is_ok() { "success" } else {"failure"}]).inc();
                    if let Err(e) = r {
                        warn!("GenericLimiter: unable to refresh: {e:#}");
                    }

                    // Update the metrics
                    self.metrics.last_successful_fetch.set(self.last_refresh.lock().await.elapsed().as_secs_f64() as i64);
                    self.metrics.shards_count.set(self.shards_count() as i64);
                }
            }
        }
    }
}

pub async fn middleware(
    State(state): State<Arc<GenericLimiter>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet): Extension<Arc<Subnet>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, ErrorCause> {
    let canister_id = request.extensions().get::<CanisterId>().copied();

    let ctx = Context {
        subnet_id: subnet.id,
        canister_id: canister_id.map(|x| x.get().into()),
        method: ctx.method_name.as_deref(),
        request_type: ctx.request_type,
        ip: conn_info.remote_addr.ip(),
    };

    let decision = state.evaluate(ctx);

    let decision_str: &'static str = decision.into();
    state
        .metrics
        .decisions
        .with_label_values(&[decision_str])
        .inc();

    match decision {
        Decision::Pass => Ok(next.run(request).await),
        Decision::Block => Err(ErrorCause::Forbidden),
        Decision::Limit => Err(ErrorCause::RateLimited(RateLimitCause::Generic)),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::bail;
    use ic_bn_lib_common::principal;
    use indoc::indoc;
    use std::str::FromStr;

    use crate::snapshot::{ApiBoundaryNode, generate_stub_snapshot};

    struct BrokenFetcher;

    #[async_trait]
    impl FetchesRules for BrokenFetcher {
        async fn fetch_rules(&self) -> Result<Vec<RateLimitRule>, Error> {
            bail!("boo")
        }
    }

    struct TestFetcher(Vec<RateLimitRule>);

    #[async_trait]
    impl FetchesRules for TestFetcher {
        async fn fetch_rules(&self) -> Result<Vec<RateLimitRule>, Error> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn test_ratelimit() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.0.1").unwrap();
        let ip_local4 = IpAddr::from_str("127.0.0.1").unwrap();
        let ip_local6 = IpAddr::from_str("::1").unwrap();

        let id0 = principal!("pawub-syaaa-aaaam-qb7zq-cai");
        let id1 = principal!("aaaaa-aa");
        let id2 = principal!("5s2ji-faaaa-aaaaa-qaaaq-cai");
        let id3 = principal!("qoctq-giaaa-aaaaa-aaaea-cai");

        let subnet_id =
            principal!("3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe");
        let subnet_id2 =
            principal!("6pbhf-qzpdk-kuqbr-pklfa-5ehhf-jfjps-zsj6q-57nrl-kzhpd-mu7hc-vae");

        let rules = indoc! {"
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
          request_types: [call_v2]
          limit: 10/1h

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          request_types: [read_state_v2]
          ip_prefix_group:
            v4: 24
            v6: 64
          limit: 10/1h

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          limit: 20/1h
        "};

        let rules: Vec<RateLimitRule> = serde_yaml::from_str(rules).unwrap();
        let opts = Options {
            tti: Duration::from_secs(10),
            max_shards: 10000,
            poll_interval: Duration::from_secs(30),
            autoscale: true,
        };

        // Check that fetching works
        let fetcher = TestFetcher(rules.clone());
        let (_, rx) = watch::channel(None);
        let limiter = Arc::new(GenericLimiter::new_with_fetcher(
            Arc::new(fetcher),
            opts.clone(),
            rx,
            &Registry::new(),
        ));
        assert!(limiter.refresh().await.is_ok());
        assert_eq!(limiter.active_rules.load().len(), 7);

        // Check id1 limiting with any method
        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Check different rules
        let (tx, rx) = watch::channel(None);
        let limiter = Arc::new(GenericLimiter::new_with_fetcher(
            Arc::new(BrokenFetcher),
            opts,
            rx,
            &Registry::new(),
        ));

        let limiter_clone = limiter.clone();
        tokio::spawn(async move {
            let _ = limiter_clone.run(CancellationToken::new()).await;
        });

        limiter.apply_rules(rules.clone(), 1);

        let mut snapshot = generate_stub_snapshot(vec![]);
        snapshot.api_bns = vec![
            ApiBoundaryNode {
                _id: principal!("3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"),
                _addr: ip1,
                _port: 31337,
            },
            ApiBoundaryNode {
                _id: principal!("3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"),
                _addr: ip2,
                _port: 31337,
            },
        ];

        // Check that blocked canister always works from localhost even if there's a block rule present
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id0),
                    method: None,
                    request_type: RequestType::QueryV2,
                    ip: ip_local4,
                }),
                Decision::Pass
            );
        }
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id0),
                    method: None,
                    request_type: RequestType::QueryV2,
                    ip: ip_local6,
                }),
                Decision::Pass
            );
        }

        // Check id1 limiting with any method
        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Check id2 limiting with two methods
        // 20 pass
        // Another subnet_id which shouldn't have any difference
        for _ in 0..20 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id: subnet_id2,
                    canister_id: Some(id2),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // Then all limit
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id: subnet_id2,
                    canister_id: Some(id2),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }
        // Other methods should not limit ever
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id: subnet_id2,
                    canister_id: Some(id2),
                    method: Some("lol"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id: subnet_id2,
                    canister_id: Some(id2),
                    method: Some("rofl"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // This method should be blocked always
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id2),
                    method: Some("baz"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Block
            );
        }

        // Check id3 limiting with any method and request type call
        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: Some("rofl"),
                    request_type: RequestType::CallV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }
        // then all limited
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: Some("bar"),
                    request_type: RequestType::CallV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Then check id3 limiting with any method and request type query
        // 20 pass
        for _ in 0..20 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: Some("baz"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }
        // then all limited
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: Some("zob"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Check per-ip-subnet blocking
        // IP1
        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: None,
                    request_type: RequestType::ReadStateV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }
        // Then all limited
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: None,
                    request_type: RequestType::ReadStateV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }
        // IP2
        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: None,
                    request_type: RequestType::ReadStateV2,
                    ip: ip2,
                }),
                Decision::Pass
            );
        }
        // Then all limited
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id3),
                    method: None,
                    request_type: RequestType::ReadStateV2,
                    ip: ip2,
                }),
                Decision::Limit
            );
        }

        // Check that scaling works, the rules should fire 2x earlier now
        limiter.apply_rules(rules.clone(), 2);

        // 5 pass (instead of configured 10)
        for _ in 0..5 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Make sure that resetting scale back to 1 works
        limiter.apply_rules(rules.clone(), 1);

        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Check that limit after scaling doesn't go under 1
        limiter.apply_rules(rules.clone(), 100);

        // 1 pass (instead of configured 10)
        assert_eq!(
            limiter.evaluate(Context {
                subnet_id,
                canister_id: Some(id1),
                method: Some("foo"),
                request_type: RequestType::QueryV2,
                ip: ip1,
            }),
            Decision::Pass
        );

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Check that autoscaling works by sending a snapshot
        limiter.active_rules.store(Arc::new(rules.clone()));
        tx.send(Some(Arc::new(snapshot.clone()))).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 5 pass (instead of configured 10)
        for _ in 0..5 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }

        // Check that autoscaling resets to 1 if there are no API BNs
        snapshot.api_bns = vec![];
        tx.send(Some(Arc::new(snapshot))).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 10 pass
        for _ in 0..10 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("foo"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Pass
            );
        }

        // then all blocked
        for _ in 0..100 {
            assert_eq!(
                limiter.evaluate(Context {
                    subnet_id,
                    canister_id: Some(id1),
                    method: Some("bar"),
                    request_type: RequestType::QueryV2,
                    ip: ip1,
                }),
                Decision::Limit
            );
        }
    }
}
