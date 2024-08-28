use std::{fmt, path::PathBuf, sync::Arc, time::Duration};

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
use humantime::parse_duration;
use ic_types::CanisterId;
use ratelimit::Ratelimiter;
use regex::Regex;
use serde::{
    de::{self, Deserializer},
    Deserialize,
};
use tokio::fs;
use tracing::warn;

use crate::{
    core::Run,
    persist::RouteSubnet,
    routes::{ErrorCause, RateLimitCause, RequestContext, RequestType},
};

/// Implement serde parser for Action
struct ActionVisitor;
impl<'de> de::Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a rate limit spec in <count>/<duration> format e.g. 100/30s or block"
        )
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s == "block" {
            return Ok(Action::Block);
        }

        let (count, interval) = s
            .split_once('/')
            .ok_or(de::Error::custom("invalid limit format"))?;

        let count = count.parse::<u32>().map_err(de::Error::custom)?;
        let interval = parse_duration(interval).map_err(de::Error::custom)?;

        if count == 0 || interval == Duration::ZERO {
            return Err(de::Error::custom("count and interval should be > 0"));
        }

        Ok(Action::Limit(count, interval))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Block,
    Limit(u32, Duration),
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Action, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ActionVisitor)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    subnet_id: Option<Principal>,
    canister_id: Option<Principal>,
    request_type: Option<RequestType>,
    #[serde(default, with = "serde_regex")]
    methods: Option<Regex>,
    limit: Action,
}

/// Regex does not implement Eq, so do it manually
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.methods.as_ref().map(|x| x.as_str()) == other.methods.as_ref().map(|x| x.as_str())
            && self.canister_id == other.canister_id
            && self.subnet_id == other.subnet_id
            && self.limit == other.limit
    }
}
impl Eq for Rule {}

struct Bucket {
    rule: Rule,
    limiter: Option<Ratelimiter>,
}

impl PartialEq for Bucket {
    fn eq(&self, other: &Self) -> bool {
        self.rule == other.rule
    }
}
impl Eq for Bucket {}

pub struct Limiter {
    path: PathBuf,
    buckets: ArcSwap<Vec<Bucket>>,
}

impl Limiter {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            buckets: ArcSwap::new(Arc::new(vec![])),
        }
    }

    fn process_rules(rules: Vec<Rule>) -> Vec<Bucket> {
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

    async fn load_rules(&self) -> Result<Vec<Rule>, Error> {
        // no file -> no rules
        if fs::metadata(&self.path).await.is_err() {
            return Ok(vec![]);
        }

        let data = fs::read(&self.path)
            .await
            .context("unable to read rules file")?;
        let rules: Vec<Rule> = serde_yaml::from_slice(&data).context("unable to parse rules")?;
        Ok(rules)
    }

    fn apply_rules(&self, rules: Vec<Rule>) -> bool {
        let new = Arc::new(Self::process_rules(rules));
        let old = self.buckets.load_full();

        if old != new {
            warn!("GenericLimiter: ruleset updated: {} rules", new.len());

            for b in new.as_ref() {
                warn!(
                    "GenericLimiter: subnet: {:?}, canister: {:?}, methods: {:?}, action: {:?}",
                    b.rule.subnet_id, b.rule.canister_id, b.rule.methods, b.rule.limit,
                );
            }

            self.buckets.store(new);
            return true;
        }

        false
    }

    async fn refresh(&self) -> Result<(), Error> {
        let rules = self.load_rules().await.context("unable to load rules")?;
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

            if let Some(v) = b.rule.request_type {
                if request_type != v {
                    continue;
                }
            }

            if let Some(rgx) = &b.rule.methods {
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
            } else {
                // Always block
                return false;
            }
        }

        // No rules / no match -> pass
        true
    }
}

#[async_trait]
impl Run for Arc<Limiter> {
    async fn run(&mut self) -> Result<(), Error> {
        self.refresh().await
    }
}

pub async fn middleware(
    State(state): State<Arc<Limiter>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    Extension(subnet): Extension<Arc<RouteSubnet>>,
    canister_id: Option<Extension<CanisterId>>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ErrorCause> {
    if !state.acquire_token(
        subnet.id,
        canister_id.map(|x| (x.0).get().into()),
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
    fn test_rules() {
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: 100/1s

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods: ^(foo|bar)$
          limit: 60/1m

        - subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
          canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          limit: 90/1m

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods: ^(foo|bar)$
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_type: query
          methods: ^(foo|bar)$
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_type: call
          limit: block
        "};
        let rules: Vec<Rule> = serde_yaml::from_str(rules).unwrap();

        assert_eq!(
            rules,
            vec![
                Rule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("aaaaa-aa").unwrap()),
                    request_type: None,
                    methods: Some(Regex::new("^.*$").unwrap()),
                    limit: Action::Limit(100, Duration::from_secs(1)),
                },
                Rule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_type: None,
                    methods: Some(Regex::new("^(foo|bar)$").unwrap()),
                    limit: Action::Limit(60, Duration::from_secs(60)),
                },
                Rule {
                    subnet_id: Some(
                        Principal::from_text(
                            "3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"
                        )
                        .unwrap()
                    ),
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_type: None,
                    methods: None,
                    limit: Action::Limit(90, Duration::from_secs(60)),
                },
                Rule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_type: None,
                    methods: Some(Regex::new("^(foo|bar)$").unwrap()),
                    limit: Action::Block,
                },
                Rule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_type: Some(RequestType::Query),
                    methods: Some(Regex::new("^(foo|bar)$").unwrap()),
                    limit: Action::Block,
                },
                Rule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_type: Some(RequestType::Call),
                    methods: None,
                    limit: Action::Block,
                },
            ],
        );

        Limiter::process_rules(rules);

        // Bad canister
        let rules = indoc! {"
        - canister_id: aaaaa-zzz
          methods: ^.*$
          limit: 100/1s
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        // Bad regex
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: foo(bar
          limit: 100/1s
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        // Bad limits
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: 100/
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: /100s
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: /
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: 0/1s
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: 1/0s
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods: ^.*$
          limit: 1/1
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());

        // Bad request type
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          request_type: blah
          limit: 10/1s
        "};
        let rules = serde_yaml::from_str::<Vec<Rule>>(rules);
        assert!(rules.is_err());
    }

    #[test]
    fn test_ratelimit() {
        let rules = indoc! {"
        - subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
          canister_id: aaaaa-aa
          methods: ^.*$
          limit: 10/1h

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods: ^(foo|bar)$
          limit: 20/1h

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods: ^baz$
          limit: block

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          request_type: call
          limit: 10/1h

        - canister_id: qoctq-giaaa-aaaaa-aaaea-cai
          limit: 20/1h
        "};
        let rules: Vec<Rule> = serde_yaml::from_str(rules).unwrap();

        let limiter = Limiter::new("/tmp/foo".into());
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
