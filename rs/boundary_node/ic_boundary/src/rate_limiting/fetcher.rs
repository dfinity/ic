use std::{path::PathBuf, sync::Arc};

use anyhow::{Context as _, Error, anyhow, bail};
use async_trait::async_trait;
use candid::{Decode, Encode};
use ic_agent::{Agent, export::Principal};
use ic_types::CanisterId;
use rate_limits_api::{GetConfigResponse, Version, v1::RateLimitRule};
use tokio::fs;

const SCHEMA_VERSION: u64 = 1;

#[async_trait]
pub trait FetchesRules: Send + Sync {
    async fn fetch_rules(&self) -> Result<Vec<RateLimitRule>, Error>;
}

#[async_trait]
pub trait FetchesConfig: Send + Sync {
    async fn fetch_config(&self) -> Result<Vec<u8>, Error>;
}

pub struct FileFetcher(pub PathBuf);

#[async_trait]
impl FetchesRules for FileFetcher {
    async fn fetch_rules(&self) -> Result<Vec<RateLimitRule>, Error> {
        // no file -> no rules
        if fs::metadata(&self.0).await.is_err() {
            return Ok(vec![]);
        }

        let data = fs::read(&self.0)
            .await
            .context("unable to read rules file")?;

        let rules: Vec<RateLimitRule> =
            serde_yaml::from_slice(&data).context("unable to parse rules")?;

        Ok(rules)
    }
}

pub struct CanisterConfigFetcherQuery(pub Agent, pub CanisterId);

#[async_trait]
impl FetchesConfig for CanisterConfigFetcherQuery {
    async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
        let response = self
            .0
            .query(&Principal::from(self.1), "get_config")
            .with_arg(Encode!(&None::<Version>).unwrap())
            .call()
            .await
            .map_err(|e| anyhow!("failed to fetch config from the canister: {e:#}"))?;

        if response.is_empty() {
            bail!("got empty response from the canister")
        } else {
            Ok(response)
        }
    }
}

pub struct CanisterConfigFetcherUpdate(pub Agent, pub CanisterId);

#[async_trait]
impl FetchesConfig for CanisterConfigFetcherUpdate {
    async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
        let response = self
            .0
            .update(&Principal::from(self.1), "get_config")
            .with_arg(Encode!(&None::<Version>).unwrap())
            .call_and_wait()
            .await
            .map_err(|e| anyhow!("failed to fetch config from the canister: {e:#}"))?;

        if response.is_empty() {
            bail!("got empty response from the canister")
        } else {
            Ok(response)
        }
    }
}

pub struct CanisterFetcher(pub Arc<dyn FetchesConfig>);

#[async_trait]
impl FetchesRules for CanisterFetcher {
    async fn fetch_rules(&self) -> Result<Vec<RateLimitRule>, Error> {
        let response = self
            .0
            .fetch_config()
            .await
            .context("unable to fetch config")?;

        let response = Decode!(&response, GetConfigResponse)
            .context("failed to decode candid response")?
            .map_err(|e| anyhow!("failed to get config: {e:?}"))?;

        if response.config.schema_version != SCHEMA_VERSION {
            bail!(
                "incorrect schema version (got {}, expected {})",
                response.config.schema_version,
                SCHEMA_VERSION
            );
        }

        if response.config.is_redacted {
            bail!("got a redacted response, probably authentication is incorrect");
        }

        let rules = response
            .config
            .rules
            .into_iter()
            .map(|x| -> Result<RateLimitRule, Error> {
                let Some(raw) = x.rule_raw else {
                    bail!("rule with id {} ({:?}) is None", x.rule_id, x.description);
                };

                let rule = RateLimitRule::from_bytes_yaml(&raw)
                    .context(format!("unable to decode raw rule with id {}", x.rule_id))?;

                Ok(rule)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rules)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use candid::Encode;
    use ic_bn_lib::principal;
    use indoc::indoc;
    use rate_limits_api::*;
    use regex::Regex;

    use super::*;

    struct FakeConfigFetcherOk;

    #[async_trait]
    impl FetchesConfig for FakeConfigFetcherOk {
        async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
            let resp: GetConfigResponse = Ok(ConfigResponse {
                version: 1,
                active_since: 0,
                config: OutputConfig {
                    schema_version: SCHEMA_VERSION,
                    is_redacted: false,
                    rules: vec![
                        OutputRule {
                            rule_id: "foobar".into(),
                            incident_id: "barfoo".into(),
                            rule_raw: Some(indoc! {"
                                canister_id: aaaaa-aa
                                subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
                                methods_regex: ^foo|bar$
                                limit: block
                            "}.into()),
                            description: None
                        },
                        OutputRule {
                            rule_id: "foobaz".into(),
                            incident_id: "barfoo".into(),
                            rule_raw: Some(indoc! {"
                                canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
                                subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
                                methods_regex: ^baz|bax$
                                limit: 1/10s
                            "}.into()),
                            description: None
                        },
                        OutputRule {
                            rule_id: "deadbeef".into(),
                            incident_id: "barfoo".into(),
                            rule_raw: Some(indoc! {"
                                canister_id: aaaaa-aa
                                methods_regex: ^foo|bax$
                                limit: 10/1m
                            "}.into()),
                            description: None
                        },
                    ],
                },
            });

            Ok(Encode!(&resp).unwrap())
        }
    }

    struct FakeConfigFetcherBadSchema;

    #[async_trait]
    impl FetchesConfig for FakeConfigFetcherBadSchema {
        async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
            let resp: GetConfigResponse = Ok(ConfigResponse {
                version: 1,
                active_since: 0,
                config: OutputConfig {
                    schema_version: SCHEMA_VERSION + 1,
                    is_redacted: false,
                    rules: vec![],
                },
            });

            Ok(Encode!(&resp).unwrap())
        }
    }

    struct FakeConfigFetcherNoneRule;

    #[async_trait]
    impl FetchesConfig for FakeConfigFetcherNoneRule {
        async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
            let resp: GetConfigResponse = Ok(ConfigResponse {
                version: 1,
                active_since: 0,
                config: OutputConfig {
                    schema_version: SCHEMA_VERSION,
                    is_redacted: false,
                    rules: vec![OutputRule {
                        rule_id: "foobar".into(),
                        incident_id: "barfoo".into(),
                        rule_raw: None,
                        description: None,
                    }],
                },
            });

            Ok(Encode!(&resp).unwrap())
        }
    }

    #[tokio::test]
    async fn test_canister_fetcher() {
        // Check bad schema
        let canister_fetcher = CanisterFetcher(Arc::new(FakeConfigFetcherBadSchema));
        assert!(canister_fetcher.fetch_rules().await.is_err());

        // Check missing rule
        let canister_fetcher = CanisterFetcher(Arc::new(FakeConfigFetcherNoneRule));
        assert!(canister_fetcher.fetch_rules().await.is_err());

        // Check correct rules parsing
        let canister_fetcher = CanisterFetcher(Arc::new(FakeConfigFetcherOk));
        let rules = canister_fetcher.fetch_rules().await.unwrap();

        assert_eq!(
            rules,
            vec![
                RateLimitRule {
                    canister_id: Some(principal!("aaaaa-aa")),
                    subnet_id: Some(principal!(
                        "3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"
                    )),
                    methods_regex: Some(Regex::new("^foo|bar$").unwrap()),
                    request_types: None,
                    ip_prefix_group: None,
                    ip: None,
                    limit: v1::Action::Block,
                },
                RateLimitRule {
                    canister_id: Some(principal!("5s2ji-faaaa-aaaaa-qaaaq-cai")),
                    subnet_id: Some(principal!(
                        "3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"
                    )),
                    methods_regex: Some(Regex::new("^baz|bax$").unwrap()),
                    request_types: None,
                    ip_prefix_group: None,
                    ip: None,
                    limit: v1::Action::Limit(1, Duration::from_secs(10)),
                },
                RateLimitRule {
                    canister_id: Some(principal!("aaaaa-aa")),
                    subnet_id: None,
                    methods_regex: Some(Regex::new("^foo|bax$").unwrap()),
                    request_types: None,
                    ip_prefix_group: None,
                    ip: None,
                    limit: v1::Action::Limit(10, Duration::from_secs(60)),
                }
            ]
        );
    }
}
