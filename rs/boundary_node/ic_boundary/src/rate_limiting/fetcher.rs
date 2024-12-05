use std::{path::PathBuf, sync::Arc, time::SystemTime};

use anyhow::{anyhow, Context as _, Error};
use async_trait::async_trait;
use candid::Decode;
use ic_canister_client::Agent;
use ic_types::CanisterId;
use rate_limits_api::{v1::RateLimitRule, GetConfigResponse};
use tokio::fs;

const SCHEMA_VERSION: u64 = 1;

fn nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

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

pub struct CanisterConfigFetcher(pub Agent, pub CanisterId);

#[async_trait]
impl FetchesConfig for CanisterConfigFetcher {
    async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
        self.0
            .execute_update(
                &self.1,      // effective_canister_id
                &self.1,      // canister_id
                "get_config", // method
                vec![],       // arguments
                nonce(),      // nonce
            )
            .await
            .map_err(|e| anyhow!("failed to fetch config from the canister: {e:#}"))?
            .ok_or_else(|| anyhow!("got empty response from the canister"))
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
            return Err(anyhow!(
                "incorrect schema version (got {}, expected {})",
                response.config.schema_version,
                SCHEMA_VERSION
            ));
        }

        if response.config.is_redacted {
            return Err(anyhow!(
                "got a redacted response, probably authentication is incorrect"
            ));
        }

        let rules = response
            .config
            .rules
            .into_iter()
            .map(|x| -> Result<RateLimitRule, Error> {
                let Some(raw) = x.rule_raw else {
                    return Err(anyhow!(
                        "rule with id {} ({:?}) is None",
                        x.id,
                        x.description
                    ));
                };

                let rule = RateLimitRule::from_bytes_yaml(&raw)
                    .context(format!("unable to decode raw rule with id {}", x.id))?;
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
    use rate_limits_api::*;
    use regex::Regex;

    use super::*;
    use crate::test_utils::principal;

    struct FakeConfigFetcher;

    #[async_trait]
    impl FetchesConfig for FakeConfigFetcher {
        async fn fetch_config(&self) -> Result<Vec<u8>, Error> {
            let resp: GetConfigResponse = Ok(ConfigResponse {
                version: 1,
                active_since: 0,
                config: OutputConfig {
                    schema_version: SCHEMA_VERSION,
                    is_redacted: false,
                    rules: vec![
                        OutputRule {
                            id: "foobar".into(),
                            incident_id: "barfoo".into(),
                            rule_raw: Some(b"canister_id: aaaaa-aa\nsubnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe\nmethods_regex: ^foo|bar$\nlimit: block\n".into()),
                            description: None
                        },
                        OutputRule {
                            id: "foobaz".into(),
                            incident_id: "barfoo".into(),
                            rule_raw: Some(b"canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai\nsubnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe\nmethods_regex: ^baz|bax$\nlimit: 1/10s\n".into()),
                            description: None
                        },
                        OutputRule {
                            id: "deadbeef".into(),
                            incident_id: "barfoo".into(),
                            rule_raw: Some(b"canister_id: aaaaa-aa\nmethods_regex: ^foo|bax$\nlimit: 10/1m\n".into()),
                            description: None
                        },
                    ],
                },
            });

            Ok(Encode!(&resp).unwrap())
        }
    }

    #[tokio::test]
    async fn test_canister_fetcher() {
        let canister_fetcher = CanisterFetcher(Arc::new(FakeConfigFetcher));
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
                    limit: v1::Action::Block,
                },
                RateLimitRule {
                    canister_id: Some(principal!("5s2ji-faaaa-aaaaa-qaaaq-cai")),
                    subnet_id: Some(principal!(
                        "3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"
                    )),
                    methods_regex: Some(Regex::new("^baz|bax$").unwrap()),
                    request_types: None,
                    limit: v1::Action::Limit(1, Duration::from_secs(10)),
                },
                RateLimitRule {
                    canister_id: Some(principal!("aaaaa-aa")),
                    subnet_id: None,
                    methods_regex: Some(Regex::new("^foo|bax$").unwrap()),
                    request_types: None,
                    limit: v1::Action::Limit(10, Duration::from_secs(60)),
                }
            ]
        );
    }
}
