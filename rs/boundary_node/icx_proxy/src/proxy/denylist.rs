use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use candid::Principal;
use opentelemetry::{
    metrics::{Counter, Meter},
    KeyValue,
};
use serde::Deserialize;
use serde_json as json;
use tracing::{info, warn};

pub struct Denylist {
    url: Option<String>,
    http_client: reqwest::Client,
    denylist: ArcSwapOption<HashMap<Principal, Vec<String>>>,
    allowlist: HashSet<Principal>,
}

impl Denylist {
    pub fn new(url: Option<String>, allowlist: HashSet<Principal>) -> Self {
        Self {
            url,
            http_client: reqwest::Client::builder().build().unwrap(),
            denylist: ArcSwapOption::empty(),
            allowlist,
        }
    }

    pub fn is_blocked(&self, canister_id: Principal, country_code: &str) -> bool {
        if self.allowlist.contains(&canister_id) {
            return false;
        }

        if let Some(list) = self.denylist.load_full() {
            let entry = match list.get(&canister_id) {
                Some(v) => v,
                None => return false,
            };

            // if there are no codes - then all regions are blocked
            if entry.is_empty() {
                return true;
            }

            return entry.iter().any(|x| x == country_code);
        }

        false
    }

    pub async fn update(&self) -> Result<usize, Error> {
        let url = match &self.url {
            Some(v) => v.clone(),
            None => return Err(anyhow!("no URL provided")),
        };

        let request = self
            .http_client
            .request(reqwest::Method::GET, url)
            .build()
            .context("failed to build request")?;

        let response = self
            .http_client
            .execute(request)
            .await
            .context("request failed")?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("request failed with status {}", response.status()));
        }

        let data = response
            .bytes()
            .await
            .context("failed to get response bytes")?;

        self.load_json(&data)
    }

    pub fn load_json(&self, data: &[u8]) -> Result<usize, Error> {
        #[derive(Deserialize)]
        struct Canister {
            localities: Option<Vec<String>>,
        }

        #[derive(Deserialize)]
        struct Response {
            canisters: HashMap<String, Canister>,
        }

        let entries =
            json::from_slice::<Response>(data).context("failed to deserialize JSON response")?;

        let denylist = entries
            .canisters
            .into_iter()
            .map(|x| {
                let canister_id = Principal::from_text(x.0)?;
                let country_codes = x.1.localities.unwrap_or_default();
                Ok((canister_id, country_codes))
            })
            .collect::<Result<HashMap<_, _>, Error>>()?;

        let count = denylist.len();
        self.denylist.store(Some(Arc::new(denylist)));

        Ok(count)
    }

    pub async fn run(&self, interval: Duration, meter: &Meter) -> Result<(), Error> {
        // Do not run if no URL was given
        if self.url.is_none() {
            return Ok(());
        }

        let metric_params = MetricParams::new(meter);

        loop {
            let res = self.update().await;

            let lbl = match res {
                Err(e) => {
                    warn!("Denylist update failed: {e}");
                    "fail"
                }
                Ok(v) => {
                    info!("Denylist updated: {} canisters", v);
                    "ok"
                }
            };

            metric_params
                .updates
                .add(1, &[KeyValue::new("result", lbl.to_string())]);

            tokio::time::sleep(interval).await;
        }
    }
}

#[derive(Clone)]
pub struct MetricParams {
    pub updates: Counter<u64>,
}

impl MetricParams {
    pub fn new(meter: &Meter) -> Self {
        Self {
            updates: meter
                .u64_counter("denylist_updates")
                .with_description("Counts updates to the denylist and their results")
                .init(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_update() -> Result<(), Error> {
        use httptest::{matchers::*, responders::*, Expectation, Server};
        use serde_json::json;

        let denylist_json = json!({
          "$schema": "./schema.json",
          "version": "1",
          "canisters": {
            "qoctq-giaaa-aaaaa-aaaea-cai": {"localities": ["CH", "US"]},
            "s6hwe-laaaa-aaaab-qaeba-cai": {"localities": []},
            "2dcn6-oqaaa-aaaai-abvoq-cai": {},
            "g3wsl-eqaaa-aaaan-aaaaa-cai": {},
          }
        });

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/denylist.json"))
                .respond_with(json_encoded(denylist_json)),
        );

        let denylist = Denylist::new(
            Some(server.url_str("/denylist.json")),
            HashSet::from([Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap()]),
        );
        denylist.update().await?;

        // blocked in given regions
        assert!(denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            "CH"
        ));

        assert!(denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            "US"
        ));

        // unblocked in other
        assert!(!denylist.is_blocked(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
            "RU"
        ));

        // blocked regardless of region
        assert!(denylist.is_blocked(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(),
            "foobar"
        ));

        assert!(denylist.is_blocked(
            Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap(),
            "foobar"
        ));

        // allowlisted allowed regardless
        assert!(!denylist.is_blocked(
            Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap(),
            "foo"
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_corrupted() -> Result<(), Error> {
        use httptest::{matchers::*, responders::*, Expectation, Server};
        use serde_json::json;

        let denylist_json = json!({
          "$schema": "./schema.json",
          "version": "1",
          "canisters": {
            "qoctq-giaaa-aaaaa-aaaea-cai": {"localities": ["CH", "US"]},
            "s6hwe-laaaa-aaaab-qaeba-cai": {"localities": []},
            "foobar": {},
          }
        });

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/denylist.json"))
                .respond_with(json_encoded(denylist_json)),
        );

        let denylist = Denylist::new(Some(server.url_str("/denylist.json")), HashSet::new());
        assert!(denylist.update().await.is_err());

        Ok(())
    }
}
