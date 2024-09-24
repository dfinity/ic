//! Retrieve data from the public ICP dashboard REST API
//! https://ic-api.internetcomputer.org/api/v3/swagger
mod responses;
#[cfg(test)]
mod tests;

use crate::dashboard::responses::CanisterInfo;
use candid::Principal;
use std::collections::BTreeSet;

pub struct DashboardClient {
    client: reqwest::Client,
    base_url: String,
}

impl DashboardClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://ic-api.internetcomputer.org/api/v3".to_string(),
        }
    }

    /// List NNS upgrade proposals for a given canister ID.
    ///
    /// The result is sorted by increasing order of proposal ID,
    /// the largest proposal ID corresponding to the latest proposal.
    /// The result may be empty if the canister has no upgrade proposals.
    pub async fn list_canister_upgrade_proposals(&self, canister_id: &Principal) -> BTreeSet<u64> {
        let url = format!("{}/canisters/{}", self.base_url, canister_id);
        let response = self.client.get(&url).send().await.unwrap();
        let body: CanisterInfo = response.json().await.unwrap();
        body.list_upgrade_proposals()
    }
}
