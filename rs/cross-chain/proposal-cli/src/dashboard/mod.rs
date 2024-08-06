//! Retrieve data from the public ICP dashboard REST API
//! https://ic-api.internetcomputer.org/api/v3/swagger
mod responses;

use crate::dashboard::responses::CanisterInfo;
use candid::Principal;

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

    pub async fn list_canister_upgrade_proposals(&self, canister_id: &Principal) -> Vec<u64> {
        let url = format!("{}/canisters/{}", self.base_url, canister_id);
        let response = self.client.get(&url).send().await.unwrap();
        let body: CanisterInfo = response.json().await.unwrap();
        body.upgrades
            .into_iter()
            .map(|upgrade| upgrade.proposal_id)
            .collect()
    }
}
