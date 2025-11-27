//! Retrieve data from the public ICP dashboard REST API
//! https://ic-api.internetcomputer.org/api/v3/swagger
pub(crate) mod responses;

#[cfg(test)]
mod tests;

use crate::dashboard::responses::{CanisterInfo, ProposalInfo};
use candid::Principal;
use reqwest::StatusCode;
use std::collections::BTreeSet;
use std::time::Duration;

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

    pub async fn list_canister_upgrade_proposals_batch(
        &self,
        canister_ids: &[Principal],
    ) -> Vec<BTreeSet<u64>> {
        let mut fut = Vec::with_capacity(canister_ids.len());
        for canister_id in canister_ids {
            fut.push(self.list_canister_upgrade_proposals(canister_id));
        }
        futures::future::join_all(fut).await
    }

    pub async fn retrieve_proposal_batch(&self, proposal_ids: &[u64]) -> Vec<ProposalInfo> {
        let fut = proposal_ids.iter().map(|id| self.retrieve_proposal(id));
        futures::future::join_all(fut).await
    }

    /// Retrieve a given proposal by ID.
    ///
    /// When the proposal was recently submitted, the dashboard API may need some time
    /// to catch up, so that retries are maybe necessary.
    pub async fn retrieve_proposal(&self, proposal_id: &u64) -> ProposalInfo {
        let url = format!("{}/proposals/{}", self.base_url, proposal_id);
        let num_retries = 5;
        let sleep_duration = Duration::from_secs(5);
        for i in 1..=num_retries {
            let response = self.client.get(&url).send().await.unwrap();
            match response.status() {
                StatusCode::OK => {
                    let proposal: ProposalInfo = response.json().await.unwrap();
                    assert_eq!(&proposal.proposal_id, proposal_id);
                    return proposal;
                }
                StatusCode::NOT_FOUND => {
                    let delay = sleep_duration * i;
                    println!(
                        "Proposal {proposal_id} not found, retrying in {}s",
                        delay.as_secs()
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                error_status => {
                    panic!(
                        "Error when retrieving proposal {proposal_id}. Received response {response:?} with status code {error_status}"
                    )
                }
            }
        }
        panic!("Unable to retrieve proposal {proposal_id} after {num_retries} attempts.");
    }
}
