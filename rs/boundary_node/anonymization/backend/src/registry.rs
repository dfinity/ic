use anyhow::anyhow;
use async_trait::async_trait;
use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait List: Sync + Send {
    async fn list(&self) -> Result<Vec<Principal>, ListError>;
}

pub struct Client {
    cid: Principal,
}

impl Client {
    pub fn new(cid: Principal) -> Self {
        Self { cid }
    }
}

#[derive(CandidType)]
pub struct EmptyStruct {}

#[derive(Debug, CandidType, Deserialize)]
pub struct IdRecord {
    id: Option<Principal>,
}

type CallResult<T> = (Result<T, String>,);

#[async_trait]
impl List for Client {
    async fn list(&self) -> Result<Vec<Principal>, ListError> {
        // Fetch IDs
        let r: CallResult<Vec<IdRecord>> =
            ic_cdk::call(self.cid, "get_api_boundary_node_ids", (EmptyStruct {},))
                .await
                .map_err(|err| anyhow!("failed to call canister method: {err:?}"))?;

        // Flatten IDs
        let ids: Vec<Principal> =
            r.0.map_err(|err| anyhow!("canister method returned error: {err}"))?
                .into_iter()
                .filter_map(|r| r.id)
                .collect();

        return Ok(ids);
    }
}
