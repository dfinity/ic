use anyhow::anyhow;
use async_trait::async_trait;
use candid::{CandidType, Principal};
use prometheus::labels;
use serde::Deserialize;

use crate::{WithLogs, WithMetrics};

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

#[async_trait]
impl<T: List> List for WithLogs<T> {
    async fn list(&self) -> Result<Vec<Principal>, ListError> {
        let out = self.0.list().await;

        let status = match &out {
            Ok(_) => "ok",
            Err(err) => match err {
                ListError::UnexpectedError(_) => "fail",
            },
        };

        ic_cdk::println!(
            "action = '{}', status = {}, error = {:?}",
            "list",
            status,
            out.as_ref().err()
        );

        out
    }
}

#[async_trait]
impl<T: List> List for WithMetrics<T> {
    async fn list(&self) -> Result<Vec<Principal>, ListError> {
        let out = self.0.list().await;

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            ListError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}
