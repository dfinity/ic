use anyhow::{anyhow, Result};
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use ic_sns_wasm::pb::v1::{
    GetWasmRequest, GetWasmResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse,
    ListUpgradeStepsRequest, ListUpgradeStepsResponse,
};
use serde::de::DeserializeOwned;

pub(crate) trait Request: CandidType {
    type Response: CandidType + DeserializeOwned;
    const METHOD: &'static str;

    /// Indicates whether the request should be called as a query or an update
    const UPDATE: bool;
}

pub(crate) async fn call<R: Request>(
    agent: &Agent,
    canister_id: impl Into<Principal>,
    request: R,
) -> Result<R::Response> {
    let canister_id = canister_id.into();
    let request_bytes = Encode!(&request)?;
    let response = if R::UPDATE {
        let request = agent
            .update(&canister_id, R::METHOD)
            .with_arg(request_bytes)
            .call()
            .await?;
        match request {
            ic_agent::agent::CallResponse::Response(response) => response,
            ic_agent::agent::CallResponse::Poll(request_id) => {
                println!("Waiting for the request to {} to complete...", R::METHOD);
                agent.wait(&request_id, canister_id).await?
            }
        }
    } else {
        agent
            .query(&canister_id, R::METHOD)
            .with_arg(request_bytes)
            .call()
            .await?
    };

    Decode!(response.as_slice(), R::Response).map_err(|e| anyhow!(e))
}

// Implementations

impl Request for ListDeployedSnsesRequest {
    type Response = ListDeployedSnsesResponse;
    const METHOD: &'static str = "list_deployed_snses";
    const UPDATE: bool = false;
}

impl Request for GetWasmRequest {
    type Response = GetWasmResponse;
    const METHOD: &'static str = "get_wasm";
    const UPDATE: bool = false;
}

impl Request for ListUpgradeStepsRequest {
    type Response = ListUpgradeStepsResponse;
    const METHOD: &'static str = "list_upgrade_steps";
    const UPDATE: bool = false;
}
