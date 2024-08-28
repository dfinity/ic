pub mod nns;

use anyhow::{anyhow, Result};
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use ic_nervous_system_clients::Request;

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
