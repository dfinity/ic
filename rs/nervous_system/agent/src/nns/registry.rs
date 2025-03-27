use crate::CallCanisters;
use ic_base_types::{CanisterId, SubnetId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_canister_api::{Chunk, GetChunkRequest};
use registry_canister::pb::v1::GetSubnetForCanisterRequest;
use std::fmt::Display;

pub mod requests;

pub async fn get_subnet_for_canister<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
) -> Result<SubnetId, C::Error> {
    let request = GetSubnetForCanisterRequest {
        principal: Some(canister_id.get()),
    };
    let result = agent
        .call(REGISTRY_CANISTER_ID, request)
        .await?
        .unwrap_or_else(|err| {
            panic!(
                "Cannot get subnet ID for canister {}: {err}",
                canister_id.get()
            )
        });

    let subnet_id = result
        .subnet_id
        .expect("SubnetForCanister.subnet_id was not specified.");

    Ok(SubnetId::from(subnet_id))
}

/// Returns the concatenation of a bunch of chunks from Registry.
///
/// Each chunk is fetched via Registry's get_chunk method.
pub async fn get_monolithic_blob<C: CallCanisters>(
    agent: &C,
    canister_id: CanisterId,
    chunk_content_sha256s: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    fn new_err(cause: impl Display) -> String {
        format!("Failed to get monolithic registry blob: {}", cause)
    }

    let mut result = vec![];

    // TODO: This could be done in parallel, but this is simpler.
    for content_sha256 in chunk_content_sha256s {
        let content_sha256 = Some(content_sha256.to_vec());
        let Chunk { content } = agent
            .call(canister_id, GetChunkRequest { content_sha256 })
            .await
            .map_err(new_err)?
            .map_err(new_err)?;

        let mut content = content.ok_or_else(|| new_err("get_chunk response has no content"))?;

        result.append(&mut content);
    }

    Ok(result)
}
