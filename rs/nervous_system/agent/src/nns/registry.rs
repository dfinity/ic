use crate::CallCanisters;
use ic_base_types::{CanisterId, SubnetId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use registry_canister::{
    mutations::do_swap_node_in_subnet_directly::SwapNodeInSubnetDirectlyPayload,
    pb::v1::GetSubnetForCanisterRequest,
};

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

pub async fn swap_node_in_subnet_directly<C: CallCanisters>(
    agent: &C,
    payload: SwapNodeInSubnetDirectlyPayload,
) -> Result<(), C::Error> {
    agent.call(REGISTRY_CANISTER_ID, payload).await
}
