use crate::CallCanisters;
use ic_base_types::PrincipalId;
use ic_sns_swap::pb::v1::{
    ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapRequest, FinalizeSwapResponse,
    GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse, GetBuyerStateRequest,
    GetBuyerStateResponse, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
    GetInitResponse, GetLifecycleRequest, GetLifecycleResponse, GetOpenTicketRequest,
    GetOpenTicketResponse, ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse,
    NewSaleTicketRequest, NewSaleTicketResponse, RefreshBuyerTokensRequest,
    RefreshBuyerTokensResponse, SnsNeuronRecipe,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod requests;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct SwapCanister {
    pub canister_id: PrincipalId,
}

#[derive(Debug, Error)]
pub enum ListAllSnsNeuronRecipesError<CallCanistersError: std::error::Error + 'static> {
    #[error(transparent)]
    CanisterCallError(#[from] CallCanistersError),
    #[error("There seem to be too many neuron recipes ({0}).")]
    TooManyRecipes(u64),
}

impl SwapCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }

    pub async fn get_derived_state<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetDerivedStateResponse, C::Error> {
        agent
            .call(self.canister_id, GetDerivedStateRequest {})
            .await
    }

    pub async fn get_init<C: CallCanisters>(&self, agent: &C) -> Result<GetInitResponse, C::Error> {
        agent.call(self.canister_id, GetInitRequest {}).await
    }

    pub async fn list_sns_neuron_recipes<C: CallCanisters>(
        &self,
        agent: &C,
        limit: u32,
        offset: u64,
    ) -> Result<ListSnsNeuronRecipesResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                ListSnsNeuronRecipesRequest {
                    limit: Some(limit),
                    offset: Some(offset),
                },
            )
            .await
    }

    pub async fn list_all_sns_neuron_recipes<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<Vec<SnsNeuronRecipe>, ListAllSnsNeuronRecipesError<C::Error>> {
        let mut sns_neuron_recipes: Vec<SnsNeuronRecipe> = vec![];
        let batch_size = 10_000_u64;
        let num_calls = 100_u64;
        for i in 0..num_calls {
            let new_sns_neuron_recipes = self
                .list_sns_neuron_recipes(agent, batch_size as u32, batch_size * i)
                .await
                .map_err(ListAllSnsNeuronRecipesError::CanisterCallError)?;
            if new_sns_neuron_recipes.sns_neuron_recipes.is_empty() {
                return Ok(sns_neuron_recipes);
            } else {
                sns_neuron_recipes.extend(new_sns_neuron_recipes.sns_neuron_recipes.into_iter())
            }
        }
        Err(ListAllSnsNeuronRecipesError::TooManyRecipes(
            batch_size * num_calls,
        ))
    }

    pub async fn new_sale_ticket<C: CallCanisters>(
        &self,
        agent: &C,
        amount_icp_e8s: u64,
        subaccount: Option<Vec<u8>>,
    ) -> Result<NewSaleTicketResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                NewSaleTicketRequest {
                    amount_icp_e8s,
                    subaccount,
                },
            )
            .await
    }

    pub async fn refresh_buyer_tokens<C: CallCanisters>(
        &self,
        agent: &C,
        buyer: PrincipalId,
        confirmation_text: Option<String>,
    ) -> Result<RefreshBuyerTokensResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                RefreshBuyerTokensRequest {
                    buyer: buyer.to_string(),
                    confirmation_text,
                },
            )
            .await
    }

    pub async fn get_buyer_state<C: CallCanisters>(
        &self,
        agent: &C,
        principal_id: PrincipalId,
    ) -> Result<GetBuyerStateResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                GetBuyerStateRequest {
                    principal_id: Some(principal_id),
                },
            )
            .await
    }

    pub async fn get_open_ticket<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetOpenTicketResponse, C::Error> {
        agent.call(self.canister_id, GetOpenTicketRequest {}).await
    }

    pub async fn error_refund_icp<C: CallCanisters>(
        &self,
        agent: &C,
        source_principal_id: PrincipalId,
    ) -> Result<ErrorRefundIcpResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                ErrorRefundIcpRequest {
                    source_principal_id: Some(source_principal_id),
                },
            )
            .await
    }

    pub async fn get_lifecycle<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetLifecycleResponse, C::Error> {
        agent.call(self.canister_id, GetLifecycleRequest {}).await
    }

    pub async fn finalize_swap<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<FinalizeSwapResponse, C::Error> {
        agent.call(self.canister_id, FinalizeSwapRequest {}).await
    }

    pub async fn get_auto_finalization_status<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetAutoFinalizationStatusResponse, C::Error> {
        agent
            .call(self.canister_id, GetAutoFinalizationStatusRequest {})
            .await
    }
}
