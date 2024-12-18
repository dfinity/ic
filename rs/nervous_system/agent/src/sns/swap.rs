use ic_base_types::PrincipalId;
use ic_sns_swap::pb::v1::{
    GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest, GetInitResponse,
    ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse, SnsNeuronRecipe,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CallCanisters;

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
}
