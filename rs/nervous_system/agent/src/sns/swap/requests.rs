use ic_sns_swap::pb::v1::{
    GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest, GetInitResponse,
    ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse,
};

use crate::Request;

impl Request for GetDerivedStateRequest {
    fn method(&self) -> &'static str {
        "get_derived_state"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetDerivedStateResponse;
}

impl Request for GetInitRequest {
    fn method(&self) -> &'static str {
        "get_init"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetInitResponse;
}

impl Request for ListSnsNeuronRecipesRequest {
    fn method(&self) -> &'static str {
        "list_sns_neuron_recipes"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListSnsNeuronRecipesResponse;
}
