use ic_nervous_system_clients::Request;

impl Request for crate::pb::v1::GetDerivedStateRequest {
    type Response = crate::pb::v1::GetDerivedStateResponse;
    const METHOD: &'static str = "get_derived_state";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetInitRequest {
    type Response = crate::pb::v1::GetInitResponse;
    const METHOD: &'static str = "get_init";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ListSnsNeuronRecipesRequest {
    type Response = crate::pb::v1::ListSnsNeuronRecipesResponse;
    const METHOD: &'static str = "list_sns_neuron_recipes";
    const UPDATE: bool = false;
}
