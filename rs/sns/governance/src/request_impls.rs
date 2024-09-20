use ic_nervous_system_clients::Request;

use crate::pb::v1::{
    ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, FailStuckUpgradeInProgressRequest,
    FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
    GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMode,
    GetModeResponse, GetNeuronResponse, GetProposalResponse, GetSnsInitializationParametersRequest,
    GetSnsInitializationParametersResponse, ListNeuronsResponse, ListProposalsResponse,
    ManageNeuronResponse,
};

impl Request for ClaimSwapNeuronsRequest {
    type Response = ClaimSwapNeuronsResponse;
    const METHOD: &'static str = "claim_swap_neurons";
    const UPDATE: bool = true;
}

impl Request for FailStuckUpgradeInProgressRequest {
    type Response = FailStuckUpgradeInProgressResponse;
    const METHOD: &'static str = "fail_stuck_upgrade_in_progress";
    const UPDATE: bool = true;
}

impl Request for GetMaturityModulationRequest {
    type Response = GetMaturityModulationResponse;
    const METHOD: &'static str = "get_maturity_modulation";
    const UPDATE: bool = false;
}

impl Request for GetMetadataRequest {
    type Response = GetMetadataResponse;
    const METHOD: &'static str = "get_metadata";
    const UPDATE: bool = false;
}

impl Request for GetSnsInitializationParametersRequest {
    type Response = GetSnsInitializationParametersResponse;
    const METHOD: &'static str = "get_sns_initialization_parameters";
    const UPDATE: bool = false;
}

impl Request for GetMode {
    type Response = GetModeResponse;
    const METHOD: &'static str = "get_mode";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetNeuron {
    type Response = GetNeuronResponse;
    const METHOD: &'static str = "get_neuron";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetProposal {
    type Response = GetProposalResponse;
    const METHOD: &'static str = "get_proposal";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ListNeurons {
    type Response = ListNeuronsResponse;
    const METHOD: &'static str = "list_neurons";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ListProposals {
    type Response = ListProposalsResponse;
    const METHOD: &'static str = "list_proposals";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ManageNeuron {
    type Response = ManageNeuronResponse;
    const METHOD: &'static str = "manage_neuron";
    const UPDATE: bool = true;
}
