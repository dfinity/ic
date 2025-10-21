use ic_sns_governance_api::pb::v1::{
    AdvanceTargetVersionRequest, AdvanceTargetVersionResponse, ClaimSwapNeuronsRequest,
    ClaimSwapNeuronsResponse, FailStuckUpgradeInProgressRequest,
    FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
    GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMode,
    GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
    GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
    GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
    GetUpgradeJournalRequest, GetUpgradeJournalResponse, ListNeurons, ListNeuronsResponse,
    ListProposals, ListProposalsResponse, ManageNeuron, ManageNeuronResponse,
    topics::{ListTopicsRequest, ListTopicsResponse},
};

use crate::Request;

impl Request for ClaimSwapNeuronsRequest {
    fn method(&self) -> &'static str {
        "claim_swap_neurons"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ClaimSwapNeuronsResponse;
}

impl Request for FailStuckUpgradeInProgressRequest {
    fn method(&self) -> &'static str {
        "fail_stuck_upgrade_in_progress"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = FailStuckUpgradeInProgressResponse;
}

impl Request for GetMaturityModulationRequest {
    fn method(&self) -> &'static str {
        "get_maturity_modulation"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetMaturityModulationResponse;
}

impl Request for GetMetadataRequest {
    fn method(&self) -> &'static str {
        "get_metadata"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetMetadataResponse;
}

impl Request for GetSnsInitializationParametersRequest {
    fn method(&self) -> &'static str {
        "get_sns_initialization_parameters"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetSnsInitializationParametersResponse;
}

impl Request for GetMode {
    fn method(&self) -> &'static str {
        "get_mode"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetModeResponse;
}

impl Request for GetNeuron {
    fn method(&self) -> &'static str {
        "get_neuron"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetNeuronResponse;
}

impl Request for GetProposal {
    fn method(&self) -> &'static str {
        "get_proposal"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetProposalResponse;
}

impl Request for ListNeurons {
    fn method(&self) -> &'static str {
        "list_neurons"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListNeuronsResponse;
}

impl Request for ListProposals {
    fn method(&self) -> &'static str {
        "list_proposals"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListProposalsResponse;
}

impl Request for ManageNeuron {
    fn method(&self) -> &'static str {
        "manage_neuron"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ManageNeuronResponse;
}

impl Request for GetRunningSnsVersionRequest {
    fn method(&self) -> &'static str {
        "get_running_sns_version"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetRunningSnsVersionResponse;
}

impl Request for GetUpgradeJournalRequest {
    fn method(&self) -> &'static str {
        "get_upgrade_journal"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetUpgradeJournalResponse;
}

impl Request for AdvanceTargetVersionRequest {
    fn method(&self) -> &'static str {
        "advance_target_version"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = AdvanceTargetVersionResponse;
}

impl Request for ListTopicsRequest {
    fn method(&self) -> &'static str {
        "list_topics"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListTopicsResponse;
}
