use ic_nervous_system_clients::Request;

impl Request for crate::pb::v1::ClaimSwapNeuronsRequest {
    type Response = crate::pb::v1::ClaimSwapNeuronsResponse;
    const METHOD: &'static str = "claim_swap_neurons";
    const UPDATE: bool = true;
}

impl Request for crate::pb::v1::FailStuckUpgradeInProgressRequest {
    type Response = crate::pb::v1::FailStuckUpgradeInProgressResponse;
    const METHOD: &'static str = "fail_stuck_upgrade_in_progress";
    const UPDATE: bool = true;
}

impl Request for crate::pb::v1::GetMaturityModulationRequest {
    type Response = crate::pb::v1::GetMaturityModulationResponse;
    const METHOD: &'static str = "get_maturity_modulation";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetMetadataRequest {
    type Response = crate::pb::v1::GetMetadataResponse;
    const METHOD: &'static str = "get_metadata";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetSnsInitializationParametersRequest {
    type Response = crate::pb::v1::GetSnsInitializationParametersResponse;
    const METHOD: &'static str = "get_sns_initialization_parameters";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetMode {
    type Response = crate::pb::v1::GetModeResponse;
    const METHOD: &'static str = "get_mode";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetNeuron {
    type Response = crate::pb::v1::GetNeuronResponse;
    const METHOD: &'static str = "get_neuron";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetProposal {
    type Response = crate::pb::v1::GetProposalResponse;
    const METHOD: &'static str = "get_proposal";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ListNeurons {
    type Response = crate::pb::v1::ListNeuronsResponse;
    const METHOD: &'static str = "list_neurons";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ListProposals {
    type Response = crate::pb::v1::ListProposalsResponse;
    const METHOD: &'static str = "list_proposals";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::ManageNeuron {
    type Response = crate::pb::v1::ManageNeuronResponse;
    const METHOD: &'static str = "manage_neuron";
    const UPDATE: bool = true;
}

impl Request for crate::pb::v1::GetRunningSnsVersionRequest {
    type Response = crate::pb::v1::GetRunningSnsVersionResponse;
    const METHOD: &'static str = "get_running_sns_version";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::GetUpgradeJournalRequest {
    type Response = crate::pb::v1::GetUpgradeJournalResponse;
    const METHOD: &'static str = "get_upgrade_journal";
    const UPDATE: bool = false;
}

impl Request for crate::pb::v1::AdvanceTargetVersionRequest {
    type Response = crate::pb::v1::AdvanceTargetVersionResponse;
    const METHOD: &'static str = "advance_target_version";
    const UPDATE: bool = true;
}
