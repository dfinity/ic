use ic_nervous_system_clients::Request;

use crate::pb::v1::{
    AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse,
    GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetProposalIdThatAddedWasmRequest,
    GetProposalIdThatAddedWasmResponse, GetWasmMetadataRequest, GetWasmMetadataResponse,
    GetWasmRequest, GetWasmResponse, InsertUpgradePathEntriesRequest,
    InsertUpgradePathEntriesResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse,
    ListUpgradeStepsRequest, ListUpgradeStepsResponse, UpdateSnsSubnetListRequest,
    UpdateSnsSubnetListResponse,
};

impl Request for ListDeployedSnsesRequest {
    type Response = ListDeployedSnsesResponse;
    const METHOD: &'static str = "list_deployed_snses";
    const UPDATE: bool = false;
}

impl Request for GetWasmRequest {
    type Response = GetWasmResponse;
    const METHOD: &'static str = "get_wasm";
    const UPDATE: bool = false;
}

impl Request for ListUpgradeStepsRequest {
    type Response = ListUpgradeStepsResponse;
    const METHOD: &'static str = "list_upgrade_steps";
    const UPDATE: bool = false;
}

impl Request for AddWasmRequest {
    type Response = AddWasmResponse;
    const METHOD: &'static str = "add_wasm";
    const UPDATE: bool = true;
}

impl Request for DeployNewSnsRequest {
    type Response = DeployNewSnsResponse;
    const METHOD: &'static str = "deploy_new_sns";
    const UPDATE: bool = true;
}

impl Request for GetDeployedSnsByProposalIdRequest {
    type Response = GetDeployedSnsByProposalIdResponse;
    const METHOD: &'static str = "get_deployed_sns_by_proposal_id";
    const UPDATE: bool = false;
}

impl Request for GetNextSnsVersionRequest {
    type Response = GetNextSnsVersionResponse;
    const METHOD: &'static str = "get_next_sns_version";
    const UPDATE: bool = false;
}

impl Request for GetProposalIdThatAddedWasmRequest {
    type Response = GetProposalIdThatAddedWasmResponse;
    const METHOD: &'static str = "get_proposal_id_that_added_wasm";
    const UPDATE: bool = false;
}

impl Request for GetWasmMetadataRequest {
    type Response = GetWasmMetadataResponse;
    const METHOD: &'static str = "get_wasm_metadata";
    const UPDATE: bool = false;
}

impl Request for InsertUpgradePathEntriesRequest {
    type Response = InsertUpgradePathEntriesResponse;
    const METHOD: &'static str = "insert_upgrade_path_entries";
    const UPDATE: bool = true;
}

impl Request for UpdateSnsSubnetListRequest {
    type Response = UpdateSnsSubnetListResponse;
    const METHOD: &'static str = "update_sns_subnet_list";
    const UPDATE: bool = true;
}
