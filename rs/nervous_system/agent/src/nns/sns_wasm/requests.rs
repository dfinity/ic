use crate::Request;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse,
    GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetProposalIdThatAddedWasmRequest,
    GetProposalIdThatAddedWasmResponse, GetSnsSubnetIdsRequest, GetSnsSubnetIdsResponse,
    GetWasmMetadataRequest, GetWasmMetadataResponse, GetWasmRequest, GetWasmResponse,
    InsertUpgradePathEntriesRequest, InsertUpgradePathEntriesResponse, ListDeployedSnsesRequest,
    ListDeployedSnsesResponse, ListUpgradeStepsRequest, ListUpgradeStepsResponse,
    UpdateSnsSubnetListRequest, UpdateSnsSubnetListResponse,
};

impl Request for ListDeployedSnsesRequest {
    fn method(&self) -> &'static str {
        "list_deployed_snses"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListDeployedSnsesResponse;
}

impl Request for GetWasmRequest {
    fn method(&self) -> &'static str {
        "get_wasm"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetWasmResponse;
}

impl Request for ListUpgradeStepsRequest {
    fn method(&self) -> &'static str {
        "list_upgrade_steps"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListUpgradeStepsResponse;
}

impl Request for AddWasmRequest {
    fn method(&self) -> &'static str {
        "add_wasm"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = AddWasmResponse;
}

impl Request for DeployNewSnsRequest {
    fn method(&self) -> &'static str {
        "deploy_new_sns"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = DeployNewSnsResponse;
}

impl Request for GetDeployedSnsByProposalIdRequest {
    fn method(&self) -> &'static str {
        "get_deployed_sns_by_proposal_id"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetDeployedSnsByProposalIdResponse;
}

impl Request for GetNextSnsVersionRequest {
    fn method(&self) -> &'static str {
        "get_next_sns_version"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetNextSnsVersionResponse;
}

impl Request for GetProposalIdThatAddedWasmRequest {
    fn method(&self) -> &'static str {
        "get_proposal_id_that_added_wasm"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetProposalIdThatAddedWasmResponse;
}

impl Request for GetWasmMetadataRequest {
    fn method(&self) -> &'static str {
        "get_wasm_metadata"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetWasmMetadataResponse;
}

impl Request for InsertUpgradePathEntriesRequest {
    fn method(&self) -> &'static str {
        "insert_upgrade_path_entries"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }
    type Response = InsertUpgradePathEntriesResponse;
}

impl Request for UpdateSnsSubnetListRequest {
    fn method(&self) -> &'static str {
        "update_sns_subnet_list"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = UpdateSnsSubnetListResponse;
}

impl Request for GetSnsSubnetIdsRequest {
    fn method(&self) -> &'static str {
        "get_sns_subnet_ids"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetSnsSubnetIdsResponse;
}
