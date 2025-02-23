use crate::Request;
use ic_nns_governance_api::pb::v1::{
    GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse, ManageNeuronRequest,
    ManageNeuronResponse,
};

impl Request for GetNeuronsFundAuditInfoRequest {
    fn method(&self) -> &'static str {
        "get_neurons_fund_audit_info"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetNeuronsFundAuditInfoResponse;
}

impl Request for ManageNeuronRequest {
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
