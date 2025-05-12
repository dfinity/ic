use crate::Request;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance_api::{
    GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse, ListNeurons,
    ListNeuronsResponse, ManageNeuronRequest, ManageNeuronResponse, NetworkEconomics, ProposalInfo,
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

pub(crate) struct GetProposalInfo(pub ProposalId);

impl Request for GetProposalInfo {
    fn method(&self) -> &'static str {
        "get_proposal_info"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self.0.id)
    }

    type Response = Option<ProposalInfo>;
}

// @rvem: Dummy type to implement 'Request' for 'get_network_economics_parameters'.
pub(crate) struct GetNetworkEconomicsParameters();

impl Request for GetNetworkEconomicsParameters {
    fn method(&self) -> &'static str {
        "get_network_economics_parameters"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Ok(vec![])
    }

    type Response = NetworkEconomics;
}
