use crate::CallCanisters;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::{
    GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse,
};

pub async fn get_neurons_fund_audit_info<C: CallCanisters>(
    agent: &C,
    nns_proposal_id: ProposalId,
) -> Result<GetNeuronsFundAuditInfoResponse, C::Error> {
    let request = GetNeuronsFundAuditInfoRequest {
        nns_proposal_id: Some(nns_proposal_id),
    };
    agent.call(GOVERNANCE_CANISTER_ID, request).await
}
