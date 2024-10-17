use ic_nervous_system_clients::Request;

impl Request for crate::pb::v1::GetNeuronsFundAuditInfoRequest {
    type Response = crate::pb::v1::GetNeuronsFundAuditInfoResponse;
    const METHOD: &'static str = "get_neurons_fund_audit_info";
    const UPDATE: bool = false;
}
