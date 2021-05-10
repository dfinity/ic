use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{CanisterAuthzInfo, MethodAuthzInfo};

#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct RootCanisterInitPayload {
    pub authz_info: CanisterAuthzInfo,
}

pub struct RootCanisterInitPayloadBuilder {
    proposal_submitter_whitelist: Vec<PrincipalId>,
}

#[allow(clippy::new_without_default)]
impl RootCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        RootCanisterInitPayloadBuilder {
            proposal_submitter_whitelist: Vec::new(),
        }
    }

    pub fn add_principal_authorized_to_submit_proposals(
        &mut self,
        principal: PrincipalId,
    ) -> &mut Self {
        self.proposal_submitter_whitelist.push(principal);
        self
    }

    pub fn add_principals_authorized_to_submit_proposals(
        &mut self,
        proposal_submitter_whitelist: Vec<PrincipalId>,
    ) -> &mut Self {
        self.proposal_submitter_whitelist
            .extend(proposal_submitter_whitelist);
        self
    }

    pub fn build(&self) -> RootCanisterInitPayload {
        let authz_info = CanisterAuthzInfo {
            methods_authz: vec![
                MethodAuthzInfo {
                    method_name: "submit_change_nns_canister_proposal".to_string(),
                    principal_ids: self
                        .proposal_submitter_whitelist
                        .iter()
                        .map(|p| p.to_vec())
                        .collect(),
                },
                MethodAuthzInfo {
                    method_name: "change_nns_canister".to_string(),
                    principal_ids: vec![ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()],
                },
                MethodAuthzInfo {
                    method_name: "add_nns_canister".to_string(),
                    principal_ids: vec![ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()],
                },
            ],
        };
        RootCanisterInitPayload { authz_info }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_build_root_init_payload() {
        let init_payload = RootCanisterInitPayloadBuilder::new()
            .add_principal_authorized_to_submit_proposals(PrincipalId::new_anonymous())
            .build();

        assert_eq!(
            init_payload.authz_info,
            CanisterAuthzInfo {
                methods_authz: vec![
                    MethodAuthzInfo {
                        method_name: "submit_change_nns_canister_proposal".to_string(),
                        principal_ids: vec![PrincipalId::new_anonymous().to_vec()],
                    },
                    MethodAuthzInfo {
                        method_name: "change_nns_canister".to_string(),
                        principal_ids: vec![ic_nns_constants::GOVERNANCE_CANISTER_ID
                            .get()
                            .to_vec()],
                    },
                    MethodAuthzInfo {
                        method_name: "add_nns_canister".to_string(),
                        principal_ids: vec![ic_nns_constants::GOVERNANCE_CANISTER_ID
                            .get()
                            .to_vec()],
                    },
                ],
            }
        );
    }
}
