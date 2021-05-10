use crate::pb::v1::{CanisterAuthzInfo, MethodAuthzInfo};
use ic_base_types::PrincipalId;

#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct LifelineCanisterInitPayload {
    pub authz_info: CanisterAuthzInfo,
}

pub struct LifelineCanisterInitPayloadBuilder {
    principals: Vec<PrincipalId>,
}

#[allow(clippy::new_without_default)]
impl LifelineCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        LifelineCanisterInitPayloadBuilder {
            principals: Vec::new(),
        }
    }

    pub fn add_principal_authorized_to_submit_proposals(
        &mut self,
        principal: PrincipalId,
    ) -> &mut Self {
        self.principals.push(principal);
        self
    }

    pub fn build(&self) -> LifelineCanisterInitPayload {
        let authz_info = CanisterAuthzInfo {
            methods_authz: vec![MethodAuthzInfo {
                method_name: "submit_upgrade_root_proposal".to_string(),
                principal_ids: self.principals.iter().map(|p| p.to_vec()).collect(),
            }],
        };
        LifelineCanisterInitPayload { authz_info }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_build_lifeline_init_payload() {
        let init_payload = LifelineCanisterInitPayloadBuilder::new()
            .add_principal_authorized_to_submit_proposals(PrincipalId::new_anonymous())
            .build();

        assert_eq!(
            init_payload.authz_info,
            CanisterAuthzInfo {
                methods_authz: vec![MethodAuthzInfo {
                    method_name: "submit_upgrade_root_proposal".to_string(),
                    principal_ids: vec![PrincipalId::new_anonymous().to_vec()],
                },],
            }
        );
    }
}
