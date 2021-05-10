use std::fmt;

use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{CanisterAuthzInfo, MethodAuthzInfo};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;

#[derive(candid::CandidType, candid::Deserialize, Clone, Debug)]
pub struct RegistryCanisterInitPayload {
    pub authz_info: CanisterAuthzInfo,
    pub mutations: Vec<RegistryAtomicMutateRequest>,
}

impl Default for RegistryCanisterInitPayload {
    fn default() -> Self {
        RegistryCanisterInitPayload {
            authz_info: CanisterAuthzInfo {
                methods_authz: vec![MethodAuthzInfo {
                    method_name: "atomic_mutate".to_string(),
                    principal_ids: vec![ic_nns_constants::ROOT_CANISTER_ID.get().to_vec()],
                }],
            },
            mutations: vec![],
        }
    }
}

impl fmt::Display for RegistryCanisterInitPayload {
    /// Produces a string that partly represent the content of this init
    /// payload.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "authz_info: {:?}. mutations: [{}]",
            self.authz_info,
            self.mutations
                .iter()
                .map(RegistryAtomicMutateRequest::to_string)
                .collect::<Vec::<String>>()
                .join(", ")
        )
    }
}

pub struct RegistryCanisterInitPayloadBuilder {
    principals_allowed_to_mutate: Vec<PrincipalId>,
    initial_mutations: Vec<RegistryAtomicMutateRequest>,
}

#[allow(clippy::new_without_default)]
impl RegistryCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            principals_allowed_to_mutate: Vec::new(),
            initial_mutations: Vec::new(),
        }
    }

    pub fn allow_principal_to_mutate(&mut self, principal: PrincipalId) -> &mut Self {
        self.principals_allowed_to_mutate.push(principal);
        self
    }

    pub fn push_init_mutate_request(
        &mut self,
        mutate_req: RegistryAtomicMutateRequest,
    ) -> &mut Self {
        self.initial_mutations.push(mutate_req);
        self
    }

    pub fn build(&self) -> RegistryCanisterInitPayload {
        let principals: Vec<Vec<u8>> = self
            .principals_allowed_to_mutate
            .iter()
            .map(|p| p.to_vec())
            .collect();
        let mut rcip = RegistryCanisterInitPayload::default();
        rcip.authz_info.methods_authz = rcip
            .authz_info
            .methods_authz
            .iter_mut()
            .map(|authz| {
                authz.principal_ids.extend_from_slice(&principals);
                authz.clone()
            })
            .collect();
        rcip.mutations.extend(self.initial_mutations.clone());
        rcip
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use maplit::btreemap;
    use std::collections::BTreeMap;

    #[test]
    fn test_default_payload_has_no_mutations() {
        let default = RegistryCanisterInitPayloadBuilder::new().build();
        assert_eq!(default.mutations, vec![]);
    }

    #[test]
    fn test_can_build_registry_init_payload() {
        let init_payload = RegistryCanisterInitPayloadBuilder::new().build();

        assert_eq!(
            init_payload
                .authz_info
                .methods_authz
                .iter()
                .map(|i| (i.method_name.as_str(), i.principal_ids.clone()))
                .collect::<BTreeMap::<_, _>>(),
            btreemap! {
            "atomic_mutate" => vec![
                ic_nns_constants::ROOT_CANISTER_ID.get().to_vec(),
            ],}
        );
    }
}
