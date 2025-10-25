use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_types::{PrincipalId, SubnetId};
use std::{collections::BTreeSet, fmt};

#[derive(Clone, Debug, Default, candid::CandidType, candid::Deserialize)]
pub struct RegistryCanisterInitPayload {
    pub mutations: Vec<RegistryAtomicMutateRequest>,

    // IC-1869 (Node swaps) flags that are used
    // integration tests and will be removed as
    // a part of Phase 3 of the rollout.
    //
    // Note: in `src/flags.rs` are the default
    // values for all of these arguments and these
    // shouldn't be provided when deploying to
    // mainnet and should be left behind the
    // test configuration.
    //
    // Note: these flags are temporary and will
    // go away once the feature is fully deployed.
    pub is_swapping_feature_enabled: Option<bool>,
    pub swapping_whitelisted_callers: Option<Vec<PrincipalId>>,
    pub swapping_enabled_subnets: Option<Vec<SubnetId>>,
}

impl fmt::Display for RegistryCanisterInitPayload {
    /// Produces a string that partly represent the content of this init
    /// payload.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mutations: [{}]",
            self.mutations
                .iter()
                .map(RegistryAtomicMutateRequest::to_string)
                .collect::<Vec::<String>>()
                .join(", ")
        )
    }
}

pub struct RegistryCanisterInitPayloadBuilder {
    initial_mutations: Vec<RegistryAtomicMutateRequest>,
    // Explanation for these fields can be found in `RegistryCanisterInitPayload`.
    is_swapping_feature_enabled: bool,
    swapping_whitelisted_callers: BTreeSet<PrincipalId>,
    swapping_enabled_subnets: BTreeSet<SubnetId>,
}

#[allow(clippy::new_without_default)]
impl RegistryCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            initial_mutations: Vec::new(),
            is_swapping_feature_enabled: false,
            swapping_whitelisted_callers: BTreeSet::new(),
            swapping_enabled_subnets: BTreeSet::new(),
        }
    }

    pub fn push_init_mutate_request(
        &mut self,
        mutate_req: RegistryAtomicMutateRequest,
    ) -> &mut Self {
        self.initial_mutations.push(mutate_req);
        self
    }

    pub fn build(&self) -> RegistryCanisterInitPayload {
        RegistryCanisterInitPayload {
            mutations: self.initial_mutations.clone(),
            is_swapping_feature_enabled: Some(self.is_swapping_feature_enabled),
            swapping_whitelisted_callers: Some(
                self.swapping_whitelisted_callers
                    .clone()
                    .into_iter()
                    .collect(),
            ),
            swapping_enabled_subnets: Some(
                self.swapping_enabled_subnets.clone().into_iter().collect(),
            ),
        }
    }

    pub fn enable_swapping_feature_globally(&mut self) -> &mut Self {
        self.is_swapping_feature_enabled = true;
        self
    }

    pub fn enable_swapping_feature_for_subnet(&mut self, subnet_id: SubnetId) -> &mut Self {
        self.swapping_enabled_subnets.insert(subnet_id);
        self
    }

    pub fn whitelist_swapping_feature_caller(&mut self, caller: PrincipalId) -> &mut Self {
        self.swapping_whitelisted_callers.insert(caller);
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_default_payload_has_no_mutations() {
        let default = RegistryCanisterInitPayloadBuilder::new().build();
        assert_eq!(default.mutations, vec![]);
    }
}
