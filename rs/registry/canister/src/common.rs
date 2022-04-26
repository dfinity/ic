pub const LOG_PREFIX: &str = "[Registry Canister] ";

#[cfg(test)]
pub mod test_helpers {

    use crate::mutations::common::encode_or_panic;
    use crate::registry::Registry;
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_registry_transport::pb::v1::{
        registry_mutation::Type, RegistryAtomicMutateRequest, RegistryMutation,
    };

    pub fn invariant_compliant_registry() -> Registry {
        let mut registry = Registry::new();
        let mutations = invariant_compliant_mutation();
        registry.maybe_apply_mutation_internal(mutations);
        registry
    }

    pub fn empty_mutation() -> Vec<u8> {
        encode_or_panic(&RegistryAtomicMutateRequest {
            mutations: vec![RegistryMutation {
                mutation_type: Type::Upsert as i32,
                key: "_".into(),
                value: "".into(),
            }],
            preconditions: vec![],
        })
    }
}
