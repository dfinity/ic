use crate::registry::Registry;
use test_registry_builder::builder::CompliantRegistryMutations;

pub struct TestableRegistry {
    registry: Registry,
    compliant_mutations: CompliantRegistryMutations,
}

impl Registry {
    fn from_compliant_mutations(compliant_mutations: &CompliantRegistryMutations) -> Self {
        let mutations = compliant_mutations.mutations();

        let mut registry = Registry::new();
        // Ensures that the mutations are invariant compliant
        registry.maybe_apply_mutation_internal(mutations);

        registry
    }
}

impl From<CompliantRegistryMutations> for TestableRegistry {
    fn from(value: CompliantRegistryMutations) -> Self {
        let registry = Registry::from_compliant_mutations(&value);

        Self {
            registry,
            compliant_mutations: value,
        }
    }
}

impl From<CompliantRegistryMutations> for Registry {
    fn from(value: CompliantRegistryMutations) -> Self {
        Registry::from_compliant_mutations(&value)
    }
}

impl From<&CompliantRegistryMutations> for Registry {
    fn from(value: &CompliantRegistryMutations) -> Self {
        Registry::from_compliant_mutations(value)
    }
}

impl TestableRegistry {
    pub fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Registry) -> R,
    {
        f(&self.registry)
    }

    pub fn run_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Registry) -> R,
    {
        f(&mut self.registry)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    pub fn compliant_mutations(&self) -> &CompliantRegistryMutations {
        &self.compliant_mutations
    }
}

mod tests {
    use ic_protobuf::registry::{
        dc::v1::DataCenterRecord, node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord,
    };
    use ic_registry_keys::{
        make_data_center_record_key, make_node_operator_record_key, make_node_record_key,
    };
    use ic_types::PrincipalId;
    use prost::Message;
    use test_registry_builder::builder::CompliantRegistryMutationsBuilder;

    use crate::common::compliant_registry_helpers::TestableRegistry;

    #[test]
    fn ensure_registry_compliant() {
        let mutations = CompliantRegistryMutationsBuilder::default()
            .with_operator("operator", "dc", "provider")
            .with_node("node", "operator", None)
            .build();

        let testable_registry = TestableRegistry::from(mutations);

        let latest_version = testable_registry.registry().latest_version();

        // Ensure SubnetListRecord
        let subnet_list_record = testable_registry.registry().get_subnet_list_record();
        assert!(
            subnet_list_record.subnets.len() == 1,
            "Expected only NNS to be in this test, but got {} more",
            subnet_list_record.subnets.len()
        );

        // Ensure operator
        let operator_id = testable_registry
            .compliant_mutations()
            .operator_id("operator");

        let operator = testable_registry
            .registry()
            .get_high_capacity(
                make_node_operator_record_key(operator_id).as_bytes(),
                latest_version,
            )
            .expect("Expected to find the configured node operator");

        let content = match operator.content.clone().unwrap() {
            ic_registry_transport::pb::v1::high_capacity_registry_value::Content::Value(items) => {
                items
            }
            c => panic!("Expected to receive content of type `Value`, got {c:?}"),
        };
        let operator = NodeOperatorRecord::decode(content.as_slice()).unwrap();

        // Ensure operator is related to the correct node provider
        let provider = testable_registry
            .compliant_mutations()
            .provider_id("provider");
        let provider_from_reg = PrincipalId::try_from(operator.node_provider_principal_id).unwrap();

        assert_eq!(provider, provider_from_reg, "Expected the provider id related to operator to be equal in compliant mutations and registry");

        // Ensure that the data center exists and that the node operator is linked to it
        let dc = testable_registry
            .registry()
            .get_high_capacity(make_data_center_record_key("dc").as_bytes(), latest_version)
            .expect("Expected to find the configured data center");

        let content = match dc.content.clone().unwrap() {
            ic_registry_transport::pb::v1::high_capacity_registry_value::Content::Value(items) => {
                items
            }
            c => panic!("Expected to receive content of type `Value`, got {c:?}"),
        };
        let dc = DataCenterRecord::decode(content.as_slice()).unwrap();

        assert_eq!(
            operator.dc_id, dc.id,
            "Expected data center from registry to be the same as the one in compliant mutations"
        );

        // Ensure that the node is related to the operator
        let node_id = testable_registry.compliant_mutations().node_id("node");

        let node = testable_registry
            .registry()
            .get_high_capacity(make_node_record_key(node_id).as_bytes(), latest_version)
            .expect("Expected to find the configured node");

        let content = match node.content.clone().unwrap() {
            ic_registry_transport::pb::v1::high_capacity_registry_value::Content::Value(items) => {
                items
            }
            c => panic!("Expected to receive content of type `Value`, got {c:?}"),
        };

        let node = NodeRecord::decode(content.as_slice()).unwrap();
        let reg_node_operator_id = PrincipalId::try_from(node.node_operator_id).unwrap();

        assert_eq!(
            reg_node_operator_id, operator_id,
            "Expected the node to be realted to the configured operator"
        );
    }
}
