use std::collections::{BTreeMap, BTreeSet};

use ic_nns_test_utils::registry::{
    create_subnet_threshold_signing_pubkey_and_cup_mutations, invariant_compliant_mutation,
};
use ic_protobuf::registry::{
    dc::v1::DataCenterRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetType},
};
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
use ic_types::{NodeId, PrincipalId, SubnetId};

use crate::{
    copied_utils::{
        get_invariant_compliant_subnet_record, prepare_mutations_with_nodes_and_operator_id,
    },
    model::{TestNode, TestNodeOperator},
    operator, provider, subnet,
};
use prost::Message;

#[derive(Debug)]
struct NodeHint {
    operator_id: PrincipalId,
    subnet: Option<SubnetId>,
}

#[derive(Default)]
pub struct CompliantRegistryMutationsBuilder {
    nodes: BTreeMap<String, NodeHint>,
    subnets: BTreeMap<String, SubnetId>,
    operators: BTreeMap<String, TestNodeOperator>,
    providers: BTreeMap<String, PrincipalId>,
    data_centers: BTreeSet<String>,
}

impl CompliantRegistryMutationsBuilder {
    #[track_caller]
    pub fn with_operator(
        mut self,
        operator_utility_id: &str,
        dc_id: &str,
        provider_utility_id: &str,
    ) -> Self {
        self = self.with_data_center(dc_id);

        let provider_id = provider(self.providers.len() as u64 + 1);
        self.providers
            .insert(provider_utility_id.to_string(), provider_id);

        if let Some(existing_operator) = self.operators.get(operator_utility_id) {
            panic!("Operator with utility key {operator_utility_id} is already specified with the following values {existing_operator:?}");
        }

        self.operators.insert(
            operator_utility_id.to_string(),
            TestNodeOperator::new(
                operator(self.operators.len() as u64 + 1),
                provider_id,
                dc_id.to_string(),
            ),
        );

        self
    }

    #[track_caller]
    pub fn with_node(
        mut self,
        operator_utility_id: &str,
        node_utility_id: &str,
        subnet_utility_id: Option<&str>,
    ) -> Self {
        let subnet_id = if let Some(key) = subnet_utility_id {
            self = self.with_subnet(key);
            // At this point the call can't wait as it was added
            // by the previous `with_subnet`.
            self.subnets.get(key).cloned()
        } else {
            None
        };

        let operator = match self.operators.get(operator_utility_id) {
            Some(op) => op.id,
            None => panic!(
                "Node operator {operator_utility_id} isn't yet known to the registry builder."
            ),
        };

        if let Some(node_hint) = self.nodes.get(node_utility_id) {
            if node_hint.operator_id != operator || node_hint.subnet != subnet_id {
                panic!("Node with utility key {node_utility_id} already exists in the builder with slightly different data. Already present value {:?}", (node_utility_id, node_hint))
            }
        }

        self.nodes.insert(
            node_utility_id.to_string(),
            NodeHint {
                operator_id: operator,
                subnet: subnet_id,
            },
        );

        self
    }

    pub fn with_subnet(mut self, subnet_utility_id: &str) -> Self {
        if !self.subnets.contains_key(subnet_utility_id) {
            self.subnets.insert(
                subnet_utility_id.to_string(),
                subnet(self.subnets.len() as u64 + 1),
            );
        }

        self
    }

    pub fn with_data_center(mut self, dc_id: &str) -> Self {
        self.data_centers.insert(dc_id.to_string());
        self
    }

    pub fn build(self) -> CompliantRegistryMutations {
        let mut mutations = vec![];
        let mut nodes_with_keys = BTreeMap::new();
        for (node_utility_id, hint) in &self.nodes {
            let (request, nodes) = prepare_mutations_with_nodes_and_operator_id(
                nodes_with_keys.len() as u8 + 1,
                1,
                hint.operator_id,
            );

            mutations.extend(request.mutations);

            let (principal_id, public_key) = nodes.into_iter().next().unwrap();

            nodes_with_keys.insert(
                node_utility_id.to_string(),
                TestNode {
                    id: principal_id,
                    operator: hint.operator_id,
                    subnet: hint.subnet,
                    public_key,
                },
            );
        }

        for dc in &self.data_centers {
            mutations.push(upsert(
                make_data_center_record_key(dc.as_str()),
                DataCenterRecord {
                    id: dc.to_string(),
                    region: "region".to_string(),
                    owner: "owner".to_string(),
                    gps: Some(ic_protobuf::registry::dc::v1::Gps {
                        latitude: 0.0,
                        longitude: 0.0,
                    }),
                }
                .encode_to_vec(),
            ));
        }

        for operator in self.operators.values() {
            mutations.push(upsert(
                make_node_operator_record_key(operator.id),
                NodeOperatorRecord {
                    node_operator_principal_id: operator.id.to_vec(),
                    node_allowance: 10,
                    node_provider_principal_id: operator.provider.to_vec(),
                    dc_id: operator.dc_id.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ));
        }

        for subnet in self.subnets.values() {
            let nodes_for_subnet: Vec<_> = nodes_with_keys
                .values()
                .filter(|test_node| test_node.subnet.is_some_and(|s| s == *subnet))
                .collect();

            let mut subnet_record = get_invariant_compliant_subnet_record(
                nodes_for_subnet.iter().map(|n| n.id).collect(),
            );
            // For convenience, since we need at least one system subnet.
            subnet_record.subnet_type = SubnetType::System.into();

            let relevant_node_with_keys = nodes_for_subnet
                .iter()
                .map(|test_node| (test_node.id, test_node.public_key.clone()))
                .collect();
            let threshold_pk_and_cup = create_subnet_threshold_signing_pubkey_and_cup_mutations(
                *subnet,
                &relevant_node_with_keys,
            );

            mutations.push(upsert(
                make_subnet_record_key(*subnet),
                subnet_record.encode_to_vec(),
            ));

            mutations.extend(threshold_pk_and_cup);
        }

        mutations.push(upsert(
            make_subnet_list_record_key(),
            SubnetListRecord {
                subnets: self.subnets.values().map(|s| s.get().to_vec()).collect(),
            }
            .encode_to_vec(),
        ));

        mutations.extend(invariant_compliant_mutation(0));

        CompliantRegistryMutations {
            nodes: nodes_with_keys,
            subnets: self.subnets,
            operators: self.operators,
            providers: self.providers,
            data_centers: self.data_centers,
            mutations,
        }
    }
}

pub struct CompliantRegistryMutations {
    nodes: BTreeMap<String, TestNode>,
    subnets: BTreeMap<String, SubnetId>,
    operators: BTreeMap<String, TestNodeOperator>,
    providers: BTreeMap<String, PrincipalId>,
    data_centers: BTreeSet<String>,
    mutations: Vec<RegistryMutation>,
}

impl CompliantRegistryMutations {
    pub fn node_id(&self, node_utility_key: &str) -> NodeId {
        self.nodes.get(node_utility_key).map(|tn| tn.id).unwrap()
    }

    pub fn operator_id(&self, operator_utility_key: &str) -> PrincipalId {
        self.operators
            .get(operator_utility_key)
            .map(|op| op.id)
            .unwrap()
    }

    pub fn subnet_id(&self, subnet_utility_key: &str) -> SubnetId {
        *self.subnets.get(subnet_utility_key).unwrap()
    }

    pub fn mutations(&self) -> Vec<RegistryMutation> {
        self.mutations.clone()
    }

    pub fn provider_id(&self, provider_utility_key: &str) -> PrincipalId {
        *self.providers.get(provider_utility_key).unwrap()
    }

    pub fn dcs(&self) -> BTreeSet<String> {
        self.data_centers.clone()
    }

    pub fn node(&self, node_utility_key: &str) -> TestNode {
        self.nodes.get(node_utility_key).cloned().unwrap()
    }

    pub fn operator(&self, operator_utility_key: &str) -> TestNodeOperator {
        self.operators.get(operator_utility_key).cloned().unwrap()
    }
}
