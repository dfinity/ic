use std::collections::{BTreeMap, BTreeSet};

use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_protobuf::registry::{
    dc::v1::DataCenterRecord, node_operator::v1::NodeOperatorRecord, subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
use ic_types::{NodeId, PrincipalId, SubnetId};

use ic_nns_test_utils::registry::{
    create_subnet_threshold_signing_pubkey_and_cup_mutations, invariant_compliant_mutation,
};
use prost::Message;

use crate::{
    get_invariant_compliant_subnet_record, prepare_registry_with_nodes_and_node_operator_id,
};

#[derive(Clone, Debug)]
pub struct TestNode {
    pub id: NodeId,
    pub operator: PrincipalId,
    pub subnet: Option<SubnetId>,
    pub public_keys: PublicKey,
}

#[derive(Clone, Debug)]
pub struct TestNodeOperator {
    pub id: PrincipalId,
    pub provider: PrincipalId,
    pub dc: String,
}

#[derive(Default)]
pub struct CompliantRegistryBuilder {
    nodes: BTreeMap<String, (PrincipalId, Option<SubnetId>)>,
    subnets: BTreeMap<String, SubnetId>,
    operators: BTreeMap<String, TestNodeOperator>,
    providers: BTreeMap<String, PrincipalId>,
    data_centers: BTreeSet<String>,
}

fn operator(num: u64) -> PrincipalId {
    PrincipalId::new_user_test_id(num)
}

fn provider(num: u64) -> PrincipalId {
    PrincipalId::new_user_test_id(9999 - num)
}

fn subnet(num: u64) -> SubnetId {
    SubnetId::new(PrincipalId::new_subnet_test_id(num))
}

impl CompliantRegistryBuilder {
    // Ensure the panic is showing the line where
    // it has been called from to make debugging easier.
    #[track_caller]
    pub fn with_operator(
        mut self,
        operator_utility_id: &str,
        dc_id: &str,
        provider_utility_id: &str,
    ) -> Self {
        self.data_centers.insert(dc_id.to_string());
        let provider_id = provider(self.providers.len() as u64 + 1);
        self.providers
            .insert(provider_utility_id.to_string(), provider_id);

        if let Some(existing_op) = self.operators.get(operator_utility_id) {
            panic!("Operator with utility key {operator_utility_id} is already specified with the following values {existing_op:?}");
        }

        self.operators.insert(
            operator_utility_id.to_string(),
            TestNodeOperator {
                id: operator(self.operators.len() as u64 + 1),
                provider: provider_id,
                dc: dc_id.to_string(),
            },
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
        let subnet_id = subnet_utility_id.map(|key| {
            let id = subnet(self.subnets.len() as u64 + 1);
            self.subnets.insert(key.to_string(), id);
            id
        });

        let operator = match self.operators.get(operator_utility_id) {
            Some(op) => op.id,
            None => panic!(
                "Node operator {operator_utility_id} isn't yet known to the registry builder."
            ),
        };

        if let Some((op, maybe_subnet)) = self.nodes.get(node_utility_id) {
            if *op != operator || maybe_subnet != &subnet_id {
                panic!("Node with utility key {node_utility_id} already exists in the builder with slightly different data. Already present value {:?}", (node_utility_id, op, maybe_subnet))
            }
        }

        self.nodes
            .insert(node_utility_id.to_string(), (operator, subnet_id));

        self
    }

    pub fn build(self) -> CompliantRegistry {
        let mut mutations = vec![];
        let mut nodes_with_keys = BTreeMap::new();
        for (node_utility_id, (operator, subnet)) in &self.nodes {
            let (request, nodes) = prepare_registry_with_nodes_and_node_operator_id(
                nodes_with_keys.len() as u8 + 1,
                1,
                *operator,
            );

            mutations.extend(request.mutations);

            let (principal_id, public_keys) = nodes.into_iter().next().unwrap();

            nodes_with_keys.insert(
                node_utility_id.to_string(),
                TestNode {
                    id: principal_id,
                    operator: *operator,
                    subnet: *subnet,
                    public_keys,
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

        for (_, operator) in &self.operators {
            mutations.push(upsert(
                make_node_operator_record_key(operator.id),
                NodeOperatorRecord {
                    node_operator_principal_id: operator.id.to_vec(),
                    node_allowance: 10,
                    node_provider_principal_id: operator.provider.to_vec(),
                    dc_id: operator.dc.clone(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ));
        }

        for (_, subnet) in &self.subnets {
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
                .map(|test_node| (test_node.id.clone(), test_node.public_keys.clone()))
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
                subnets: self.subnets.iter().map(|(_, s)| s.get().to_vec()).collect(),
            }
            .encode_to_vec(),
        ));

        mutations.extend(invariant_compliant_mutation(0));

        // Sort and dedublicate by key
        // to ensure that we didn't apply
        // mutations multiple times.
        mutations.sort_by_key(|m| m.key.clone());
        mutations.dedup_by_key(|m| m.key.clone());

        CompliantRegistry {
            nodes: nodes_with_keys,
            subnets: self.subnets,
            operators: self.operators,
            providers: self.providers,
            data_centers: self.data_centers,
            mutations,
        }
    }
}

#[allow(dead_code)]
pub struct CompliantRegistry {
    nodes: BTreeMap<String, TestNode>,
    subnets: BTreeMap<String, SubnetId>,
    operators: BTreeMap<String, TestNodeOperator>,
    providers: BTreeMap<String, PrincipalId>,
    data_centers: BTreeSet<String>,
    mutations: Vec<RegistryMutation>,
}

impl CompliantRegistry {
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

    // pub fn run_mut<F, R>(&mut self, f: F) -> R
    // where
    //     F: FnOnce(&mut Registry) -> R,
    // {
    //     f(&mut self.registry)
    // }

    // pub fn run<F, R>(&self, f: F) -> R
    // where
    //     F: FnOnce(&Registry) -> R,
    // {
    //     f(&self.registry)
    // }

    pub fn mutations(&self) -> Vec<RegistryMutation> {
        self.mutations.clone()
    }
}
