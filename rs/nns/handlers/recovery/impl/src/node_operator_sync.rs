use std::{cell::RefCell, collections::BTreeMap};

use candid::Principal;
use ic_nns_handler_recovery_interface::simple_node_operator_record::SimpleNodeOperatorRecord;
use ic_nns_handler_root::root_proposals::{
    get_nns_membership, get_nns_subnet_id, get_node_operator_pid_of_node,
};
use itertools::Itertools;

thread_local! {
  static NODE_OPERATORS_IN_NNS: RefCell<Vec<SimpleNodeOperatorRecord>> = const { RefCell::new(Vec::new()) };
  static INITIAL_NODE_OPERATORS: RefCell<Vec<SimpleNodeOperatorRecord>> = const { RefCell::new(Vec::new()) };
}

pub async fn sync_node_operators() -> Result<(), String> {
    let nns_subnet_id = get_nns_subnet_id().await?;
    let (nns_nodes, subnet_membership_registry_version) =
        get_nns_membership(&nns_subnet_id).await?;

    let mut new_simple_records: BTreeMap<Principal, Vec<Principal>> = BTreeMap::new();

    for node in nns_nodes {
        let node_operator_id =
            get_node_operator_pid_of_node(&node, subnet_membership_registry_version).await?;

        if let Some(entry) = new_simple_records.get_mut(&node_operator_id.0) {
            entry.push(node.get().0);
        } else {
            new_simple_records.insert(node_operator_id.0, vec![node.get().0]);
        }
    }

    let new_simple_records = new_simple_records
        .into_iter()
        .map(|(operator_id, nodes)| SimpleNodeOperatorRecord { operator_id, nodes })
        .collect();
    NODE_OPERATORS_IN_NNS.replace(new_simple_records);

    Ok(())
}

pub fn set_initial_node_operators(initial: Vec<SimpleNodeOperatorRecord>) {
    INITIAL_NODE_OPERATORS.replace(initial);
}

pub fn get_node_operators_in_nns() -> Vec<SimpleNodeOperatorRecord> {
    let initial = INITIAL_NODE_OPERATORS.with_borrow(|records| records.clone());
    let obtained_from_sync = NODE_OPERATORS_IN_NNS.with_borrow(|records| records.clone());

    let mut merged: Vec<_> = obtained_from_sync
        .clone()
        .into_iter()
        .chain(initial.clone())
        .collect();
    merged.sort_by(|a, b| b.nodes.len().cmp(&a.nodes.len()));
    merged.dedup_by(|a, b| a.operator_id == b.operator_id);

    if !initial.is_empty() {
        ic_cdk::println!("Initial: {}", format_node_operators(&initial));
        ic_cdk::println!("Obtained: {}", format_node_operators(&obtained_from_sync));
    }
    ic_cdk::println!("Merged: {}", format_node_operators(&merged));
    merged
}

fn format_node_operators(operators: &Vec<SimpleNodeOperatorRecord>) -> String {
    operators
        .iter()
        .map(|operator| {
            format!(
                "Principal: {}, Nodes: [{}]",
                operator.operator_id.to_string(),
                operator.nodes.iter().map(|n| n.to_string()).join(", ")
            )
        })
        .join("\n")
}
