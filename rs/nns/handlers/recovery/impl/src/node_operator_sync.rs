use std::{cell::RefCell, collections::BTreeMap};

use candid::Principal;
use ic_nns_handler_recovery_interface::simple_node_operator_record::SimpleNodeOperatorRecord;
use ic_nns_handler_root::root_proposals::{
    get_nns_membership, get_nns_subnet_id, get_node_operator_pid_of_node,
};

thread_local! {
  static NODE_OPERATORS_IN_NNS: RefCell<Vec<SimpleNodeOperatorRecord>> = const { RefCell::new(Vec::new()) };
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
        .map(|(principal, nodes)| SimpleNodeOperatorRecord { principal, nodes })
        .collect();
    NODE_OPERATORS_IN_NNS.replace(new_simple_records);

    Ok(())
}

pub fn get_node_operators_in_nns() -> Vec<SimpleNodeOperatorRecord> {
    NODE_OPERATORS_IN_NNS.with_borrow(|records| records.clone())
}
