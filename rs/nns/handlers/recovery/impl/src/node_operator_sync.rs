use std::cell::RefCell;

use ic_nns_handler_recovery_interface::simple_node_record::SimpleNodeRecord;
use ic_nns_handler_root::root_proposals::{
    get_nns_membership, get_nns_subnet_id, get_node_operator_pid_of_node,
};

thread_local! {
  static NODE_OPERATORS_IN_NNS: RefCell<Vec<SimpleNodeRecord>> = const { RefCell::new(Vec::new()) };
}

pub async fn sync_node_operators() -> Result<(), String> {
    let nns_subnet_id = get_nns_subnet_id().await?;
    let (nns_nodes, subnet_membership_registry_version) =
        get_nns_membership(&nns_subnet_id).await?;

    let mut new_simple_records = vec![];

    for node in nns_nodes {
        let node_operator_id =
            get_node_operator_pid_of_node(&node, subnet_membership_registry_version).await?;

        new_simple_records.push(SimpleNodeRecord {
            node_principal: node.get().0,
            operator_principal: node_operator_id.0,
        });
    }

    NODE_OPERATORS_IN_NNS.replace(new_simple_records);

    Ok(())
}

pub fn get_node_operators_in_nns() -> Vec<SimpleNodeRecord> {
    NODE_OPERATORS_IN_NNS.with_borrow(|records| records.clone())
}
