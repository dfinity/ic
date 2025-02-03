use std::cell::RefCell;

use candid::CandidType;
use ic_base_types::{NodeId, PrincipalId};
use ic_nns_handler_root::root_proposals::{
    get_nns_membership, get_nns_subnet_id, get_node_operator_pid_of_node,
};
use serde::Deserialize;

#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct SimpleNodeRecord {
    pub node_principal: NodeId,
    pub operator_principal: PrincipalId,
}

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
            node_principal: node,
            operator_principal: node_operator_id,
        });
    }

    NODE_OPERATORS_IN_NNS.replace(new_simple_records);

    Ok(())
}

pub fn get_node_operators_in_nns() -> Vec<SimpleNodeRecord> {
    NODE_OPERATORS_IN_NNS.with_borrow(|records| records.clone())
}
