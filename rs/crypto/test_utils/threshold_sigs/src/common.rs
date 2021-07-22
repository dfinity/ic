use ic_types::NodeId;
use std::collections::BTreeMap;

pub(crate) fn crypto_for<T>(node_id: NodeId, crypto_components: &BTreeMap<NodeId, T>) -> &T {
    crypto_components
        .get(&node_id)
        .unwrap_or_else(|| panic!("missing crypto component for {:?}", node_id))
}
