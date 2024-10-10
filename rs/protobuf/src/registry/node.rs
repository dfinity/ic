use crate::registry::node::v1::NodeType;

#[allow(clippy::all)]
#[path = "../gen/registry/registry.node.v1.rs"]
pub mod v1;

impl From<NodeType> for String {
    fn from(value: NodeType) -> Self {
        match value {
            NodeType::Unspecified => {
                panic!("Cannot create a node type string from unspecified")
            }
            NodeType::Type0 => "type0".to_string(),
            NodeType::Type1 => "type1".to_string(),
            NodeType::Type2 => "type2".to_string(),
            NodeType::Type3 => "type3".to_string(),
            NodeType::Type3dot1 => "type3.1".to_string(),
            NodeType::Type1dot1 => "type1.1".to_string(),
        }
    }
}
