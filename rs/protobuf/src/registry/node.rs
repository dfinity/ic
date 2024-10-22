use crate::registry::node::v1::NodeRewardType;

#[allow(clippy::all)]
#[path = "../gen/registry/registry.node.v1.rs"]
pub mod v1;

impl From<NodeRewardType> for String {
    fn from(value: NodeRewardType) -> Self {
        match value {
            NodeRewardType::Unspecified => {
                panic!("Cannot create a node type string from unspecified")
            }
            NodeRewardType::Type0 => "type0".to_string(),
            NodeRewardType::Type1 => "type1".to_string(),
            NodeRewardType::Type2 => "type2".to_string(),
            NodeRewardType::Type3 => "type3".to_string(),
            NodeRewardType::Type3dot1 => "type3.1".to_string(),
            NodeRewardType::Type1dot1 => "type1.1".to_string(),
        }
    }
}
