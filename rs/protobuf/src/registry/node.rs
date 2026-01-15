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
            NodeRewardType::Type1dot1 => "type1.1".to_string(),
            NodeRewardType::Type2 => "type2".to_string(),
            NodeRewardType::Type3 => "type3".to_string(),
            NodeRewardType::Type3dot1 => "type3.1".to_string(),
        }
    }
}

impl std::fmt::Display for NodeRewardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from(*self))
    }
}

impl From<String> for NodeRewardType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "type0" => NodeRewardType::Type0,
            "type1" => NodeRewardType::Type1,
            "type1.1" => NodeRewardType::Type1dot1,
            "type2" => NodeRewardType::Type2,
            "type3" => NodeRewardType::Type3,
            "type3.1" => NodeRewardType::Type3dot1,
            _ => NodeRewardType::Unspecified,
        }
    }
}
