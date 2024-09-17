use ic_agent::agent::ApiBoundaryNode;
use url::Url;

#[derive(Clone, PartialEq, Debug)]
pub struct Node {
    pub domain: String,
}

impl Node {
    pub fn new<S: AsRef<str>>(domain: S) -> Self {
        Self {
            domain: domain.as_ref().to_string(),
        }
    }
}

impl Node {
    pub fn to_routing_url(&self) -> Url {
        Url::parse(&format!("https://{}", self.domain)).expect("failed to parse URL")
    }
}

impl From<Node> for Url {
    fn from(node: Node) -> Self {
        Url::parse(&format!("https://{}", node.domain)).expect("failed to parse URL")
    }
}

impl From<&ApiBoundaryNode> for Node {
    fn from(api_bn: &ApiBoundaryNode) -> Self {
        Node::new(api_bn.domain.as_str())
    }
}
