use url::Url;

#[derive(Debug, Clone)]
pub struct Node {
    pub domain: String,
}

impl Node {
    pub fn new(domain: String) -> Self {
        Self { domain }
    }
}

impl From<Node> for Url {
    fn from(node: Node) -> Self {
        Url::parse(&format!("https://{}/api/v2/", node.domain)).expect("failed to parse URL")
    }
}
