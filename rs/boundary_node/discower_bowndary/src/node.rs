use url::Url;

#[derive(Debug, Clone)]
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

impl From<Node> for Url {
    fn from(node: Node) -> Self {
        Url::parse(&format!("https://{}/api/v2/", node.domain)).expect("failed to parse URL")
    }
}
