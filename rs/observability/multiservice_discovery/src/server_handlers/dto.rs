use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;

use crate::definition::Definition;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefinitionDto {
    pub nns_urls: Vec<Url>,
    pub name: String,
    pub public_key: Option<String>,
}

impl From<&Definition> for DefinitionDto {
    fn from(value: &Definition) -> Self {
        Self {
            name: value.name.clone(),
            nns_urls: value.nns_urls.clone(),
            public_key: value.public_key.map(|pk| base64::encode(pk.into_bytes())),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundaryNodeDto {
    pub name: String,
    pub ic_name: String,
    pub custom_labels: BTreeMap<String, String>,
    pub targets: BTreeSet<SocketAddr>,
    pub job_type: String,
}
