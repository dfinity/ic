use serde::{Deserialize, Serialize};
use std::hash::Hash;

use super::DataContract;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sns {
    pub root_canister_id: String,
    pub name: String,
    pub url: String,
    pub description: String,
    pub enabled: bool,
    pub canisters: Vec<Canister>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Canister {
    pub module_hash: String,
    pub canister_id: String,
    pub canister_type: String,
}

impl Hash for Sns {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root_canister_id.hash(state);
        self.name.hash(state);
        self.url.hash(state);
        self.description.hash(state);
        self.enabled.hash(state);
        self.canisters.iter().for_each(|f| f.hash(state))
    }
}

impl Hash for Canister {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.module_hash.hash(state);
        self.canister_id.hash(state);
        self.canister_type.hash(state);
    }
}

impl DataContract for Sns {
    fn get_name(&self) -> String {
        self.name.to_string()
    }

    fn get_id(&self) -> String {
        self.root_canister_id.to_string()
    }
}
