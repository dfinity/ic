use std::collections::BTreeMap;

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct EnvironmentVariables {
    map: BTreeMap<String, String>,
}

impl EnvironmentVariables {
    pub fn new(environment_variables: BTreeMap<String, String>) -> Self {
        Self {
            map: environment_variables,
        }
    }

    #[allow(dead_code)]
    pub fn hash(&self) -> Vec<u8> {
        // TODO(EXC-2067): Implement the hash function
        todo!()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.map.iter()
    }
}

impl From<EnvironmentVariables> for BTreeMap<String, String> {
    fn from(environment_variables: EnvironmentVariables) -> Self {
        environment_variables.map
    }
}