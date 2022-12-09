use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use std::string::ParseError;

use regex::Regex;
use service_discovery::TargetGroup;
#[derive(Debug, Serialize)]
pub struct VectorServiceDiscoveryConfigEnriched {
    sources: HashMap<String, VectorSource>,
    transforms: HashMap<String, VectorTransform>,
}

impl VectorServiceDiscoveryConfigEnriched {
    fn new() -> Self {
        Self {
            sources: HashMap::new(),
            transforms: HashMap::new(),
        }
    }

    fn add_target_group(&mut self, target_group: TargetGroup) {
        let key = target_group
            .clone()
            .targets
            .into_iter()
            .map(|t| t.to_string())
            .next()
            .unwrap();
        self.sources.insert(
            format!("{}-source", key),
            target_group.clone().try_into().unwrap(),
        );
        self.transforms
            .insert(format!("{}-transform", key), target_group.into());
    }
}

impl From<BTreeSet<TargetGroup>> for VectorServiceDiscoveryConfigEnriched {
    fn from(records: BTreeSet<TargetGroup>) -> Self {
        let mut config = Self::new();
        for record in records {
            config.add_target_group(record);
        }
        config
    }
}

#[derive(Debug, Serialize)]
struct VectorSource {
    #[serde(rename = "type")]
    _type: String,
    endpoint: String,
}

impl TryFrom<TargetGroup> for VectorSource {
    type Error = ParseError;

    fn try_from(target_group: TargetGroup) -> Result<Self, Self::Error> {
        let regex = Regex::new(r"\[.*\]").unwrap();

        let endpoint = target_group
            .targets
            .into_iter()
            .map(|g| match regex.find(&g.to_string()) {
                Some(mat) => {
                    let binding = mat.as_str().to_string();
                    let mut chars = binding.chars();
                    chars.next().unwrap();
                    chars.next_back().unwrap();
                    chars.as_str().to_string()
                }
                None => panic!("Couldn't parse url."),
            })
            .next()
            .unwrap();

        Ok(Self {
            _type: "systemd_journal_gatewayd".into(),
            endpoint,
        })
    }
}

#[derive(Debug, Serialize)]
struct VectorTransform {
    #[serde(rename = "type")]
    _type: String,
    inputs: Vec<String>,
    source: String,
}

const IC_NAME: &str = "ic";
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";
const DC: &str = "dc";

impl From<TargetGroup> for VectorTransform {
    fn from(target_group: TargetGroup) -> Self {
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(IC_NAME.into(), target_group.ic_name);
        labels.insert(IC_NODE.into(), target_group.node_id.to_string());
        if let Some(subnet_id) = target_group.subnet_id {
            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
        }
        if let Some(dc) = target_group.dc_id {
            labels.insert(DC.into(), dc);
        }
        Self {
            _type: "remap".into(),
            inputs: target_group
                .targets
                .into_iter()
                .map(|g| format!("{}-source", g))
                .collect(),
            source: labels
                .into_iter()
                // Might be dangerous as the tag value is coming from an outside source and
                // is not escaped.
                .map(|(k, v)| format!(".{} = \"{}\"", k, v))
                .collect::<Vec<String>>()
                .join("\n"),
        }
    }
}
