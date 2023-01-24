use std::collections::{BTreeSet, HashMap};

use config_writer_common::vector_config_structure::{
    VectorConfigBuilder, VectorConfigEnriched, VectorSource, VectorTransform,
};
use serde::Serialize;
use std::string::ParseError;

use regex::Regex;
use service_discovery::{job_types::JobType, TargetGroup};

pub struct VectorConfigBuilderImpl {
    batch_size: u64,
}

impl VectorConfigBuilderImpl {
    pub fn new(batch_size: u64) -> Self {
        Self { batch_size }
    }
}
impl VectorConfigBuilder for VectorConfigBuilderImpl {
    fn build(&self, target_groups: BTreeSet<TargetGroup>, _job: JobType) -> VectorConfigEnriched {
        from_targets_into_vector_config(self, target_groups)
    }
}

pub fn from_targets_into_vector_config(
    builder: &VectorConfigBuilderImpl,
    records: BTreeSet<TargetGroup>,
) -> VectorConfigEnriched {
    let mut config = VectorConfigEnriched::new();
    for record in records {
        let key = record
            .clone()
            .targets
            .into_iter()
            .map(|t| t.to_string())
            .next()
            .unwrap();
        let mut source: VectorSystemdGatewayJournaldSource = record.clone().try_into().unwrap();
        source.batch_size = builder.batch_size;
        let transform: VectorSystemdGatewayJournaldTransform = record.clone().into();
        config.add_target_group(key, Box::new(source), Box::new(transform));
    }
    config
}

#[derive(Debug, Serialize, Clone)]
struct VectorSystemdGatewayJournaldSource {
    #[serde(rename = "type")]
    _type: String,
    endpoint: String,
    data_dir: String,
    batch_size: u64,
}

impl VectorSource for VectorSystemdGatewayJournaldSource {
    fn clone_dyn(&self) -> Box<dyn VectorSource> {
        Box::new(self.clone())
    }
}

impl TryFrom<TargetGroup> for VectorSystemdGatewayJournaldSource {
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
            data_dir: "logs".to_string(),
            batch_size: 0,
        })
    }
}

#[derive(Debug, Serialize, Clone)]
struct VectorSystemdGatewayJournaldTransform {
    #[serde(rename = "type")]
    _type: String,
    inputs: Vec<String>,
    source: String,
}

impl VectorTransform for VectorSystemdGatewayJournaldTransform {
    fn clone_dyn(&self) -> Box<dyn VectorTransform> {
        Box::new(self.clone())
    }
}

const IC_NAME: &str = "ic";
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";
const DC: &str = "dc";

impl From<TargetGroup> for VectorSystemdGatewayJournaldTransform {
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
