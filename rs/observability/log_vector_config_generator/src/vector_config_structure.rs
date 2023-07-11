use std::collections::{BTreeSet, HashMap};

use config_writer_common::vector_config_structure::{
    VectorConfigBuilder, VectorConfigEnriched, VectorSource, VectorTransform,
};
use serde::Serialize;
use std::string::ParseError;

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
    fn build(&self, target_groups: BTreeSet<TargetGroup>, job: JobType) -> VectorConfigEnriched {
        from_targets_into_vector_config(self, target_groups, job)
    }
}

pub fn from_targets_into_vector_config(
    builder: &VectorConfigBuilderImpl,
    records: BTreeSet<TargetGroup>,
    job: JobType,
) -> VectorConfigEnriched {
    let mut config = VectorConfigEnriched::new();
    for record in records {
        let key = format!("{}-{}", record.node_id, job);
        let mut source: VectorSystemdGatewayJournaldSource = record.clone().try_into().unwrap();
        source.batch_size = builder.batch_size;
        let transform = VectorSystemdGatewayJournaldTransform::from(record, job);
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
        let endpoint = target_group.get_ip_as_str().unwrap();

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
const ADDRESS: &str = "address";
const NODE_PROVIDER_ID: &str = "node_provider_id";

impl VectorSystemdGatewayJournaldTransform {
    fn from(target_group: TargetGroup, job: JobType) -> Self {
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(IC_NAME.into(), target_group.ic_name.to_string());
        labels.insert(IC_NODE.into(), target_group.node_id.to_string());
        labels.insert(ADDRESS.into(), target_group.get_ip_as_str().unwrap());
        labels.insert(
            NODE_PROVIDER_ID.into(),
            target_group.node_provider_id.to_string(),
        );
        labels.insert(DC.into(), target_group.dc_id);
        if let Some(subnet_id) = target_group.subnet_id {
            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
        }
        Self {
            _type: "remap".into(),
            inputs: vec![format!("{}-{}-source", target_group.node_id, job)],
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
