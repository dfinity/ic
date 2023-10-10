use std::collections::{BTreeSet, HashMap};
use std::string::ParseError;

use ic_types::PrincipalId;
use serde::Serialize;

use service_discovery::{job_types::JobType, TargetGroup};

use crate::builders::vector_config_enriched::VectorSource;
use crate::builders::vector_config_enriched::VectorTransform;
use crate::builders::ConfigBuilder;
use crate::contracts::TargetDto;

use super::vector_config_enriched::VectorConfigEnriched;

#[derive(Debug, Clone)]
pub struct VectorConfigBuilderImpl {
    batch_size: u64,
    port: u64,
    bn_port: u64,
}

impl VectorConfigBuilderImpl {
    pub fn new(batch_size: u64, port: u64, bn_port: u64) -> Self {
        Self {
            batch_size,
            port,
            bn_port,
        }
    }
}

impl ConfigBuilder for VectorConfigBuilderImpl {
    fn build(&self, target_groups: BTreeSet<TargetDto>) -> String {
        from_targets_into_vector_config(self, target_groups)
    }
}

pub(crate) fn from_targets_into_vector_config(
    builder: &VectorConfigBuilderImpl,
    records: BTreeSet<TargetDto>,
) -> String {
    let mut config = VectorConfigEnriched::new();
    let mut edited_records: Vec<TargetDto> = vec![];

    for record in &records {
        if let Some(record) = edited_records
            .iter_mut()
            .find(|r| r.targets.first().unwrap().ip() == record.targets.first().unwrap().ip())
        {
            record.custom_labels.clear();
            continue;
        }

        edited_records.push(record.clone());
    }

    for record in edited_records {
        for job in &record.jobs {
            let mut is_bn = false;
            let mut key = record.node_id.to_string();
            let anonymous = PrincipalId::new_anonymous().to_string();
            if key == anonymous {
                key = record.clone().name;
                is_bn = true;
            }
            let key = format!("{}-{}", key, job);
            let target_group = Into::<TargetGroup>::into(&record);
            let mut source: VectorSystemdGatewayJournaldSource = target_group.try_into().unwrap();
            source.batch_size = builder.batch_size;
            source.port = match is_bn {
                false => builder.port,
                true => builder.bn_port,
            };

            let transform = VectorSystemdGatewayJournaldTransform::from(record.clone(), *job);
            config.add_target_group(key, Box::new(source), Box::new(transform));
        }
    }
    serde_json::to_string_pretty(&config).unwrap()
}

#[derive(Debug, Serialize, Clone)]
struct VectorSystemdGatewayJournaldSource {
    #[serde(rename = "type")]
    _type: String,
    endpoint: String,
    data_dir: String,
    batch_size: u64,
    port: u64,
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
            port: 19531,
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
    fn from(target: TargetDto, job: JobType) -> Self {
        let target_group = Into::<TargetGroup>::into(&target);
        let mut labels: HashMap<String, String> = HashMap::new();

        let anonymous = PrincipalId::new_anonymous().to_string();
        let mut node_id = target_group.node_id.to_string();
        if node_id == anonymous {
            node_id = target.name
        }

        labels.insert(IC_NAME.into(), target_group.ic_name.to_string());
        labels.insert(IC_NODE.into(), node_id.clone());
        labels.insert(ADDRESS.into(), target_group.get_ip_as_str().unwrap());
        labels.insert(
            NODE_PROVIDER_ID.into(),
            target_group.node_provider_id.to_string(),
        );
        labels.insert(DC.into(), target_group.dc_id);
        labels.extend(target.custom_labels);
        if let Some(subnet_id) = target_group.subnet_id {
            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
        }
        Self {
            _type: "remap".into(),
            inputs: vec![format!("{}-{}-source", node_id, job)],
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::SocketAddr;

    use ic_types::PrincipalId;
    use serde_json::{json, Value};

    use service_discovery::job_types::NodeOS;

    use super::VectorConfigBuilderImpl;
    use crate::builders::ConfigBuilder;
    use crate::contracts::TargetDto;
    use crate::JobType;

    fn convert_ipv6_to_array(ipv6: &str) -> [u16; 8] {
        let mut array = [0u16; 8];

        let mut parts = ipv6.split(':');

        for item in &mut array {
            *item = u16::from_str_radix(parts.next().unwrap(), 16)
                .unwrap()
                .to_be();
        }

        array
    }

    #[test]
    fn test_vector_config_builder() {
        let builder = VectorConfigBuilderImpl::new(32, 19531, 19532);
        let ipv6 = convert_ipv6_to_array("5c:29:a:bd:e6:38:c8:75");
        let mut targets = BTreeSet::new();
        targets.insert(SocketAddr::from((ipv6, 8080)));
        let jobs = vec![JobType::NodeExporter(NodeOS::Guest)];
        let mut custom_labels = BTreeMap::new();
        custom_labels.insert("custom".to_string(), "label".to_string());

        let mut target_dto = BTreeSet::new();
        target_dto.insert(TargetDto {
            node_id: PrincipalId::new_anonymous().into(),
            name: "bn1".to_string(),
            ic_name: "ic".to_string(),
            subnet_id: None,
            node_provider_id: PrincipalId::new_anonymous(),
            dc_id: "dc1".to_string(),
            targets: targets.clone(),
            jobs: jobs.clone(),
            operator_id: PrincipalId::new_anonymous(),
            custom_labels: custom_labels.clone(),
        });
        target_dto.insert(TargetDto {
            node_id: PrincipalId::new_anonymous().into(),
            name: "bn2".to_string(),
            ic_name: "ic".to_string(),
            subnet_id: None,
            node_provider_id: PrincipalId::new_anonymous(),
            dc_id: "dc1".to_string(),
            targets: targets.clone(),
            jobs: jobs.clone(),
            operator_id: PrincipalId::new_anonymous(),
            custom_labels: custom_labels.clone(),
        });

        let config = builder.build(target_dto);

        let expected = json!({
            "sources": {
                "bn1-node_exporter-source": {
                    "type": "systemd_journal_gatewayd",
                    "endpoint": ipv6.iter().map(|f| format!("{:x}", f)).collect::<Vec<String>>().join(":"),
                    "data_dir": "logs",
                    "batch_size": 32
                }
            },
            "transforms": {
                "bn1-node_exporter-transform": {
                    "type": "remap",
                    "inputs": [
                        "bn1-node_exporter-source"
                    ],
                    "source": "doesn't matter"
                }
            }
        });

        let actual: Value = serde_json::from_str(&config).unwrap();

        let sources_actual = actual["sources"].as_object().unwrap();
        let sources_expected = expected["sources"].as_object().unwrap();

        assert_eq!(sources_actual.len(), sources_expected.len());
    }
}
