use std::collections::{BTreeSet, HashMap};

use ic_types::PrincipalId;
use serde::Serialize;

use service_discovery::guest_to_host_address;
use service_discovery::job_types::NodeOS;
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
            let source = VectorSystemdGatewayJournaldSource {
                _type: "systemd_journal_gatewayd".into(),
                endpoint: handle_ip(record.clone(), job, is_bn),
                data_dir: "logs".to_string(),
                batch_size: builder.batch_size,
                port: match is_bn {
                    false => builder.port,
                    true => builder.bn_port,
                },
            };
            let source_key = format!("{}-source", key);
            let transform =
                VectorRemapTransform::from(record.clone(), *job, source_key.clone(), is_bn);

            let mut sources_map = HashMap::new();
            sources_map.insert(source_key, Box::new(source) as Box<dyn VectorSource>);

            let mut transforms_map = HashMap::new();
            transforms_map.insert(
                format!("{}-transform", key),
                Box::new(transform) as Box<dyn VectorTransform>,
            );
            config.add_target_group(sources_map, transforms_map);
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

#[derive(Debug, Serialize, Clone)]
pub struct VectorRemapTransform {
    #[serde(rename = "type")]
    _type: String,
    inputs: Vec<String>,
    source: String,
}

impl VectorTransform for VectorRemapTransform {
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

impl VectorRemapTransform {
    pub fn from(target: TargetDto, job: JobType, input: String, is_bn: bool) -> Self {
        let target_group = Into::<TargetGroup>::into(&target);
        let mut labels: HashMap<String, String> = HashMap::new();

        let anonymous = PrincipalId::new_anonymous().to_string();
        let mut node_id = target_group.node_id.to_string();
        if node_id == anonymous {
            node_id = target.clone().name
        }

        let endpoint = handle_ip(target.clone(), &job, is_bn);

        labels.insert(IC_NAME.into(), target_group.ic_name.to_string());
        labels.insert(IC_NODE.into(), node_id.clone());
        labels.insert(ADDRESS.into(), endpoint);
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
            inputs: vec![input],
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

pub fn handle_ip(target_group: TargetDto, job_type: &JobType, is_bn: bool) -> String {
    match job_type {
        JobType::NodeExporter(NodeOS::Guest) => {
            target_group.targets.first().unwrap().ip().to_string()
        }
        JobType::NodeExporter(NodeOS::Host) => match is_bn {
            true => target_group.targets.first().unwrap().ip().to_string(),
            false => guest_to_host_address(*target_group.targets.first().unwrap())
                .unwrap()
                .ip()
                .to_string(),
        },
        _ => panic!("Unsupported job type"),
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
