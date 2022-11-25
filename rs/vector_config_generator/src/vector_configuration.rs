use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use service_discovery::TargetGroup;

// NOTE: Those structures are tightly coupled with the use we want out of them
// for metrics, meaning adding labels and creating prometheus scraper sources.
// We might want to make those more general, so that we can use a simple configuration
// to tell the generator what we want as an input and as a result.
// This needs to be refined further

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
            key.clone() + "-source",
            target_group.clone().try_into().unwrap(),
        );
        self.transforms
            .insert(key + "-transform", target_group.into());
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
    endpoints: Vec<String>,
    scrape_interval_secs: u64,
    instance_tag: String,
    endpoint_tag: String,
}

impl TryFrom<TargetGroup> for VectorSource {
    type Error = url::ParseError;

    fn try_from(target_group: TargetGroup) -> Result<Self, Self::Error> {
        let endpoints: Vec<String> = target_group
            .targets
            .into_iter()
            .map(|g| g.to_string())
            .map(|g| "http://".to_string() + &g)
            .map(|g| url::Url::parse(&g).unwrap())
            .map(|g| g.to_string())
            .collect();

        Ok(Self {
            _type: "prometheus_scrape".into(),
            endpoints,
            scrape_interval_secs: 5,
            instance_tag: "instance".into(),
            endpoint_tag: "endpoint".into(),
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

impl From<TargetGroup> for VectorTransform {
    fn from(target_group: TargetGroup) -> Self {
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(IC_NAME.into(), target_group.ic_name);
        labels.insert(IC_NODE.into(), target_group.node_id.to_string());
        if let Some(subnet_id) = target_group.subnet_id {
            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
        }
        Self {
            _type: "remap".into(),
            inputs: target_group
                .targets
                .into_iter()
                .map(|g| g.to_string())
                .map(|g| g + "-source")
                .collect(),
            source: labels
                .into_iter()
                // Might be dangerous as the tag value is coming from an outside source and
                // is not escaped.
                .map(|(k, v)| format!(".tags.{} = \"{}\"", k, v))
                .collect::<Vec<String>>()
                .join("\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddrV6, str::FromStr};

    use ic_types::{NodeId, PrincipalId, SubnetId};
    use service_discovery::TargetGroup;

    use std::collections::BTreeSet;

    use crate::vector_configuration::VectorServiceDiscoveryConfigEnriched;

    #[test]
    fn try_from_prometheus_target_group_to_vector_config_correct_inputs() {
        let original_addr = "[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091";
        let sources_key = String::from(original_addr) + "-source";
        let transforms_key = String::from(original_addr) + "-transform";
        let mut targets = BTreeSet::new();
        targets.insert(std::net::SocketAddr::V6(
            SocketAddrV6::from_str(original_addr).unwrap(),
        ));
        let ptg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "iylgr-zpxwq-kqgmf-4srtx-o4eey-d6bln-smmq6-we7px-ibdea-nondy-eae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets,
            subnet_id: Some(SubnetId::from(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            )),
            dc_id: None,
            operator_id: None,
        };

        let mut tg_map = BTreeSet::new();
        tg_map.insert(ptg);

        let vector_config = VectorServiceDiscoveryConfigEnriched::from(tg_map);
        assert!(vector_config.sources.contains_key(&sources_key));
        assert!(vector_config.transforms.contains_key(&transforms_key));

        let sources_config_endpoint = vector_config.sources.get(&sources_key);
        if let Some(conf) = sources_config_endpoint {
            assert_eq!(
                conf.endpoints[0],
                url::Url::parse(&("http://".to_owned() + original_addr))
                    .unwrap()
                    .to_string()
            )
        }
    }
}
