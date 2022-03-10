use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ic_discovery::PrometheusTargetGroup;

/// Record of the shape as described in
/// https://prometheus.io/docs/prometheus/latest/http_sd/
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ServiceDiscoveryRecord {
    targets: Vec<String>,             // targets: ["ip:port"]
    labels: BTreeMap<String, String>, // labels: { k: v, k : v}
}

impl From<PrometheusTargetGroup> for ServiceDiscoveryRecord {
    fn from(group: PrometheusTargetGroup) -> Self {
        let targets: Vec<_> = group.targets.into_iter().map(|x| x.to_string()).collect();
        let mut labels = BTreeMap::new();

        labels.insert(IC_NAME.into(), group.ic_name);
        labels.insert(IC_NODE.into(), group.node_id.to_string());
        if let Some(subnet_id) = group.subnet_id {
            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
        }
        Self { targets, labels }
    }
}

// Default labels
const IC_NAME: &str = "ic";
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";
