use std::collections::{BTreeMap, BTreeSet, HashMap};

use config_writer_common::{
    config_builder::{Config, ConfigBuilder},
    labels_keys,
};
use serde::{Serialize, Serializer};
use service_discovery::{job_types::JobType, jobs::Job, TargetGroup};

#[derive(Serialize, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct PrometheusStaticConfig {
    targets: BTreeSet<String>,
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PrometheusFileSdConfig {
    configs: BTreeSet<PrometheusStaticConfig>,
    job: JobType,
    updated: bool,
}

impl Config for PrometheusFileSdConfig {
    fn updated(&self) -> bool {
        self.updated
    }

    fn name(&self) -> String {
        self.job.to_string()
    }
}

impl Serialize for PrometheusFileSdConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.configs.clone().into_iter())
    }
}

pub struct PrometheusConfigBuilder {
    configs_cache: HashMap<JobType, PrometheusFileSdConfig>,
}

impl PrometheusConfigBuilder {
    pub fn new() -> Self {
        PrometheusConfigBuilder {
            configs_cache: HashMap::new(),
        }
    }

    pub fn set_old_config(&mut self, job: JobType, config: PrometheusFileSdConfig) {
        self.configs_cache.insert(job, config);
    }

    pub fn get_old_config(&self, job: JobType) -> Option<PrometheusFileSdConfig> {
        self.configs_cache.get(&job).cloned()
    }
}

fn get_endpoints(target_group: TargetGroup, _job: Job) -> BTreeSet<String> {
    target_group
        .targets
        .into_iter()
        .map(|g| g.to_string())
        .collect()
}

impl ConfigBuilder for PrometheusConfigBuilder {
    fn build(&mut self, target_groups: BTreeSet<TargetGroup>, job: Job) -> Box<dyn Config> {
        let new_configs: BTreeSet<PrometheusStaticConfig> = target_groups
            .into_iter()
            .map(|tg| PrometheusStaticConfig {
                targets: get_endpoints(tg.clone(), job.clone()),
                labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert(labels_keys::IC_NAME.into(), tg.ic_name);
                    labels.insert(labels_keys::IC_NODE.into(), tg.node_id.to_string());
                    if let Some(subnet_id) = tg.subnet_id {
                        labels.insert(labels_keys::IC_SUBNET.into(), subnet_id.to_string());
                    }
                    labels.insert(labels_keys::JOB.into(), job._type.to_string());
                    labels
                },
            })
            .collect();

        let updated = match self.get_old_config(job._type) {
            None => true,
            Some(config) if config.configs == new_configs => false,
            Some(_) => true,
        };

        let new_file_config = PrometheusFileSdConfig {
            configs: new_configs,
            job: job._type,
            updated,
        };

        if updated {
            self.set_old_config(job._type, new_file_config.clone());
        }

        Box::new(new_file_config)
    }
}

#[cfg(test)]
mod prometheus_serialize {
    use std::{collections::BTreeSet, net::SocketAddrV6, str::FromStr};

    use ic_types::{NodeId, PrincipalId, SubnetId};
    use serde_json::json;
    use service_discovery::TargetGroup;

    use crate::{jobs, prometheus_config::PrometheusConfigBuilder};
    use config_writer_common::config_builder::ConfigBuilder;

    use super::get_endpoints;

    fn create_dummy_target_group(ipv6: &str, with_subnet_id: bool) -> TargetGroup {
        let mut targets = BTreeSet::new();
        targets.insert(std::net::SocketAddr::V6(
            SocketAddrV6::from_str(ipv6).unwrap(),
        ));
        let subnet_id = match with_subnet_id {
            true => Some(SubnetId::from(PrincipalId::new_anonymous())),
            false => None,
        };
        TargetGroup {
            node_id: NodeId::from(PrincipalId::new_anonymous()),
            ic_name: "mercury".into(),
            targets,
            subnet_id,
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        }
    }

    #[test]
    fn basic() {
        let mut cb = Box::new(PrometheusConfigBuilder::new()) as Box<dyn ConfigBuilder>;
        let mut target_groups: BTreeSet<TargetGroup> = BTreeSet::new();

        let tg1 = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091", true);
        target_groups.insert(tg1.clone());

        let tg2 = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c87]:9091", false);
        target_groups.insert(tg2.clone());

        let config = cb.build(target_groups, jobs::JOB_REPLICA);

        let expected_config = json!(
            [
                {
                    "targets": [
                        "[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091"
                    ],
                    "labels": {
                        "ic": tg1.ic_name,
                        "ic_node": tg1.node_id.to_string(),
                        "ic_subnet": tg1.subnet_id.unwrap().to_string(),
                        "job": "replica",
                    }
                },
                {
                    "targets": [
                        "[2a02:800:2:2003:6801:f6ff:fec4:4c87]:9091"
                    ],
                    "labels": {
                        "ic": tg2.ic_name,
                        "ic_node": tg2.node_id.to_string(),
                        "job": "replica",
                    }
                }
            ]
        );
        assert_eq!(json!(config), json!(expected_config));
    }

    #[test]
    fn updated() {
        let mut cb = Box::new(PrometheusConfigBuilder::new()) as Box<dyn ConfigBuilder>;
        let mut target_groups: BTreeSet<TargetGroup> = BTreeSet::new();

        let tg1 = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091", true);
        target_groups.insert(tg1);

        let config = cb.build(target_groups.clone(), jobs::JOB_REPLICA);
        assert!(config.updated());

        let config = cb.build(target_groups.clone(), jobs::JOB_REPLICA);
        assert!(!config.updated());

        let tg2 = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c87]:9091", true);
        target_groups.insert(tg2);

        let config = cb.build(target_groups.clone(), jobs::JOB_REPLICA);
        assert!(config.updated());
    }

    #[test]
    fn test_get_endpoints() {
        let target_group =
            create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c87]:9091", true);
        let endpoints = get_endpoints(target_group, jobs::JOB_REPLICA);
        let mut expected_endpoints = BTreeSet::new();
        expected_endpoints.insert("[2a02:800:2:2003:6801:f6ff:fec4:4c87]:9091".to_string());

        assert_eq!(endpoints, expected_endpoints)
    }
}
