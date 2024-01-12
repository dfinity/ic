use std::collections::{BTreeMap, BTreeSet};

use ic_types::PrincipalId;
use serde::{Serialize, Serializer};
use service_discovery::job_types::JobType;
use service_discovery::jobs::Job;

use crate::{builders::ConfigBuilder, contracts::target::TargetDto};

#[derive(Serialize, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct PrometheusStaticConfig {
    pub targets: BTreeSet<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PrometheusFileSdConfig {
    configs: BTreeSet<PrometheusStaticConfig>,
    updated: bool,
}

impl Serialize for PrometheusFileSdConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.configs.clone())
    }
}

#[derive(Debug, Clone)]
pub struct PrometheusConfigBuilder {}

fn get_endpoints(target_group: TargetDto, job: JobType) -> BTreeSet<String> {
    let binding = Job::all();
    let job = binding.iter().find(|j| j._type == job).unwrap();

    target_group
        .targets
        .iter()
        .map(|g| {
            let mut g = *g;
            g.set_port(job.port);
            format!(
                "{}://{}/{}",
                job.scheme,
                g,
                job.endpoint.trim_start_matches('/'),
            )
        })
        .collect()
}

const IC_NAME: &str = "ic";
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";
const JOB: &str = "job";
// TODO: Re-add the labels below once we resolve the issues with the public dashboard queries
// https://dfinity.atlassian.net/browse/OB-442
// const DC: &str = "dc";
// const NODE_PROVIDER_ID: &str = "node_provider_id";
// const NODE_OPERATOR_ID: &str = "node_operator_id";

pub fn map_target_group(target_groups: BTreeSet<TargetDto>) -> BTreeSet<PrometheusStaticConfig> {
    target_groups
        .into_iter()
        .flat_map(|tg| {
            let mut ret = vec![];
            for job in &tg.jobs {
                ret.push(PrometheusStaticConfig {
                    targets: get_endpoints(tg.clone(), *job),
                    labels: {
                        let anonymous = PrincipalId::new_anonymous().to_string();
                        let mut node_id = tg.node_id.to_string();
                        if node_id == anonymous {
                            node_id = tg.name.clone()
                        }
                        let mut labels = BTreeMap::new();
                        labels.insert(IC_NAME.into(), tg.ic_name.clone());
                        labels.insert(IC_NODE.into(), node_id);
                        if let Some(subnet_id) = tg.subnet_id {
                            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
                        }
                        labels.insert(JOB.into(), job.to_string());
                        labels.extend(tg.custom_labels.clone().into_iter());
                        // TODO: Re-add the labels below once we resolve the issues with the public dashboard queries
                        // https://dfinity.atlassian.net/browse/OB-442
                        // labels.insert(DC.into(), tg.dc_id.clone());
                        // labels.insert(NODE_PROVIDER_ID.into(), tg.node_provider_id.to_string());
                        // labels.insert(NODE_OPERATOR_ID.into(), tg.operator_id.to_string());
                        labels
                    },
                })
            }
            ret
        })
        .collect()
}

impl ConfigBuilder for PrometheusConfigBuilder {
    fn build(&self, target_groups: BTreeSet<TargetDto>) -> String {
        let new_configs: BTreeSet<PrometheusStaticConfig> = map_target_group(target_groups);

        serde_json::to_string_pretty(&new_configs).unwrap()
    }
}
