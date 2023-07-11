use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use config_writer_common::{
    labels_keys,
    vector_config_structure::{
        VectorConfigBuilder, VectorConfigEnriched, VectorSource, VectorTransform,
    },
};
use service_discovery::{job_types::JobType, TargetGroup};
use url::Url;

use crate::JobParameters;

pub struct VectorConfigBuilderImpl {
    proxy_url: Option<Url>,
    scrape_interval: u64,
    jobs_parameters: HashMap<JobType, JobParameters>,
}

impl VectorConfigBuilderImpl {
    pub fn new(
        proxy_url: Option<Url>,
        scrape_interval: u64,
        jobs_parameters: HashMap<JobType, JobParameters>,
    ) -> Self {
        Self {
            proxy_url,
            scrape_interval,
            jobs_parameters,
        }
    }

    fn add_target_groups_with_job(
        &self,
        targets: BTreeSet<TargetGroup>,
        job: JobType,
    ) -> VectorConfigEnriched {
        let mut config = VectorConfigEnriched::new();
        for target in targets {
            let key = target
                .clone()
                .targets
                .into_iter()
                .map(|t| t.to_string())
                .next()
                .unwrap();

            let source = VectorPrometheusScrapeSource::from_target_group_with_job(
                target.clone(),
                self.jobs_parameters.get(&job).unwrap(),
                self.scrape_interval,
                self.proxy_url.as_ref().cloned(),
            );
            let transform =
                VectorPrometheusScrapeTransform::from_target_group_with_job(target, &job);
            config.add_target_group(key, Box::new(source), Box::new(transform))
        }
        config
    }
}

impl VectorConfigBuilder for VectorConfigBuilderImpl {
    fn build(&self, target_groups: BTreeSet<TargetGroup>, job: JobType) -> VectorConfigEnriched {
        self.add_target_groups_with_job(target_groups, job)
    }
}

#[derive(Debug, Serialize, Clone)]
struct VectorPrometheusScrapeSource {
    #[serde(rename = "type")]
    _type: String,
    endpoints: Vec<String>,
    scrape_interval_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<VectorSourceProxy>,
    instance_tag: String,
    endpoint_tag: String,
}

impl VectorSource for VectorPrometheusScrapeSource {
    fn clone_dyn(&self) -> Box<dyn VectorSource> {
        Box::new(self.clone())
    }
}

impl VectorPrometheusScrapeSource {
    fn from_target_group_with_job(
        tg: TargetGroup,
        job_parameters: &JobParameters,
        scrape_interval: u64,
        proxy_url: Option<Url>,
    ) -> Self {
        let endpoints: Vec<String> = tg
            .targets
            .into_iter()
            .map(|g| g.to_string())
            .map(|g| format!("http://{}{}", g, job_parameters.endpoint))
            .map(|g| url::Url::parse(&g).unwrap())
            .map(|g| g.to_string())
            .collect();

        // TODO Pass URL through args

        let proxy = proxy_url.map(|url| VectorSourceProxy {
            enabled: true,
            http: Some(url),
            https: None,
        });

        Self {
            _type: "prometheus_scrape".into(),
            endpoints,
            scrape_interval_secs: scrape_interval,
            proxy,
            // proxy: Some(VectorSourceProxy {
            //     enabled: true,
            //     http: Some(proxy_url),
            //     https: None,
            // }),
            instance_tag: "instance".into(),
            endpoint_tag: "endpoint".into(),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct VectorSourceProxy {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<url::Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    https: Option<url::Url>,
}

#[derive(Debug, Serialize, Clone)]
struct VectorPrometheusScrapeTransform {
    #[serde(rename = "type")]
    _type: String,
    inputs: Vec<String>,
    source: String,
}

impl VectorTransform for VectorPrometheusScrapeTransform {
    fn clone_dyn(&self) -> Box<dyn VectorTransform> {
        Box::new(self.clone())
    }
}

impl VectorPrometheusScrapeTransform {
    fn from_target_group_with_job(tg: TargetGroup, job: &JobType) -> Self {
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert(labels_keys::IC_NAME.into(), tg.ic_name);
        labels.insert(labels_keys::IC_NODE.into(), tg.node_id.to_string());
        if let Some(subnet_id) = tg.subnet_id {
            labels.insert(labels_keys::IC_SUBNET.into(), subnet_id.to_string());
        }
        labels.insert(labels_keys::JOB.into(), job.to_string());
        Self {
            _type: "remap".into(),
            inputs: tg
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
    use std::{
        collections::{BTreeSet, HashMap},
        net::{SocketAddr, SocketAddrV6},
        str::FromStr,
    };

    use config_writer_common::vector_config_structure::VectorConfigBuilder;
    use ic_types::{NodeId, PrincipalId, SubnetId};
    use service_discovery::{
        job_types::{JobType, NodeOS},
        TargetGroup,
    };

    use service_discovery::jobs::Job;

    use crate::JobParameters;

    use super::{VectorConfigBuilderImpl, VectorPrometheusScrapeSource};

    #[test]
    fn try_from_prometheus_target_group_to_vector_config_correct_inputs() {
        let original_addr = "[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091";
        let sources_key = String::from(original_addr) + "-source";
        let mut targets = BTreeSet::new();

        targets.insert(SocketAddr::V6(
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
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        };

        let mut tg_set = BTreeSet::new();
        tg_set.insert(ptg);
        let job_params = get_jobs_parameters();

        let vector_config_builder = VectorConfigBuilderImpl::new(None, 30, job_params);
        let vector_config = vector_config_builder.build(tg_set, JobType::Orchestrator);

        let binding = vector_config.get_sources();
        let sources_config_endpoint = binding.get(&sources_key);

        if let Some(conf) = sources_config_endpoint {
            let downcast = conf
                .as_any()
                .downcast_ref::<VectorPrometheusScrapeSource>()
                .unwrap();
            assert_eq!(
                downcast.endpoints[0],
                url::Url::parse(&("http://".to_owned() + original_addr))
                    .unwrap()
                    .to_string()
            )
        }
    }

    fn jobs() -> Vec<Job> {
        vec![
            Job {
                _type: JobType::NodeExporter(NodeOS::Guest),
                port: 9100,
                endpoint: "/metrics",
            },
            Job {
                _type: JobType::NodeExporter(NodeOS::Host),
                port: 9100,
                endpoint: "/metrics",
            },
            Job {
                _type: JobType::Orchestrator,
                port: 9091,
                endpoint: "/",
            },
            Job {
                _type: JobType::Replica,
                port: 9090,
                endpoint: "/",
            },
        ]
    }

    fn get_jobs_parameters() -> HashMap<JobType, JobParameters> {
        jobs()
            .iter()
            .map(|job| {
                (
                    job._type,
                    JobParameters {
                        port: job.port,
                        endpoint: job.endpoint.to_string(),
                    },
                )
            })
            .collect()
    }
}
