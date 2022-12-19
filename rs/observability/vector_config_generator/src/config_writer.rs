//! Write json-files containing target information for file-based service
//! discovery configuration of prometheus.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Debug,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use crate::{vector_configuration::VectorServiceDiscoveryConfigEnriched, JobParameters};

use regex::Regex;
use service_discovery::{config_generator::ConfigGenerator, job_types::JobType, TargetGroup};
use url::Url;

pub trait TargetGroupFilter: Send + Sync + Debug {
    fn filter(&self, target_groups: TargetGroup) -> bool;
}

#[derive(Debug)]
pub struct NodeIDRegexFilter {
    regex: Regex,
}

impl NodeIDRegexFilter {
    pub fn new(regex: Regex) -> Self {
        Self { regex }
    }
}

impl TargetGroupFilter for NodeIDRegexFilter {
    fn filter(&self, target_group: TargetGroup) -> bool {
        self.regex.is_match(&target_group.node_id.to_string())
    }
}

/// OldMachinesFilter will remove target groups with a target containing a 5000 as the
/// 5th field of their IPv6 address.
/// These machines were previously deployed manually by the DFINITY team, and are in
/// the process of being redeployed, so this filter should not be relevant for too long.
///
/// Feel free to inspect the machines and remove this filter when the redeployment is done
/// for all DCs.
#[derive(Debug)]
pub struct OldMachinesFilter {}

impl TargetGroupFilter for OldMachinesFilter {
    fn filter(&self, target_group: TargetGroup) -> bool {
        target_group
            .targets
            .iter()
            // Maps addresses to true if they are new
            .map(|sockaddr| !matches!(sockaddr.ip(), IpAddr::V6(a) if a.segments()[4] == 0x5000))
            .all(|is_new| is_new)
    }
}

#[derive(Debug)]
pub struct TargetGroupFilterList {
    filters: Vec<Box<dyn TargetGroupFilter>>,
}

impl TargetGroupFilterList {
    pub fn new(filters: Vec<Box<dyn TargetGroupFilter>>) -> Self {
        Self { filters }
    }
}

impl TargetGroupFilter for TargetGroupFilterList {
    fn filter(&self, target_group: TargetGroup) -> bool {
        // If the group is empty, consider that as having no filter, thus always accept the element
        if self.filters.is_empty() {
            true
        } else {
            self.filters
                .iter()
                .map(|f| f.filter(target_group.clone()))
                .all(|status| status)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddrV6, str::FromStr};

    use ic_types::{NodeId, PrincipalId, SubnetId};
    use regex::Regex;
    use service_discovery::TargetGroup;

    use crate::config_writer::TargetGroupFilter;

    use super::{NodeIDRegexFilter, OldMachinesFilter, TargetGroupFilterList};

    fn create_dummy_target_group(ipv6: &str) -> TargetGroup {
        let mut targets = BTreeSet::new();
        targets.insert(std::net::SocketAddr::V6(
            SocketAddrV6::from_str(ipv6).unwrap(),
        ));
        TargetGroup {
            node_id: NodeId::from(PrincipalId::new_anonymous()),
            ic_name: "mercury".into(),
            targets,
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: None,
            operator_id: None,
        }
    }

    #[test]
    fn old_machine_filter_test() {
        let filter = OldMachinesFilter {};

        let new_tg = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091");
        assert!(filter.filter(new_tg));

        let old_tg = create_dummy_target_group("[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091");
        assert!(!filter.filter(old_tg));
    }

    #[test]
    fn old_machine_filter_test_no_targets() {
        let filter = OldMachinesFilter {};
        let tg = TargetGroup {
            node_id: NodeId::from(PrincipalId::new_anonymous()),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: None,
            operator_id: None,
        };
        assert!(filter.filter(tg));
    }

    #[test]
    fn node_id_regex_filter_test() {
        let filter = NodeIDRegexFilter::new(Regex::new("^i").unwrap());

        let accepted_tg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "iylgr-zpxwq-kqgmf-4srtx-o4eey-d6bln-smmq6-we7px-ibdea-nondy-eae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: None,
            operator_id: None,
        };
        assert!(filter.filter(accepted_tg));

        let rejected_tg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: None,
            operator_id: None,
        };
        assert!(!filter.filter(rejected_tg));
    }

    #[test]
    fn filter_list_test() {
        let filter_vec: Vec<Box<dyn TargetGroupFilter>> = vec![
            Box::new(NodeIDRegexFilter::new(Regex::new("^i").unwrap())),
            Box::new(OldMachinesFilter {}),
        ];
        let filterlist = TargetGroupFilterList::new(filter_vec);

        let accepted_tg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "iylgr-zpxwq-kqgmf-4srtx-o4eey-d6bln-smmq6-we7px-ibdea-nondy-eae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: None,
            operator_id: None,
        };
        assert!(filterlist.filter(accepted_tg));

        let rejected_tg_1 = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: None,
            operator_id: None,
        };
        assert!(!filterlist.filter(rejected_tg_1));

        let old_tg = create_dummy_target_group("[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091");
        assert!(!filterlist.filter(old_tg));
    }

    #[test]
    fn filter_list_test_empty() {
        let filterlist = TargetGroupFilterList::new(vec![]);
        let tg = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091");
        assert!(filterlist.filter(tg));
    }
}

#[derive(Debug)]
pub struct ConfigWriter {
    /// The base directory where the configuration files will be written to.
    base_directory: PathBuf,
    /// Mapping from job name to targets.
    /// This allows to not change the file in case the targets have not changed
    last_targets: Arc<RwLock<BTreeMap<String, BTreeSet<TargetGroup>>>>,
    /// Filters the returned config basaed on different patterns
    filters: TargetGroupFilterList,
    /// Maps the job type to parameters required for writing the config
    jobs_parameters: HashMap<JobType, JobParameters>,
    /// Vector scrape interval
    scrape_interval: u64,
    /// URL of the proxy to use when generating the config
    proxy_url: Option<Url>,
}

impl ConfigWriter {
    pub fn new<P: AsRef<Path>>(
        write_path: P,
        filters: TargetGroupFilterList,
        jobs_parameters: HashMap<JobType, JobParameters>,
        scrape_interval: u64,
        proxy_url: Option<Url>,
    ) -> Self {
        ConfigWriter {
            base_directory: PathBuf::from(write_path.as_ref()),
            last_targets: Default::default(),
            filters,
            jobs_parameters,
            scrape_interval,
            proxy_url,
        }
    }

    /// Write configuration files for the job `job_name`.
    ///
    /// The assumption is that no external process manipulates or deletes the written files.
    /// FileSd will memoize the calls. Thus, calling this method twice with the
    /// same arguments will have no effect.
    pub fn write_config(
        &self,
        job: JobType,
        target_groups: BTreeSet<TargetGroup>,
    ) -> std::io::Result<()> {
        let mut last_targets = self.last_targets.write().unwrap();
        let last_job_targets = last_targets.entry(job.to_string()).or_default();
        if last_job_targets == &target_groups {
            return Ok(());
        }
        let target_path = self.base_directory.join(format!("{}.json", job));

        let filtered_target_groups: BTreeSet<TargetGroup> = target_groups
            .clone()
            .into_iter()
            .filter(|tg| self.filters.filter(tg.clone()))
            .collect();

        let vector_config = VectorServiceDiscoveryConfigEnriched::from_target_groups_with_job(
            filtered_target_groups,
            &job,
            self.jobs_parameters.get(&job).unwrap(),
            self.scrape_interval,
            self.proxy_url.clone(),
        );

        ic_utils::fs::write_atomically(target_path.as_path(), |f| {
            serde_json::to_writer_pretty(f, &vector_config).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Serialization error: {:?}", e),
                )
            })
        })?;
        last_targets.insert(job.to_string(), target_groups);
        Ok(())
    }
}

impl ConfigGenerator for ConfigWriter {
    fn generate_config(
        &self,
        job: JobType,
        target_groups: BTreeSet<TargetGroup>,
    ) -> std::io::Result<()> {
        self.write_config(job, target_groups)
    }
}
