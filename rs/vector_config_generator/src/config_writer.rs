//! Write json-files containing target information for file-based service
//! discovery configuration of prometheus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use crate::vector_configuration::VectorServiceDiscoveryConfigEnriched;

use regex::Regex;
use service_discovery::{config_generator::ConfigGenerator, TargetGroup};

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
                .any(|status| status)
        }
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
}

impl ConfigWriter {
    pub fn new<P: AsRef<Path>>(write_path: P, filters: TargetGroupFilterList) -> Self {
        ConfigWriter {
            base_directory: PathBuf::from(write_path.as_ref()),
            last_targets: Default::default(),
            filters,
        }
    }

    /// Write configuration files for the job `job_name`.
    ///
    /// The assumption is that no external process manipulates or deletes the written files.
    /// FileSd will memoize the calls. Thus, calling this method twice with the
    /// same arguments will have no effect.
    pub fn write_config(
        &self,
        job_name: &str,
        target_groups: BTreeSet<TargetGroup>,
    ) -> std::io::Result<()> {
        let mut last_targets = self.last_targets.write().unwrap();
        let last_job_targets = last_targets.entry(job_name.to_string()).or_default();
        if last_job_targets == &target_groups {
            return Ok(());
        }
        let target_path = self.base_directory.join(format!("{}.json", job_name));

        let filtered_target_groups: BTreeSet<TargetGroup> = target_groups
            .clone()
            .into_iter()
            .filter(|tg| self.filters.filter(tg.clone()))
            .collect();

        let vector_config = VectorServiceDiscoveryConfigEnriched::from(filtered_target_groups);

        ic_utils::fs::write_atomically(target_path.as_path(), |f| {
            serde_json::to_writer_pretty(f, &vector_config).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Serialization error: {:?}", e),
                )
            })
        })?;
        last_targets.insert(job_name.to_string(), target_groups);
        Ok(())
    }
}

impl ConfigGenerator for ConfigWriter {
    fn generate_config(
        &self,
        job_name: &str,
        target_groups: BTreeSet<TargetGroup>,
    ) -> std::io::Result<()> {
        self.write_config(job_name, target_groups)
    }
}
