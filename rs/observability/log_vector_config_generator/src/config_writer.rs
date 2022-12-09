//! Write json-files containing target information for file-based service
//! discovery configuration of prometheus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    path::{Path, PathBuf},
};

use service_discovery::{job_types::JobType, TargetGroup};
use slog::{debug, Logger};

use crate::vector_config_structure::VectorServiceDiscoveryConfigEnriched;

#[derive(Debug)]
pub struct ConfigWriter {
    base_directory: PathBuf,
    last_targets: BTreeMap<String, BTreeSet<TargetGroup>>,
    filter: Option<String>,
    log: slog::Logger,
}

impl ConfigWriter {
    pub fn new<P: AsRef<Path>>(write_path: P, filter: Option<String>, log: Logger) -> Self {
        ConfigWriter {
            base_directory: PathBuf::from(write_path.as_ref()),
            last_targets: Default::default(),
            filter,
            log,
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
        let mut last_targets = self.last_targets.clone();
        let last_job_targets = last_targets.entry(job.to_string()).or_default();
        if last_job_targets == &target_groups {
            debug!(
                self.log,
                "Targets didn't change, skipped regenerating config"
            );
            return Ok(());
        }
        debug!(
            self.log,
            "Targets changed, proceeding with regenerating config"
        );
        let target_path = self.base_directory.join(format!("{}.json", job));

        let mut groups_for_filtering = target_groups.clone();
        if let Some(filter) = &self.filter {
            groups_for_filtering.retain(&parse_filter(filter.to_string()));
        }
        let vector_config = VectorServiceDiscoveryConfigEnriched::from(groups_for_filtering);

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

fn parse_filter(filter: String) -> impl Fn(&TargetGroup) -> bool {
    move |p: &TargetGroup| {
        let mut parts = filter.split('=');
        let key = parts.next().unwrap().to_string();
        let value = parts.next().unwrap().to_string();
        match key.as_str() {
            "node_id" => p.node_id.to_string() == value,
            "subnet_id" => p
                .subnet_id
                .map(|s| s.to_string() == value)
                .unwrap_or_default(),
            _ => unimplemented!("filter {} not implemented", key),
        }
    }
}
