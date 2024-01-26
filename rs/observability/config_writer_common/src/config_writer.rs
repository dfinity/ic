use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
};

use service_discovery::{job_types::JobType, TargetGroup};

use crate::{
    config_builder::Config, config_updater::ConfigUpdater, filters::TargetGroupFilter,
    vector_config_structure::VectorConfigBuilder,
};
use slog::{debug, Logger};

#[derive(Debug)]
pub struct ConfigWriter {
    base_directory: PathBuf,
    last_targets: BTreeMap<String, BTreeSet<TargetGroup>>,
    filters: Arc<dyn TargetGroupFilter>,
    log: slog::Logger,
}

impl ConfigWriter {
    pub fn new<P: AsRef<Path>>(
        write_path: P,
        filters: Arc<dyn TargetGroupFilter>,
        log: Logger,
    ) -> Self {
        ConfigWriter {
            base_directory: PathBuf::from(write_path.as_ref()),
            last_targets: Default::default(),
            filters,
            log,
        }
    }

    /// Write configuration files for the job `job_name`.
    ///
    /// The assumption is that no external process manipulates or deletes the written files.
    /// FileSd will memoize the calls. Thus, calling this method twice with the
    /// same arguments will have no effect.
    pub fn write_config(
        &mut self,
        job: JobType,
        target_groups: BTreeSet<TargetGroup>,
        vector_config_builder: &impl VectorConfigBuilder,
    ) -> std::io::Result<()> {
        let last_job_targets = self.last_targets.entry(job.to_string()).or_default();
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

        let filtered_target_groups: BTreeSet<TargetGroup> = target_groups
            .clone()
            .into_iter()
            .filter(|tg| self.filters.filter(tg.clone()))
            .collect();

        let vector_config = vector_config_builder.build(filtered_target_groups, job);

        ic_sys::fs::write_atomically(target_path.as_path(), |f| {
            serde_json::to_writer_pretty(f, &vector_config).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Serialization error: {:?}", e),
                )
            })
        })?;
        self.last_targets.insert(job.to_string(), target_groups);
        Ok(())
    }
}

impl ConfigUpdater for ConfigWriter {
    fn update(&self, config: &dyn Config) -> Result<(), Box<dyn Error>> {
        if !config.updated() {
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
        let target_path = self.base_directory.join(format!("{}.json", config.name()));

        ic_sys::fs::write_atomically(target_path.as_path(), |f| {
            serde_json::to_writer_pretty(f, &config).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Serialization error: {:?}", e),
                )
            })
        })?;
        Ok(())
    }
}
