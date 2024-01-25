//! An experimental component that allows scraping logs using the http-endpoint
//! exposed by systemd-journal-gatewayd.
use crossbeam::select;
use service_discovery::metrics::Metrics;
use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::Receiver;
use slog::{info, warn};

use service_discovery::{job_types::JobType, IcServiceDiscovery};

use crate::config_writer::ConfigWriter;
use crate::filters::TargetGroupFilter;
use crate::vector_config_structure::VectorConfigBuilder;

pub fn config_writer_loop(
    log: slog::Logger,
    discovery: Arc<dyn IcServiceDiscovery>,
    filters: Arc<dyn TargetGroupFilter>,
    shutdown_signal: Receiver<()>,
    jobs: Vec<JobType>,
    update_signal_recv: Receiver<()>,
    vector_config_dir: PathBuf,
    vector_config_builder: impl VectorConfigBuilder,
    metrics: Metrics,
) -> impl FnMut() {
    move || {
        let mut config_writer =
            ConfigWriter::new(vector_config_dir.clone(), filters.clone(), log.clone());
        loop {
            for job in &jobs {
                let targets = match discovery.get_target_groups(*job, log.clone()) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(log, "Failed to retrieve targets for job {}: {:?}", job, e);
                        continue;
                    }
                };
                metrics
                    .total_targets
                    .with_label_values(&[job.to_string().as_str()])
                    .set(targets.len().try_into().unwrap());
                if let Err(e) = config_writer.write_config(*job, targets, &vector_config_builder) {
                    warn!(
                        log,
                        "Failed to write config for targets for job {}: {:?}", job, e
                    );
                };
            }
            select! {
                recv(shutdown_signal) -> _ => {
                        info!(log, "Received shutdown signal in log_scraper");
                        break;
                    },
                recv(update_signal_recv) -> _ => continue,
            };
        }
    }
}
