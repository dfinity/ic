//! An experimental component that allows scraping logs using the http-endpoint
//! exposed by systemd-journal-gatewayd.
use crossbeam::select;
use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::Receiver;
use slog::{info, warn};

use service_discovery::{job_types::JobType, IcServiceDiscovery};

use crate::config_writer::ConfigWriter;

pub fn config_writer_loop(
    log: slog::Logger,
    discovery: Arc<dyn IcServiceDiscovery>,
    filter: Option<String>,
    shutdown_signal: Receiver<()>,
    job: JobType,
    update_signal_recv: Receiver<()>,
    vector_config_dir: PathBuf,
) -> impl FnMut() {
    move || {
        let mut config_writer =
            ConfigWriter::new(vector_config_dir.clone(), filter.clone(), log.clone());
        loop {
            let targets = match discovery.get_target_groups(job) {
                Ok(t) => t,
                Err(e) => {
                    warn!(log, "Failed to retrieve targets for job {}: {:?}", job, e);
                    continue;
                }
            };
            if let Err(e) = config_writer.write_config(job, targets) {
                warn!(
                    log,
                    "Failed to write config for targets for job {}: {:?}", job, e
                );
            };
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
