//! An experimental component that allows scraping logs using the http-endpoint
//! exposed by systemd-journal-gatewayd.
use crossbeam::select;
use crossbeam_channel::Receiver;
use regex::Regex;
use service_discovery::{config_generator::ConfigGenerator, job_types::JobType};
use slog::{info, warn};
use std::path::PathBuf;
use std::sync::Arc;

use service_discovery::IcServiceDiscovery;

use crate::config_writer::{
    ConfigWriter, NodeIDRegexFilter, OldMachinesFilter, TargetGroupFilter, TargetGroupFilterList,
};

pub fn config_writer_loop(
    log: slog::Logger,
    discovery: Arc<dyn IcServiceDiscovery>,
    shutdown_signal: Receiver<()>,
    jobs: Vec<JobType>,
    update_signal_recv: Receiver<()>,
    generation_dir: PathBuf,
    regex: Option<Regex>,
) -> impl FnMut() {
    move || {
        let mut filters_vec: Vec<Box<dyn TargetGroupFilter>> = vec![];
        if let Some(filter_node_id_regex) = &regex {
            filters_vec.push(Box::new(NodeIDRegexFilter::new(
                filter_node_id_regex.clone(),
            )));
        };

        filters_vec.push(Box::new(OldMachinesFilter {}));

        let filters = TargetGroupFilterList::new(filters_vec);

        let config_writer = ConfigWriter::new(generation_dir.clone(), filters);
        loop {
            for job in &jobs {
                let targets = match discovery.get_target_groups(*job) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(log, "Failed to retrieve targets for job {}: {:?}", job, e);
                        continue;
                    }
                };
                if let Err(e) = config_writer.generate_config(*job, targets) {
                    warn!(log, "Failed to write targets for job {}: {:?}", job, e);
                }
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
