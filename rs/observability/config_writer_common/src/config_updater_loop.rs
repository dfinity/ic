use std::{collections::BTreeSet, sync::Arc};

use crossbeam::select;
use crossbeam_channel::Receiver;
use service_discovery::metrics::Metrics;
use service_discovery::{jobs::Job, IcServiceDiscovery, TargetGroup};
use slog::{info, warn};

use crate::{
    config_builder::ConfigBuilder, config_updater::ConfigUpdater, filters::TargetGroupFilter,
};

pub fn config_updater_loop(
    log: slog::Logger,
    discovery: Arc<dyn IcServiceDiscovery>,
    filters: Arc<dyn TargetGroupFilter>,
    shutdown_signal: Receiver<()>,
    jobs: Vec<Job>,
    update_signal_recv: Receiver<()>,
    mut config_builder: impl ConfigBuilder,
    config_updater: impl ConfigUpdater,
    metrics: Metrics,
) -> impl FnMut() {
    move || loop {
        for job in &jobs {
            let target_groups = match discovery.get_target_groups(job._type, log.clone()) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        log,
                        "Failed to retrieve targets for job {}: {:?}", job._type, e
                    );
                    continue;
                }
            };
            let filtered_target_groups: BTreeSet<TargetGroup> = target_groups
                .clone()
                .into_iter()
                .filter(|tg| TargetGroupFilter::filter(filters.as_ref(), tg.clone()))
                .collect();

            metrics
                .total_targets
                .with_label_values(&[job._type.to_string().as_str()])
                .set(target_groups.len().try_into().unwrap());

            let config = config_builder.build(filtered_target_groups, job.clone());
            let config_binding = config.as_ref();
            if let Err(e) = config_updater.update(config_binding) {
                warn!(log, "Failed to write config {}: {:?}", &config.name(), e);
            };
        }
        select! {
            recv(shutdown_signal) -> _ => {
                    info!(log, "Received shutdown signal");
                    break;
                },
            recv(update_signal_recv) -> _ => continue,
        };
    }
}
