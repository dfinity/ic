use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::metrics::Metrics;
use crate::IcServiceDiscovery;
use crate::IcServiceDiscoveryImpl;
use crate::{config_generator::ConfigGenerator, job_types::JobType};
use crossbeam::select;
use crossbeam_channel::Receiver;
use slog::{info, warn};

pub fn make_poll_loop(
    log: slog::Logger,
    rt: tokio::runtime::Handle,
    ic_discovery: Arc<IcServiceDiscoveryImpl>,
    stop_signal: Receiver<()>,
    poll_interval: Duration,
    metrics: Metrics,
    config_generator: Option<Box<dyn ConfigGenerator>>,
    jobs: Vec<JobType>,
) -> impl FnMut() {
    let interval = crossbeam::channel::tick(poll_interval);
    move || {
        let mut tick = Instant::now();
        loop {
            let mut err = false;
            info!(log, "Loading new scraping targets (tick: {:?})", tick);
            if let Err(e) = ic_discovery.load_new_ics() {
                warn!(
                    log,
                    "Failed to load new scraping targets @ interval {:?}: {:?}", tick, e
                );
                metrics
                    .poll_error_count
                    .with_label_values(&["load_new_scraping_targets"])
                    .inc();
                err = true;
            }
            info!(log, "Update registries");
            let timer = metrics.registries_update_latency_seconds.start_timer();
            if let Err(e) = rt.block_on(ic_discovery.update_registries()) {
                warn!(
                    log,
                    "Failed to sync registry @ interval {:?}: {:?}", tick, e
                );
                metrics
                    .poll_error_count
                    .with_label_values(&["update_registries"])
                    .inc();
                err = true;
            }
            if let Some(config_generator) = &config_generator {
                for job in &jobs {
                    let targets = match ic_discovery.get_target_groups(*job) {
                        Ok(t) => t,
                        Err(e) => {
                            warn!(log, "Failed to retrieve targets for job {}: {:?}", job, e);
                            err = true;
                            continue;
                        }
                    };
                    if let Err(e) = config_generator.generate_config(*job, targets) {
                        warn!(
                            log,
                            "Failed to write targets for job {}: {:?}",
                            &job.to_string(),
                            e
                        );
                        err = true;
                    }
                }
            }
            std::mem::drop(timer);
            let poll_status = if err { "error" } else { "successful" };
            metrics.poll_count.with_label_values(&[poll_status]).inc();
            tick = select! {
                recv(stop_signal) -> _ => return,
                recv(interval) -> msg => msg.expect("tick failed!")
            };
        }
    }
}
