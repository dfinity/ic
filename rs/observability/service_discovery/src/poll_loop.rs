use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{metrics::Metrics, IcServiceDiscoveryImpl};
use crossbeam::select;
use crossbeam_channel::{Receiver, Sender};
use slog::{info, warn};

pub fn make_poll_loop(
    log: slog::Logger,
    rt: tokio::runtime::Handle,
    ic_discovery: Arc<IcServiceDiscoveryImpl>,
    stop_signal: Receiver<()>,
    poll_interval: Duration,
    metrics: Metrics,
    update_notifier: Option<Sender<()>>,
    amount_of_updaters: usize,
) -> impl FnMut() {
    let interval = crossbeam::channel::tick(poll_interval);
    move || {
        let mut tick = Instant::now();
        loop {
            let mut err = false;
            info!(log, "Loading new scraping targets (tick: {:?})", tick);
            if let Err(e) = ic_discovery.load_new_ics(log.clone()) {
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
            if let Some(sender) = &update_notifier {
                for _ in 0..amount_of_updaters {
                    if let Err(e) = sender.send(()) {
                        warn!(log, "Failed to send update signal : {:?}", e);
                    }
                }
            }
            std::mem::drop(timer);
            let poll_status = if err { "error" } else { "successful" };
            metrics.poll_count.with_label_values(&[poll_status]).inc();
            tick = select! {
                recv(stop_signal) -> _ => {
                    info!(log, "Received shutdown signal in poll_loop");
                    return
                },
                recv(interval) -> msg => msg.expect("tick failed!")
            };
        }
    }
}
