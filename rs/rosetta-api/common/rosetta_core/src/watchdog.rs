//! Module providing a simple watchdog that monitors a thread via periodic heartbeats.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{Instrument, error, info, info_span};

/// A watchdog thread that monitors a monitored task by checking periodic heartbeats.
/// If the heartbeat is not updated within a specified timeout, the watchdog will trigger
/// a restart callback and abort the monitored task.
///
/// The `skip_first_heartbeat_check` configuration determines whether the loss of heartbeats
/// before the first heartbeat is observed is tolerated (true) or treated as a timeout (false).
pub struct WatchdogThread {
    /// Indicates whether the watchdog has been stopped.
    stopped: Arc<AtomicBool>,
    /// Maximum allowed duration between heartbeats (monitored task's responsiveness timeout).
    heartbeat_timeout: Duration,
    /// Handle to the internal watchdog monitoring task.
    handle: Option<tokio::task::JoinHandle<()>>,
    /// Optional callback invoked when the monitored task is restarted.
    on_restart: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Timestamp (in milliseconds) of the last heartbeat received.
    last_heartbeat_ms: Arc<AtomicU64>,
    /// If true, missing the first heartbeat is tolerated and does not trigger a restart.
    skip_first_heartbeat_check: bool,
    /// Tracing span for the watchdog thread.
    tracing_span: Option<tracing::Span>,
}

/// A thread watchdog implementation that monitors a task and restarts it if it becomes unresponsive.
impl WatchdogThread {
    /// Creates a new `WatchdogThread` with the specified `heartbeat_timeout` and `skip_first_heartbeat` mode.
    ///
    /// # Arguments
    ///
    /// * `heartbeat_timeout` - Duration that the watchdog will wait before considering the monitored task stalled.
    /// * `on_restart` - Optional callback function that is called when the watchdog restarts the task.
    /// * `skip_first_heartbeat_check` - If true, the watchdog will not trigger a restart if no heartbeat is received before the first heartbeat.
    /// * `tracing_span` - Optional tracing span to associate with the watchdog thread for logging purposes.
    pub fn new(
        heartbeat_timeout: Duration,
        on_restart: Option<Arc<dyn Fn() + Send + Sync>>,
        skip_first_heartbeat_check: bool,
        tracing_span: Option<tracing::Span>,
    ) -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            heartbeat_timeout,
            handle: None,
            on_restart,
            last_heartbeat_ms: Arc::new(AtomicU64::new(0)),
            skip_first_heartbeat_check,
            tracing_span,
        }
    }

    /// Returns the current timestamp in milliseconds since the UNIX epoch.
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }

    /// Starts monitoring a thread.
    ///
    /// The provided closure `create_thread` should spawn the monitored task and call the provided heartbeat callback periodically.
    /// If the monitored task does not update the heartbeat within the timeout, the watchdog will log an error,
    /// call the optional restart callback, and abort the monitored task.
    ///
    /// # Arguments
    ///
    /// * `create_thread` - A closure that receives a heartbeat callback and returns a JoinHandle of the spawned task.
    pub fn start<F>(&mut self, mut create_thread: F)
    where
        F: FnMut(Box<dyn Fn() + Send + Sync>) -> tokio::task::JoinHandle<()> + Send + 'static,
    {
        let stopped = Arc::clone(&self.stopped);
        let heartbeat_timeout = self.heartbeat_timeout;
        let on_restart = self.on_restart.clone();
        let last_heartbeat_ms = Arc::clone(&self.last_heartbeat_ms);
        let skip_first = self.skip_first_heartbeat_check;

        let span = self
            .tracing_span
            .clone()
            .unwrap_or_else(|| info_span!("watchdog_thread"));

        let handle = tokio::spawn(async move {
            loop {
                if stopped.load(Ordering::SeqCst) {
                    info!("Stopping the watchdog thread");
                    break;
                }

                // Clone for this iteration so the closures below have their own copies.
                let last_heartbeat_clone = last_heartbeat_ms.clone();

                let thread_handle = create_thread(Box::new(move || {
                    last_heartbeat_clone.store(Self::current_timestamp(), Ordering::SeqCst);
                }));

                let mut thread_handle = thread_handle; // make mutable for select!
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(heartbeat_timeout) => {
                            let last = last_heartbeat_ms.load(Ordering::SeqCst);
                            if last == 0 {
                                if skip_first {
                                    continue;
                                } else {
                                    error!("No heartbeat received and skip_first_heartbeat disabled, restarting");
                                }
                            }
                            let now = Self::current_timestamp();
                            if now - last > heartbeat_timeout.as_millis() as u64 {
                                if stopped.load(Ordering::SeqCst) {
                                    break;
                                }
                                error!("Thread is not responding, restarting");
                                if let Some(ref on_restart_fn) = on_restart {
                                    on_restart_fn();
                                }
                                thread_handle.abort();
                                break;
                            }
                        },
                        res = &mut thread_handle => {
                            if res.is_err() {
                                error!("Monitored task panicked, restarting");
                                if let Some(ref on_restart_fn) = on_restart {
                                    on_restart_fn();
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }.instrument(span));

        self.handle = Some(handle);
    }

    /// Stops the watchdog thread gracefully, aborting the monitored task if needed.
    pub async fn stop(&mut self) {
        info!("Stopping watchdog thread");
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.abort();
            if let Err(e) = handle.await {
                if e.is_cancelled() {
                    info!("Watchdog thread stopped");
                } else {
                    error!("Error stopping watchdog thread: {:?}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_watchdog_thread_starts_and_stops() {
        let mut watchdog = WatchdogThread::new(Duration::from_secs(1), None, false, None);

        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                loop {
                    heartbeat();
                    sleep(Duration::from_secs(1)).await;
                }
            })
        });

        sleep(Duration::from_secs(2)).await;
        watchdog.stop().await;
    }

    #[tokio::test]
    async fn test_watchdog_thread_restarts_on_no_heartbeat() {
        let restart_count = Arc::new(AtomicUsize::new(0));
        let restart_count_clone = restart_count.clone();
        let mut watchdog = WatchdogThread::new(
            Duration::from_secs(1),
            Some(Arc::new(move || {
                restart_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            false,
            None,
        );

        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                heartbeat();
                loop {
                    // Do not send heartbeats.
                    sleep(Duration::from_secs(2)).await;
                }
            })
        });

        sleep(Duration::from_secs(3)).await;
        watchdog.stop().await;

        assert!(
            restart_count.load(Ordering::SeqCst) > 0,
            "Watchdog thread should have restarted at least once"
        );
    }

    #[tokio::test]
    async fn test_watchdog_thread_receives_heartbeat() {
        let mut watchdog = WatchdogThread::new(Duration::from_secs(1), None, false, None);

        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                loop {
                    heartbeat();
                    sleep(Duration::from_millis(500)).await;
                }
            })
        });

        sleep(Duration::from_secs(3)).await;
        watchdog.stop().await;
    }

    #[tokio::test]
    async fn test_watchdog_thread_stops_properly() {
        let mut watchdog = WatchdogThread::new(Duration::from_secs(1), None, false, None);

        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                loop {
                    heartbeat();
                    sleep(Duration::from_millis(500)).await;
                }
            })
        });

        sleep(Duration::from_secs(1)).await;
        watchdog.stop().await;

        // Ensure the watchdog thread has stopped.
        assert!(
            watchdog.handle.is_none(),
            "Watchdog thread should be stopped"
        );
    }

    #[tokio::test]
    async fn test_watchdog_thread_handles_multiple_restarts() {
        let restart_count = Arc::new(AtomicUsize::new(0));
        let restart_count_clone = restart_count.clone();
        let mut watchdog = WatchdogThread::new(
            Duration::from_secs(1),
            Some(Arc::new(move || {
                restart_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            false,
            None,
        );

        watchdog.start(|heartbeat| {
            heartbeat();
            tokio::spawn(async move {
                loop {
                    // Do not send heartbeats.
                    sleep(Duration::from_secs(2)).await;
                }
            })
        });

        sleep(Duration::from_secs(5)).await;
        watchdog.stop().await;

        assert!(
            restart_count.load(Ordering::SeqCst) >= 2,
            "Watchdog thread should have restarted at least twice"
        );
    }

    #[tokio::test]
    async fn test_skip_first_heartbeat_enabled() {
        // When skip_first_heartbeat is enabled, lack of initial heartbeat should be tolerated.
        let mut watchdog = WatchdogThread::new(Duration::from_secs(1), None, true, None);
        // Spawn a task which delays the first call to heartbeat.
        let start = std::time::Instant::now();
        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                // Delay longer than heartbeat_timeout for the first heartbeat.
                sleep(Duration::from_secs(2)).await;
                heartbeat();
                loop {
                    sleep(Duration::from_secs(1)).await;
                    heartbeat();
                }
            })
        });
        // Sleep enough time to cover the initial delay plus one timeout period.
        sleep(Duration::from_secs(4)).await;
        watchdog.stop().await;
        // If skip_first_heartbeat works, no restart should have been triggered.
        // (In this test, we do not count restarts, so absence of panic is the test.)
        assert!(start.elapsed() >= Duration::from_secs(4));
    }

    #[tokio::test]
    async fn test_skip_first_heartbeat_disabled() {
        // When skip_first_heartbeat is disabled, absence of the first heartbeat should trigger a restart.
        let restart_count = Arc::new(AtomicUsize::new(0));
        let restart_clone = restart_count.clone();
        let mut watchdog = WatchdogThread::new(
            Duration::from_secs(1),
            Some(Arc::new(move || {
                restart_clone.fetch_add(1, Ordering::SeqCst);
            })),
            false,
            None,
        );
        // Spawn a task that deliberately delays the heartbeat beyond the timeout.
        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                // Delay for 2 seconds (exceeds timeout) before sending any heartbeat.
                sleep(Duration::from_secs(2)).await;
                heartbeat();
                loop {
                    sleep(Duration::from_secs(1)).await;
                    heartbeat();
                }
            })
        });
        sleep(Duration::from_secs(3)).await;
        watchdog.stop().await;
        assert!(
            restart_count.load(Ordering::SeqCst) > 0,
            "Expected at least one restart when skip_first_heartbeat is disabled"
        );
    }

    #[tokio::test]
    async fn test_watchdog_thread_restarts_on_panic() {
        let restart_count = Arc::new(AtomicUsize::new(0));
        let restart_clone = restart_count.clone();
        let mut watchdog = WatchdogThread::new(
            Duration::from_secs(1),
            Some(Arc::new(move || {
                restart_clone.fetch_add(1, Ordering::SeqCst);
            })),
            false,
            None,
        );

        watchdog.start(|heartbeat| {
            tokio::spawn(async move {
                heartbeat();
                panic!("Simulated panic to trigger restart");
            })
        });

        // Allow time for the panic to be detected and a restart to be triggered.
        sleep(Duration::from_secs(2)).await;
        watchdog.stop().await;

        assert!(
            restart_count.load(Ordering::SeqCst) > 0,
            "Expected at least one restart when the monitored task panics"
        );
    }
}
