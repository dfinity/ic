use anyhow::Result;

/// A trait for notifying systemd about service state changes.
pub trait SystemdNotifier: Send + Sync {
    /// Notifies systemd that the service is ready to accept connections.
    fn notify_ready(&self) -> Result<()>;
}

/// Default implementation that calls systemd.
#[cfg(target_os = "linux")]
pub struct DefaultSystemdNotifier;

#[cfg(target_os = "linux")]
impl SystemdNotifier for DefaultSystemdNotifier {
    fn notify_ready(&self) -> Result<()> {
        systemd::daemon::notify(false, [(systemd::daemon::STATE_READY, "1")].iter())?;
        Ok(())
    }
}

#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod testing {
    use super::*;
    use tokio::sync::watch::{Receiver, Sender, channel};

    /// Mock implementation that records the notifications.
    pub struct MockSystemdNotifier {
        ready: (Sender<bool>, Receiver<bool>),
    }

    impl MockSystemdNotifier {
        pub fn new() -> Self {
            Self {
                ready: channel(false),
            }
        }

        /// Wait until `self.notify_ready()` is called. If it has already been called
        /// before, the function returns immediately.
        pub async fn await_ready(&self) {
            self.ready.1.clone().wait_for(|x| *x).await.unwrap();
        }
    }

    impl SystemdNotifier for MockSystemdNotifier {
        fn notify_ready(&self) -> Result<()> {
            self.ready
                .0
                .send(true)
                .expect("Failed to send ready notification");
            Ok(())
        }
    }
}
