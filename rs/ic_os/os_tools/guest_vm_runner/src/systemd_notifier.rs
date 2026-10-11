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
        libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])?;
        Ok(())
    }
}

#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod testing {
    use super::*;
    use tokio::sync::watch::{Receiver, Sender, channel};

    /// Mock implementation that counts the notifications.
    #[derive(Clone)]
    pub struct MockSystemdNotifier {
        ready_count: (Sender<u32>, Receiver<u32>),
    }

    impl MockSystemdNotifier {
        pub fn new() -> Self {
            Self {
                ready_count: channel(0),
            }
        }

        /// Wait until `self.notify_ready()` has been called at least `count` times. If it has
        /// already been called that often before, the function returns immediately.
        pub async fn await_ready_count(&self, count: u32) {
            self.ready_count
                .1
                .clone()
                .wait_for(|x| *x >= count)
                .await
                .unwrap();
        }
    }

    impl SystemdNotifier for MockSystemdNotifier {
        fn notify_ready(&self) -> Result<()> {
            self.ready_count.0.send_modify(|x| *x += 1);
            Ok(())
        }
    }
}
