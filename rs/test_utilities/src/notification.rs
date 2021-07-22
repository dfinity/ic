use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// One-off notification that can be used to synchronize two threads.
///
/// ```no_run
/// use ic_test_utilities::notification::{Notification, WaitResult};
/// use std::sync::Arc;
/// use std::thread;
/// use std::time::Duration;
///
/// let notification = Arc::new(Notification::new());
/// let handle = thread::spawn({
///     let notification = Arc::clone(&notification);
///     move || {
///         assert_eq!(
///             notification.wait_with_timeout(Duration::from_secs(10)),
///             WaitResult::Notified(()),
///         );
///     }
/// });
/// notification.notify(());
/// handle.join().unwrap();
/// ```
pub struct Notification<T> {
    mutex: Mutex<Option<T>>,
    condvar: Condvar,
}

/// The result of the `wait_with_timeout` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WaitResult<T> {
    Notified(T),
    TimedOut,
}

impl<T> Default for Notification<T> {
    fn default() -> Self {
        Self {
            mutex: Mutex::new(None),
            condvar: Condvar::new(),
        }
    }
}

impl<T> Notification<T>
where
    T: Clone + std::fmt::Debug + PartialEq,
{
    /// Create a new notification that is not raised.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the notification to the raised state. Once notification is
    /// saturated, it stays saturated forever, there is no way to reset it.
    ///
    /// # Panics
    ///
    /// Panics if `notify` is called twice with different values.
    pub fn notify(&self, value: T) {
        {
            let mut guard = self.mutex.lock().unwrap();
            if let Some(ref old_value) = *guard {
                if value != *old_value {
                    panic!(
                        "Notified twice with different values: first {:?}, then {:?}",
                        old_value, value
                    );
                } else {
                    return;
                }
            }
            *guard = Some(value);
        }
        self.condvar.notify_all();
    }

    /// Wait for another thread to call `notify`, but no longer than
    /// `duration`.
    ///
    /// Returns `WaitResult::Notified(T)` if the notification was raised and
    /// `WaitResult::TimedOut` if it didn't happen within `duration`.
    pub fn wait_with_timeout(&self, duration: Duration) -> WaitResult<T> {
        let guard = self.mutex.lock().unwrap();

        if let Some(ref value) = *guard {
            return WaitResult::Notified(value.clone());
        }

        let (guard, _result) = self.condvar.wait_timeout(guard, duration).unwrap();
        match *guard {
            Some(ref value) => WaitResult::Notified(value.clone()),
            None => WaitResult::TimedOut,
        }
    }
}

#[test]
fn test_single_threaded_notification() {
    let notification = Notification::<i32>::new();
    assert_eq!(
        notification.wait_with_timeout(Duration::from_millis(0)),
        WaitResult::TimedOut
    );

    notification.notify(1);
    assert_eq!(
        notification.wait_with_timeout(Duration::from_millis(0)),
        WaitResult::Notified(1)
    );
}

#[test]
#[should_panic(expected = "first 1, then 2")]
fn test_panics_on_incompatible_notify() {
    let notification = Notification::<i32>::new();
    notification.notify(1);
    notification.notify(2);
}

#[test]
fn test_notify_same_value_twice_does_not_panic() {
    let notification = Notification::<i32>::new();
    notification.notify(1);
    notification.notify(1);
    assert_eq!(
        notification.wait_with_timeout(Duration::from_millis(0)),
        WaitResult::Notified(1)
    );
}
