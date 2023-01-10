use ic_interfaces::time_source::{SysTimeSource, TimeSource};
use ic_logger::{warn, ReplicaLogger};
use ic_types::Time;

/// Wraps [`SysTimeSource`] to update current system time automatically every time it is retrieved
/// and provide logging in case time was erroneously not increasing monotonically.
///
/// Note that if time is erroneously not increasing monotonically,
/// then [`SysTimeSource::update_time`] skips the update and
/// [`CurrentSystemTimeSource::get_relative_time`] returns the same value as before
/// ( as long as [`SysTimeSource::update_time`] is not successful).
pub struct CurrentSystemTimeSource {
    source: SysTimeSource,
    logger: ReplicaLogger,
}

impl CurrentSystemTimeSource {
    pub fn new(logger: ReplicaLogger) -> Self {
        CurrentSystemTimeSource {
            source: SysTimeSource::new(),
            logger,
        }
    }
}

impl TimeSource for CurrentSystemTimeSource {
    fn get_relative_time(&self) -> Time {
        if let Err(e) = self.source.update_time() {
            warn!(self.logger, "Error retrieving current system time: {:?}", e)
        };
        self.source.get_relative_time()
    }
}
