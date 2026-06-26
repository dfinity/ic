/// This module contains panics that are allowed by default to occur in logs in system-tests.
use ic_types::Height;

pub(crate) fn panic_with_replica_diverged_at_height(height: Height) -> ! {
    panic!("Replica diverged at height {}", height)
}
