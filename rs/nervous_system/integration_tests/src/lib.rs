//! Integration tests for the Neurons Fund.
//!
//! Each test creates a PocketIc instance, installs the NNS canisters, and then
//! proceeds to perform operations and verify they completed successfully, and
//! that the state is the expected one. State inspection is done via the public
//! canister API.
//!
//! This is not a library at all. However, if this was under `tests/`, then each
//! file would become its own crate, and the tests would run sequentially. By
//! pretending it's a library with several modules inside, `cargo test` is
//! supposed to run all tests in parallel, because they are all in the same
//! crate.

pub mod create_service_nervous_system_builder;
pub mod pocket_ic_helpers;

use std::time::Instant;

/// Used for annotating a "section" of the test with timing information, which is useful for improving the performance of the tests.
pub struct SectionTimer {
    name: String,
    start_time: Instant,
}

impl SectionTimer {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        println!("{name}");
        Self {
            name,
            start_time: Instant::now(),
        }
    }
}

impl Drop for SectionTimer {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("Panicked during `{}`", self.name);
        } else {
            eprintln!(
                "Executed `{}` in {:?}",
                self.name,
                self.start_time.elapsed()
            );
        }
    }
}
