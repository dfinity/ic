//! This module contains panics that are allowed by default to occur in logs in system-tests.
use ic_types::{RegistryVersion, SubnetId};

pub(crate) fn panic_with_no_subnet_record(version: RegistryVersion, subnet_id: SubnetId) -> ! {
    panic!(
        "No subnet record found for registry version={:?} and subnet_id={:?}",
        version, subnet_id,
    )
}
