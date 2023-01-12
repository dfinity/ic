#[rustfmt::skip]

use anyhow::Result;
use std::time::Duration;

use ic_tests::driver::ic::{ImageSizeGiB, VmResources};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::networking::subnet_query_workload::{long_duration_test, LONG_DURATION_TEST_RUNTIME};
use ic_tests::networking::subnet_update_workload::default_config;
use ic_tests::systest;

fn main() -> Result<()> {
    let per_task_timeout: Duration = LONG_DURATION_TEST_RUNTIME + Duration::from_secs(10 * 60); // This should be a bit larger than the workload execution time.
    let overall_timeout: Duration = per_task_timeout + Duration::from_secs(5 * 60); // This should be a bit larger than the per_task_timeout.

    SystemTestGroup::new()
        .with_setup(default_config)
        .add_test(systest!(long_duration_test))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(overall_timeout) // the entire group may take up to `overall_timeout`.
        // Since this is a long-running test, it accumulates a lot of disk space.
        // This is why we increase the default of 50 GiB to 500 GiB.
        .with_default_vm_resources(Some(VmResources {
            vcpus: None,
            memory_kibibytes: None,
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        }))
        .execute_from_args()?;
    Ok(())
}
