use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmResources};
use ic_system_test_driver::systest;
use std::time::Duration;
use xnet_slo_test_lib::Config;

const SUBNETS: usize = 3;
const NODES_PER_SUBNET: usize = 1;
const RUNTIME: Duration = Duration::from_secs(6000);
const REQUEST_RATE: usize = 500 << 10;
const RESPONSE_SIZE: u64 = 200;
const RESPONSE_TIMEOUT_SECONDS: u32 = 300;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(15 * 600);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 600);

fn main() -> Result<()> {
    let config = Config::new(SUBNETS, NODES_PER_SUBNET, RUNTIME, REQUEST_RATE)
        .with_vm_resources(VmResources {
            vcpus: Some(NrOfVCPUs::new(64)),
            memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        })
        .with_payload_bytes(0)
        .with_response_payload_size_bytes(RESPONSE_SIZE)
        .with_call_timeouts(&[
            Some(RESPONSE_TIMEOUT_SECONDS),
            Some(RESPONSE_TIMEOUT_SECONDS),
            Some(RESPONSE_TIMEOUT_SECONDS),
        ])
        .with_prometheus();
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(OVERALL_TIMEOUT) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
