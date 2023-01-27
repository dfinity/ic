use std::time::Duration;

#[rustfmt::skip]

use anyhow::Result;

use ic_tests::distributed_tests::distributed_api::{distributed_config, distributed_test};
use ic_tests::driver::new::dsl::TestFunction;
use ic_tests::driver::new::group::{SystemTestGroup, SystemTestSubGroup};
use ic_tests::driver::test_env::TestEnv;

static UVM_LABELS: [char; 4] = ['a', 'b', 'c', 'd'];
const WORKLOAD_GENERATION_TIMEOUT: Duration = Duration::from_secs(3 * 60); // 3 min

/// The purpose of this test is to spawn multiple universal VMs,
/// each based on //rs/tests:nns_dapp_specs_uvm_config_image
/// Each instance creates some workload using a Docker command.
/// the resulting Docker logs are then collected into the test_tmpdir.
fn main() -> Result<()> {
    let config_uvms = {
        let uvm_labels = UVM_LABELS
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        move |env: TestEnv| {
            distributed_config(env, uvm_labels.clone());
        }
    };

    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(60 * 60))
        .with_timeout_per_test(Duration::from_secs(60 * 60))
        .with_setup(config_uvms)
        .add_parallel({
            let mut workers = SystemTestSubGroup::new();
            let target_fns = UVM_LABELS
                .iter()
                .map(|uvm_label| {
                    let target_fn = move |env: TestEnv| {
                        distributed_test(env, &uvm_label.to_string(), WORKLOAD_GENERATION_TIMEOUT);
                    };
                    TestFunction::new(&format!("worker_{uvm_label}"), target_fn)
                })
                .collect::<Vec<TestFunction>>();
            for target_fn in target_fns {
                workers = workers.add_test(target_fn)
            }
            workers
        })
        .execute_from_args()?;
    Ok(())
}
