//! Make sure the governance canister scales

use std::time::Duration;

use canister_test::{CanisterInstallMode, Project, Runtime};
use ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet;

#[test]
fn governance_mem_test() {
    local_test_on_nns_subnet(|mut runtime| async move {
        println!("Initializing governance mem test canister...");

        if let Runtime::Local(local_runtime) = &mut runtime {
            local_runtime.ingress_time_limit = Duration::from_secs(20 * 60);
        }

        let mut governance = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        let state_initializer_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "nns/integration_tests",
            "governance-mem-test-canister",
            &[],
        );

        // It's on purpose that we don't want retries here! This test is only about
        // initializing a canister with a very large state. A failure is most
        // likely repeatable, so the test will fail much faster without retries.
        let install = state_initializer_wasm
            .install(&runtime)
            .with_mode(CanisterInstallMode::Install);
        install.install(&mut governance, Vec::new()).await.unwrap();

        // Now let's upgrade to the real governance canister
        let real_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "nns/governance",
            "governance-canister",
            &[],
        );
        governance.set_wasm(real_wasm.bytes());

        // Exercise canister_post_upgrade of the real canister
        governance
            .upgrade_to_self_binary(/* arg passed to post-upgrade: */ Vec::new())
            .await
            .unwrap();

        // Exercise canister_pre_upgrade (and post upgrade again) of the real canister
        governance
            .upgrade_to_self_binary(/* arg passed to post-upgrade: */ Vec::new())
            .await
            .unwrap();

        Ok(())
    })
}
