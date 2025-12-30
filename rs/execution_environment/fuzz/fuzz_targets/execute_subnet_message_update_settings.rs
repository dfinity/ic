use ic_management_canister_types_private::{Method, Payload, UpdateSettingsArgs};
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use libfuzzer_sys::{Corpus, fuzz_target};

// This fuzz tries to execute the UpdateSettings management canister method
//
// The fuzz test is only compiled but not executed by CI.
// bazel run --config=sandbox_fuzzing //rs/execution_environment/fuzz:execute_subnet_message_update_settings

fn main() {
    let features = fuzzer_sandbox::SandboxFeatures {
        syscall_tracing: false,
    };
    fuzzer_sandbox::fuzzer_main(features);
}

fuzz_target!(|args: UpdateSettingsArgs| -> Corpus {
    let mut test = ExecutionTestBuilder::new()
        .with_precompiled_universal_canister(false)
        .build();

    let wat = r#"(module)"#;
    let canister_id = test.canister_from_wat(wat).unwrap();

    let mut update_settings_args = args;
    update_settings_args.canister_id = canister_id.into();

    match test.subnet_message(Method::UpdateSettings, update_settings_args.encode()) {
        Ok(_) => {
            let controllers = &test.canister_state(canister_id).system_state.controllers;
            let compute_allocation = test
                .canister_state(canister_id)
                .scheduler_state
                .compute_allocation
                .as_percent();
            let memory_allocation = test
                .canister_state(canister_id)
                .system_state
                .memory_allocation
                .pre_allocated_bytes()
                .get();
            let freezing_threshold = test
                .canister_state(canister_id)
                .system_state
                .freeze_threshold
                .get();

            for principal in update_settings_args.settings.controllers.unwrap().get() {
                assert!(controllers.contains(principal));
            }
            assert_eq!(
                compute_allocation,
                update_settings_args.settings.compute_allocation.unwrap()
            );
            assert_eq!(
                memory_allocation,
                update_settings_args.settings.memory_allocation.unwrap()
            );
            assert_eq!(
                freezing_threshold,
                update_settings_args.settings.freezing_threshold.unwrap()
            );
            Corpus::Keep
        }
        Err(_err) => Corpus::Reject,
    }
});
