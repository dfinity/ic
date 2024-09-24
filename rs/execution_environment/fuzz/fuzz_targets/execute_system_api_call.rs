#![no_main]
use ic_management_canister_types::{Method, Payload, UpdateSettingsArgs};
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use libfuzzer_sys::{fuzz_target, Corpus};

// This fuzz tries to execute the UpdateSettings management canister method
//
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=fuzzing //rs/execution_environment/fuzz:execute_system_api_call


fuzz_target!(|_args: UpdateSettingsArgs| -> Corpus {
    Corpus::Reject
}
