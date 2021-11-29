//! Tests `ic_nns_integration_tests::stable_mem_utils` using a canister

use canister_test::{local_test_with_config_e, Canister};
use dfn_candid::candid;
use ic_config::subnet_config::SubnetConfig;
use ic_nns_test_utils::itest_helpers::install_rust_canister;
use phantom_newtype::AmountOf;

#[test]
fn chunked_stable_mem_ser_deser_roundtrip() {
    let (config, _tmpdir) = ic_config::Config::temp_config();
    let mut subnet_config = SubnetConfig::default_system_subnet();
    // Work around exeuction u64-to-i64 overflow bug
    let max_cycles = i64::MAX as u64;
    // Allocating 200,000 neurons takes some cycles so we have to bump the
    // limits
    subnet_config.scheduler_config.max_instructions_per_message = AmountOf::new(max_cycles);
    // Not sure why I need to bump this, but without this the test starts to
    // hang, without any error messages
    subnet_config.scheduler_config.max_instructions_per_round = AmountOf::new(max_cycles);

    local_test_with_config_e(config, subnet_config, |runtime| async move {
        println!("Installing mem utils test canister...");

        let mut canister = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        install_mem_utils_test_canister(&mut canister).await;

        // Tests writing when the buffer is empty and we have no stable memory
        // pages allocated yet
        canister
            .update_("test_empty", candid::<(), ()>, ())
            .await
            .unwrap();

        // 10MiB, 1MiB, 1KiB, 100 bytes
        for buffer_size in &[10 * 1024 * 1024, 1024 * 1024, 1024u32, 100] {
            canister
                .update_("test_buffer_size", candid::<(), (u32,)>, (*buffer_size,))
                .await
                .unwrap();
        }

        // Try small data with 1 byte buffer (makes a lot of system calls to
        // read/write data 1 byte at a time)
        canister
            .update_("test_1_byte_buffer", candid::<(), ()>, ())
            .await
            .unwrap();
        Ok(())
    })
}

async fn install_mem_utils_test_canister(canister: &mut Canister<'_>) {
    install_rust_canister(
        canister,
        "nns/integration_tests",
        "mem-utils-test-canister",
        None,
    )
    .await;
}
