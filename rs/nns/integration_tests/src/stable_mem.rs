//! Tests `ic_nervous_system_common::stable_mem_utils` using a canister

use canister_test::Canister;
use dfn_candid::candid;
use ic_nns_test_utils::itest_helpers::{install_rust_canister, state_machine_test_on_nns_subnet};

#[test]
fn chunked_stable_mem_ser_deser_roundtrip() {
    state_machine_test_on_nns_subnet(|runtime| async move {
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
    install_rust_canister(canister, "mem-utils-test-canister", &[], None).await;
}
