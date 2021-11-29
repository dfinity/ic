use crate::util::*;
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::wasm;
use std::convert::TryInto;

const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; /* 64KiB */

/// This test assumes it's being executed using 20MiB of subnet capacity.
pub fn exceeding_memory_capacity_fails_during_message_execution(
    handle: IcHandle,
    ctx: &fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            // The universal canister is created with 1 page of stable memory (see
            // implementation of `new_with_64bit_stable_memory).
            let canister = UniversalCanister::new_with_64bit_stable_memory(&agent)
                .await
                .unwrap();

            // Subnet has 20MiB memory capacity. There are `NUMBER_OF_EXECUTION_THREADS` ==
            // 4 running which means that the available subnet capacity would be split
            // across these many threads. If the canister is trying to allocate
            // 1MiB of memory, it'll keep succeeding until we reach 16MiB total allocated
            // capacity and then should fail after that point because the capacity split
            // over 4 threads will be less than 1MiB (keep in mind the wasm module of the
            // canister also takes some space).
            let memory_to_allocate = 1024 * 1024 / WASM_PAGE_SIZE_IN_BYTES; // 1MiB in Wasm pages.
            let mut expected_result = 1;
            for _ in 0..15 {
                let res = canister
                    .update(wasm().stable64_grow(memory_to_allocate).reply_int64())
                    .await
                    .unwrap();
                assert_eq!(
                    u64::from_le_bytes(res[0..8].try_into().unwrap()),
                    expected_result
                );
                expected_result += memory_to_allocate;
            }

            // Canister tries to grow by another `memory_to_allocate` pages, should fail and
            // the return value will be -1.
            let res = canister
                .update(wasm().stable64_grow(memory_to_allocate).reply_int64())
                .await
                .unwrap();
            assert_eq!(i64::from_le_bytes(res[0..8].try_into().unwrap()), -1);
        }
    })
}
