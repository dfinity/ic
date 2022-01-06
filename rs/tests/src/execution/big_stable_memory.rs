use crate::{types::RejectCode, util::*};
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::wasm;
use ic_utils::interfaces::ManagementCanister;

pub fn can_access_big_stable_memory(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister = UniversalCanister::new_with_64bit_stable_memory(&agent)
                .await
                .unwrap();

            canister
                // Grow stable memory to 5GiB.
                .update(wasm().stable64_grow(81_920).reply())
                .await
                .unwrap();

            let big_offset: u64 = 4 * 1024 * 1024 * 1024 + 1;
            let data = 42;
            let size = 1024;
            // Write 1KiB of 42s to an index above 4GiB, should succeed.
            canister
                .update(wasm().stable64_write(big_offset, data, size).reply())
                .await
                .unwrap();

            // Read the data written above and confirm it's the same.
            let res = canister
                .query(wasm().stable64_read(big_offset, size).append_and_reply())
                .await
                .unwrap();
            assert_eq!(res, vec![data as u8; 1024]);
        }
    })
}

pub fn can_handle_out_of_bounds_access(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister = UniversalCanister::new_with_64bit_stable_memory(&agent)
                .await
                .unwrap();

            canister
                // Grow stable memory to 5GiB.
                .update(wasm().stable64_grow(81_920).reply())
                .await
                .unwrap();

            // Offset to a position outside the currently allocated stable memory.
            let big_offset: u64 = 10 * 1024 * 1024 * 1024 + 1;
            let data = 42;
            let size = 1024;
            // Write 1KiB of 42s to an index above 10GiB, should fail.
            let res = canister
                .update(wasm().stable64_write(big_offset, data, size).reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);

            // Attempt to read data above 10GB, should fail.
            let res = canister
                .query(wasm().stable64_read(big_offset, size).append_and_reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}

pub fn can_handle_overflows_when_indexing_stable_memory(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister = UniversalCanister::new_with_64bit_stable_memory(&agent)
                .await
                .unwrap();

            canister
                // Grow stable memory to 5GiB.
                .update(wasm().stable64_grow(81_920).reply())
                .await
                .unwrap();

            // Offset to a position out of range.
            let big_offset = u64::MAX;
            let data = 42;
            let size = 1024;
            // Write 1KiB of 42s to an offset that can't fit in 64 bits, should fail.
            let res = canister
                .update(wasm().stable64_write(big_offset, data, size).reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);

            // Attempt to read data at an offset that can't fit in 64 bits, should fail.
            let res = canister
                .query(wasm().stable64_read(big_offset, size).append_and_reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}

pub fn can_access_big_heap_and_big_stable_memory(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let mgr = ManagementCanister::create(&agent);
            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(delay())
                .await
                .unwrap()
                .0;

            let wasm = wabt::wat2wasm(
                r#"
                (module
                    (import "ic0" "stable64_size" (func $stable64_size (result i64)))
                    (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                    (import "ic0" "stable64_write"
                        (func $stable64_write (param i64) (param i64) (param i64)))
                    (import "ic0" "stable64_read"
                        (func $stable64_read (param i64) (param i64) (param i64)))
                    (import "ic0" "msg_reply" (func $msg_reply))

                    (func $grow_stable_memory
                        ;; Grow stable memory by 5GiB and trap if it's not possible.
                        (if (i64.eq (call $stable64_grow (i64.const 81_920)) (i64.const -1))
                            (then (unreachable))
                        )
                        (call $msg_reply)
                    )

                    (func $write_stable_memory
                        (call $stable64_write (i64.const 4294967299) (i64.const 0) (i64.const 10))
                        (call $msg_reply)
                    )

                    (func $read_stable_memory
                        (call $stable64_read (i64.const 100) (i64.const 4294967299) (i64.const 10))
                        (call $msg_reply)
                    )

                    (memory $memory 65536)
                    (export "memory" (memory $memory))
                    (export "canister_update grow_stable_memory" (func $grow_stable_memory))
                    (export "canister_update write_stable_memory" (func $write_stable_memory))
                    (export "canister_update read_stable_memory" (func $read_stable_memory)))"#,
            )
            .unwrap();

            mgr.install_code(&canister_id, &wasm)
                .with_raw_arg(vec![])
                .call_and_wait(delay())
                .await
                .unwrap();

            // Grow stable memory by 5GiB. Should succeed and the canister is now using
            // 9GiB.
            agent
                .update(&canister_id, "grow_stable_memory")
                .call_and_wait(delay())
                .await
                .unwrap();

            agent
                .update(&canister_id, "write_stable_memory")
                .call_and_wait(delay())
                .await
                .unwrap();

            agent
                .update(&canister_id, "read_stable_memory")
                .call_and_wait(delay())
                .await
                .unwrap();

            // Update memory allocation of canister to 12GiB.
            mgr.update_settings(&canister_id)
                .with_memory_allocation(12u64 * 1024 * 1024 * 1024)
                .call_and_wait(delay())
                .await
                .unwrap();

            // Grow stable memory by another 5GiB. Should fail.
            let res = agent
                .update(&canister_id, "grow_stable_memory")
                .call_and_wait(delay())
                .await;

            assert_reject(res, RejectCode::CanisterError);
        }
    })
}

pub fn canister_traps_if_32_bit_api_used_on_big_memory(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            // Create a canister that uses 32-bit stable memory.
            let canister = UniversalCanister::new(&agent).await;

            // Canister can use 32-bit api.
            canister
                .query(wasm().stable_size().reply_int())
                .await
                .unwrap();

            canister
                .update(wasm().stable_write(10, &vec![42_u8; 1024]).reply())
                .await
                .unwrap();

            canister
                .query(wasm().stable_read(10, 1024).append_and_reply())
                .await
                .unwrap();

            // Increase memory to 5GB.
            canister
                .update(wasm().stable64_grow(81_920).reply())
                .await
                .unwrap();

            // Canister can use 64-bit api but access via the 32-bit api traps.
            canister
                .query(wasm().stable64_size().reply())
                .await
                .unwrap();

            canister
                .update(wasm().stable64_write(10, 42, 1024).reply())
                .await
                .unwrap();

            canister
                .query(wasm().stable64_read(10, 1024).append_and_reply())
                .await
                .unwrap();

            let res = canister.query(wasm().stable_size().reply_int()).await;
            assert_reject(res, RejectCode::CanisterError);

            let res = canister.query(wasm().stable_grow(0).reply_int()).await;
            assert_reject(res, RejectCode::CanisterError);

            let res = canister.query(wasm().stable_grow(1).reply_int()).await;
            assert_reject(res, RejectCode::CanisterError);

            let res = canister
                .update(wasm().stable_write(10, &vec![42_u8; 1024]).reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);

            let res = canister
                .query(wasm().stable_read(10, 1024).append_and_reply())
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}
