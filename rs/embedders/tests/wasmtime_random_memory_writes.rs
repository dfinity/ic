use ic_config::embedders::Config;
use ic_embedders::wasm_utils::instrumentation::{instrument, InstructionCostTable};
use ic_embedders::WasmtimeEmbedder;
use ic_interfaces::execution_environment::{
    AvailableMemory, ExecutionMode, ExecutionParameters, SubnetAvailableMemory,
};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, NumWasmPages};
use ic_sys::PAGE_SIZE;
use ic_system_api::DefaultOutOfInstructionsHandler;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType, SystemApiImpl};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time,
    state::SystemStateBuilder,
    types::ids::{call_context_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::{
    methods::{FuncRef, WasmMethod},
    ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId,
};
use ic_wasm_types::BinaryEncodedWasm;
use lazy_static::lazy_static;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into();
}

fn test_api_for_update(
    log: ReplicaLogger,
    caller: Option<PrincipalId>,
    payload: Vec<u8>,
    subnet_type: SubnetType,
) -> SystemApiImpl {
    let caller = caller.unwrap_or_else(|| user_test_id(24).get());
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = Arc::new(
        CyclesAccountManagerBuilder::new()
            .with_subnet_type(subnet_type)
            .build(),
    );
    let static_system_state = SandboxSafeSystemState::new(&system_state, *cycles_account_manager);
    let canister_memory_limit = NumBytes::from(4 << 30);
    let canister_current_memory_usage = NumBytes::from(0);

    SystemApiImpl::new(
        ApiType::update(
            mock_time(),
            payload,
            Cycles::from(0),
            caller,
            call_context_test_id(13),
        ),
        static_system_state,
        canister_current_memory_usage,
        ExecutionParameters {
            total_instruction_limit: MAX_NUM_INSTRUCTIONS,
            slice_instruction_limit: MAX_NUM_INSTRUCTIONS,
            canister_memory_limit,
            subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
        },
        Memory::default(),
        Arc::new(DefaultOutOfInstructionsHandler {}),
        log,
    )
}

fn make_module_wat(heap_size: usize) -> String {
    format!(
        r#"
    (module
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32) (param i32)))
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i32)))
      (import "ic0" "stable_grow"
        (func $ic0_stable_grow (param $pages i32) (result i32)))
      (import "ic0" "stable_read"
        (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))

      (func $dump_heap
        (call $msg_reply_data_append (i32.const 0) (i32.mul (memory.size) (i32.const 0x10000)))
        (call $msg_reply)
      )

      ;; write to memory
      (func $write_bytes
        ;; copy the i32 `addr` to heap[0;4]
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (i32.const 4) ;; len
        )
        ;; copy the remainder of the payload to the heap[addr;size]
        (call $ic0_msg_arg_data_copy
          ;; addr
          (i32.load (i32.const 0))
          ;; offset
          (i32.const 4)
          ;; size
          (i32.sub
            (call $ic0_msg_arg_data_size)
            (i32.const 4)
          )
        )
      )

      ;; One stable_read() System API call
      (func $test_stable_read
        (drop (call $ic0_stable_grow (i32.const 1)))
        (call $ic0_stable_read (i32.const 0) (i32.const 0) (i32.const 0))
      )

      (memory $memory {HEAP_SIZE})
      (export "memory" (memory $memory))
      (export "canister_query dump_heap" (func $dump_heap))
      (export "canister_update write_bytes" (func $write_bytes))
      (export "canister_update test_stable_read" (func $test_stable_read))
    )"#,
        HEAP_SIZE = heap_size
    )
}

#[derive(Debug, Clone)]
pub struct Write {
    dst: u32,
    bytes: Vec<u8>,
}

fn random_writes(heap_size: usize, num_writes: usize) -> impl Strategy<Value = Vec<Write>> {
    // Start generating writes at address 4096 (or higher) to avoid generating
    // writes to the first OS page. This is because we must first copy the
    // offset from the payload to Wasm memory. We store the 4-byte offset at
    // addr=0, hence dirtying the first OS page.
    let write_strategy = (4096..heap_size).prop_flat_map(move |dst| {
        let dst = dst as u32;
        // up to 128 bytes
        let remain = (heap_size - dst as usize) % 128;
        prop::collection::vec(any::<u8>(), 0..=remain).prop_map(move |bytes| Write { dst, bytes })
    });
    prop::collection::vec(write_strategy, 1..num_writes)
}

fn buf_apply_write(heap: &mut [u8], write: &Write) {
    // match the behavior of write_bytes: copy the i32 `addr` to heap[0;4]
    heap[0..4].copy_from_slice(&write.dst.to_le_bytes());
    heap[write.dst as usize..(write.dst as usize + write.bytes.len() as usize)]
        .copy_from_slice(&write.bytes)
}

const TEST_HEAP_SIZE_BYTES: usize = WASM_PAGE_SIZE_BYTES * TEST_NUM_PAGES;
const TEST_NUM_PAGES: usize = 800;
const TEST_NUM_WRITES: usize = 2000;
const WASM_PAGE_SIZE_BYTES: usize = 65536;
const BYTES_PER_INSTRUCTION: usize = 1;

fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wabt::Error> {
    wabt::wat2wasm(wat).map(BinaryEncodedWasm::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_embedders::wasm_executor::compute_page_delta;
    // Get .current() trait method
    use ic_interfaces::execution_environment::HypervisorError;
    use ic_logger::ReplicaLogger;
    use ic_replicated_state::{PageIndex, PageMap};
    use ic_system_api::ModificationTracking;
    use ic_test_utilities::types::ids::canister_test_id;
    use proptest::strategy::ValueTree;

    fn apply_writes_and_check_heap(
        writes: Vec<Write>,
        modification_tracking: ModificationTracking,
    ) {
        with_test_replica_logger(|log| {
            let wat = make_module_wat(TEST_NUM_PAGES);
            let wasm = wat2wasm(&wat).unwrap();

            let output_instrumentation = instrument(&wasm, &InstructionCostTable::new()).unwrap();

            // We will perform identical writes to wasm module's heap and this buffer.
            let mut test_heap = vec![0; TEST_HEAP_SIZE_BYTES];
            // Use SIGSEGV tracking and later compare against /proc/pic/pagemap.
            let config = Config::default();
            let embedder = WasmtimeEmbedder::new(config, log);
            let embedder_cache = embedder.compile(&output_instrumentation.binary).unwrap();
            let mut page_map = PageMap::default();
            let mut dirty_pages: BTreeSet<u64> = BTreeSet::new();

            for write in &writes {
                let mut payload = write.dst.to_le_bytes().to_vec();
                payload.extend(write.bytes.iter());

                let api =
                    test_api_for_update(no_op_logger(), None, payload, SubnetType::Application);

                let mut instance = embedder
                    .new_instance(
                        canister_test_id(1),
                        &embedder_cache,
                        &[],
                        NumWasmPages::from(0),
                        page_map.clone(),
                        modification_tracking,
                        api,
                    )
                    .map_err(|r| r.0)
                    .expect("Failed to create instance");
                instance.set_num_instructions(MAX_NUM_INSTRUCTIONS);

                // Apply the write to the test buffer.
                buf_apply_write(&mut test_heap, write);

                // Apply the write to the Wasm instance.
                println!(
                    "write_bytes(dst: {}, page: {}, bytes: {:?})",
                    write.dst,
                    write.dst / PAGE_SIZE as u32,
                    write.bytes
                );
                let result = instance
                    .run(FuncRef::Method(WasmMethod::Update(
                        "write_bytes".to_string(),
                    )))
                    .expect("call to write_bytes failed");

                // Compare the written regions.
                let wasm_heap: &[u8] = unsafe {
                    let addr = instance.heap_addr();
                    let size_in_bytes = instance.heap_size().get() as usize * WASM_PAGE_SIZE_BYTES;
                    std::slice::from_raw_parts_mut(addr as *mut _, size_in_bytes)
                };
                let start = write.dst as usize;
                let end = start + write.bytes.len();
                assert_eq!(wasm_heap[start..end], test_heap[start..end]);

                if modification_tracking == ModificationTracking::Track {
                    dirty_pages.extend(result.dirty_pages.iter().map(|x| x.get()));

                    // Verify that wasm heap and test buffer are the same.
                    let i = result.dirty_pages.last().unwrap().get();
                    let offset = i as usize * PAGE_SIZE as usize;
                    let page1 = unsafe { test_heap.as_ptr().add(offset) };
                    let page2 = unsafe { wasm_heap.as_ptr().add(offset) };
                    let pages_match = unsafe {
                        libc::memcmp(
                            page1 as *const libc::c_void,
                            page2 as *const libc::c_void,
                            PAGE_SIZE,
                        )
                    };
                    assert!(
                        pages_match == 0,
                        "page({}) of test buffer and Wasm heap doesn't match",
                        i
                    );
                    page_map.update(&compute_page_delta(&mut instance, &result.dirty_pages));
                }
            }

            if modification_tracking == ModificationTracking::Track {
                for i in 0..TEST_NUM_PAGES {
                    let wasm_page = page_map.get_page(PageIndex::new(i as u64));
                    let test_page = &test_heap[i * PAGE_SIZE..(i + 1) * PAGE_SIZE];
                    assert_eq!(wasm_page[..], test_page[..]);
                }

                let sigsegv_dirty_pages = dirty_pages.iter().cloned().collect::<Vec<u64>>();

                let writes_pages: Vec<u64> = {
                    let mut result = BTreeSet::new();
                    // Pre-populate with page(0). This is because despite 0 does
                    // not appear in any writes, calling $write_bytes dirties
                    // page(0) by copying the 4-byte value to addr=0.
                    result.insert(0);
                    // Add the target pages.
                    result.extend(writes.iter().map(|w| w.dst as u64 / PAGE_SIZE as u64));
                    result.iter().cloned().collect()
                };

                // Check SIGSEGV against expected.
                assert_eq!(
                sigsegv_dirty_pages,
                writes_pages,
                "dirty pages returned by SIGSEGV tracking (left) don't match the expected value (right)"
            );
            }
        });
    }

    fn random_payload() -> Vec<u8> {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();

        let mut payload: Vec<u8> = vec![];
        for w in &writes {
            payload.extend(&w.bytes);
        }
        payload
    }

    #[test]
    fn test_charge_instruction_for_data_copy() {
        with_test_replica_logger(|log| {
            // This test is to ensure that the callers of `charge_for_system_api_call`
            // properly convert `size: i32` to u64 and this process does not charge
            // more than the equivalent of `size` for values >= 2^31.
            let num_bytes = 2147483648; // equivalent to 2^31
            let payload = vec![0u8; num_bytes];
            let wasm = wat2wasm(
                r#"
              (module
                (import "ic0" "trap" (func $trap (param i32) (param i32)))

                (func $func_trap
                    (call $trap (i32.const 0) (i32.const 2147483648)) ;; equivalent to 2 ^ 31
                )
                (memory $memory 65536)
                (export "memory" (memory $memory))
                (export "canister_update func_trap" (func $func_trap))
              )
            "#,
            )
            .unwrap();

            let max_num_instructions = NumInstructions::from(5_000_000_000);

            let embedder = WasmtimeEmbedder::new(Config::default(), log.clone());
            let output_instrumentation = instrument(&wasm, &InstructionCostTable::new()).unwrap();
            let api = test_api_for_update(log, None, payload, SubnetType::Application);
            let mut inst = embedder
                .new_instance(
                    canister_test_id(1),
                    &embedder.compile(&output_instrumentation.binary).unwrap(),
                    &[],
                    NumWasmPages::from(0),
                    PageMap::default(),
                    ModificationTracking::Ignore,
                    api,
                )
                .map_err(|r| r.0)
                .expect("Failed to create instance");
            inst.set_num_instructions(max_num_instructions);

            let _result = inst.run(FuncRef::Method(WasmMethod::Update("func_trap".into())));

            // The amount of instructions consumed: 2 constants, trap() (21 instructions)
            // plus equivalent of `num_bytes` in instructions.
            let instructions_consumed = max_num_instructions - inst.get_num_instructions();
            assert_eq!(
                instructions_consumed.get(),
                23 + (num_bytes / BYTES_PER_INSTRUCTION) as u64
            )
        });
    }

    #[test]
    fn test_running_out_of_instructions() {
        with_test_replica_logger(|log| {
            let subnet_type = SubnetType::Application;

            let dst: u32 = 0;
            let mut payload: Vec<u8> = dst.to_le_bytes().to_vec();
            payload.extend(random_payload());

            // Set maximum number of instructions to some low value to trap
            // Note: system API calls get charged per call, see system_api::charges
            let max_num_instructions = NumInstructions::new(1000);

            // Consumes less than max_num_instructions.
            let instructions_consumed_without_data = get_num_instructions_consumed(
                log.clone(),
                "write_bytes",
                dst.to_le_bytes().to_vec(),
                max_num_instructions,
                subnet_type,
            )
            .unwrap();
            assert!(instructions_consumed_without_data.get() > 0);

            // Exceeds the maximum amount of instructions.
            assert_eq!(
                get_num_instructions_consumed(
                    log,
                    "write_bytes",
                    payload,
                    max_num_instructions,
                    subnet_type,
                ),
                Err(HypervisorError::InstructionLimitExceeded)
            )
        })
    }

    #[test]
    fn test_system_api_charges() {
        with_test_replica_logger(|log| {
            let subnet_type = SubnetType::Application;

            let max_num_instructions = NumInstructions::new(1000);

            let instructions_consumed_without_data = get_num_instructions_consumed(
                log,
                "test_stable_read",
                vec![],
                max_num_instructions,
                subnet_type,
            )
            .unwrap();
            // The `test_stable_read()` snippet consists of 7 instructions: 4 constants,
            // stable_grow(), stable_read(), drop.
            // Check that the number of consumed instructions get adjusted for the
            // `stable_read()` System API call overhead.
            assert_eq!(
                instructions_consumed_without_data.get(),
                7 + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_READ
                    .get() as u64
            );
        })
    }

    #[test]
    fn test_proportional_instructions_consumption_to_data_size() {
        with_test_replica_logger(|log| {
            let subnet_type = SubnetType::Application;
            let dst: u32 = 0;

            let mut payload: Vec<u8> = dst.to_le_bytes().to_vec();
            payload.extend(random_payload());
            let payload_size = payload.len() - 4;

            let mut double_size_payload: Vec<u8> = payload.clone();
            double_size_payload.extend(random_payload());

            let instructions_consumed_without_data = get_num_instructions_consumed(
                log.clone(),
                "write_bytes",
                dst.to_le_bytes().to_vec(),
                MAX_NUM_INSTRUCTIONS,
                subnet_type,
            )
            .unwrap();

            {
                // Number of instructions consumed only for copying the payload.
                let consumed_instructions = get_num_instructions_consumed(
                    log.clone(),
                    "write_bytes",
                    payload,
                    MAX_NUM_INSTRUCTIONS,
                    subnet_type,
                )
                .unwrap()
                    - instructions_consumed_without_data;
                assert_eq!(
                    consumed_instructions.get(),
                    (payload_size / BYTES_PER_INSTRUCTION) as u64
                );
            }

            {
                // Number of instructions consumed increased with the size of the data.
                let consumed_instructions = get_num_instructions_consumed(
                    log,
                    "write_bytes",
                    double_size_payload,
                    MAX_NUM_INSTRUCTIONS,
                    subnet_type,
                )
                .unwrap()
                    - instructions_consumed_without_data;

                assert_eq!(
                    consumed_instructions.get(),
                    (2 * payload_size / BYTES_PER_INSTRUCTION) as u64
                );
            }
        })
    }

    #[test]
    fn test_no_instructions_consumption_based_on_data_size_on_system_subnet() {
        with_test_replica_logger(|log| {
            let subnet_type = SubnetType::System;
            let dst: u32 = 0;

            let mut payload: Vec<u8> = dst.to_le_bytes().to_vec();
            payload.extend(random_payload());

            let mut double_size_payload: Vec<u8> = payload.clone();
            double_size_payload.extend(random_payload());

            let instructions_consumed_without_data = get_num_instructions_consumed(
                log.clone(),
                "write_bytes",
                dst.to_le_bytes().to_vec(),
                MAX_NUM_INSTRUCTIONS,
                subnet_type,
            )
            .unwrap();

            {
                // Number of instructions consumed for copying the payload is zero.
                let consumed_instructions = get_num_instructions_consumed(
                    log.clone(),
                    "write_bytes",
                    payload,
                    MAX_NUM_INSTRUCTIONS,
                    subnet_type,
                )
                .unwrap()
                    - instructions_consumed_without_data;
                assert_eq!(consumed_instructions.get(), 0);
            }

            {
                // Number of instructions consumed for copying the payload is zero.
                let consumed_instructions = get_num_instructions_consumed(
                    log,
                    "write_bytes",
                    double_size_payload,
                    MAX_NUM_INSTRUCTIONS,
                    subnet_type,
                )
                .unwrap()
                    - instructions_consumed_without_data;
                assert_eq!(consumed_instructions.get(), 0);
            }
        })
    }

    fn get_num_instructions_consumed(
        log: ReplicaLogger,
        method: &str,
        payload: Vec<u8>,
        max_num_instructions: NumInstructions,
        subnet_type: SubnetType,
    ) -> Result<NumInstructions, HypervisorError> {
        let wat = make_module_wat(2 * TEST_NUM_PAGES);
        let wasm = wat2wasm(&wat).unwrap();

        let config = Config::default();
        let embedder = WasmtimeEmbedder::new(config, log.clone());
        let output_instrumentation = instrument(&wasm, &InstructionCostTable::new()).unwrap();
        let api = test_api_for_update(log, None, payload, subnet_type);
        let mut inst = embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(&output_instrumentation.binary).unwrap(),
                &[],
                NumWasmPages::from(0),
                PageMap::default(),
                ModificationTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        inst.set_num_instructions(max_num_instructions);

        inst.run(FuncRef::Method(WasmMethod::Update(method.into())))?;

        // The amount of instructions consumed.
        Ok(max_num_instructions - inst.get_num_instructions())
    }

    #[test]
    fn wasmtime_random_memory_writes() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        apply_writes_and_check_heap(writes, ModificationTracking::Track);
    }

    #[test]
    fn wasmtime_random_memory_writes_ignore_dirty_pages() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        apply_writes_and_check_heap(writes, ModificationTracking::Ignore);
    }
}
