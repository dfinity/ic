use ic_config::{
    embedders::Config as EmbeddersConfig, flag_status::FlagStatus, subnet_config::SchedulerConfig,
};
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::wasm_utils::compile;
use ic_embedders::WasmtimeEmbedder;
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, NetworkTopology, NumWasmPages};
use ic_sys::PAGE_SIZE;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType, SystemApiImpl};
use ic_system_api::{DefaultOutOfInstructionsHandler, ExecutionParameters, InstructionLimits};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::{call_context_test_id, user_test_id};
use ic_types::MemoryAllocation;
use ic_types::{
    messages::RequestMetadata,
    methods::{FuncRef, WasmMethod},
    time::UNIX_EPOCH,
    ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId,
};
use ic_wasm_types::BinaryEncodedWasm;
use lazy_static::lazy_static;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::rc::Rc;
use std::sync::Arc;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const STABLE_OP_BYTES: u64 = 37;

const SUBNET_MEMORY_CAPACITY: i64 = i64::MAX / 2;

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory = SubnetAvailableMemory::new(
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY
    );
}

fn test_api_for_update(
    log: ReplicaLogger,
    caller: Option<PrincipalId>,
    payload: Vec<u8>,
    subnet_type: SubnetType,
    instruction_limit: NumInstructions,
) -> SystemApiImpl {
    let caller = caller.unwrap_or_else(|| user_test_id(24).get());
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = Arc::new(
        CyclesAccountManagerBuilder::new()
            .with_subnet_type(subnet_type)
            .build(),
    );

    let api_type = ApiType::update(
        UNIX_EPOCH,
        payload,
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    );

    let static_system_state = SandboxSafeSystemState::new(
        &system_state,
        *cycles_account_manager,
        &NetworkTopology::default(),
        match subnet_type {
            SubnetType::Application => SchedulerConfig::application_subnet(),
            SubnetType::System => SchedulerConfig::system_subnet(),
            SubnetType::VerifiedApplication => SchedulerConfig::verified_application_subnet(),
        }
        .dirty_page_overhead,
        ComputeAllocation::default(),
        RequestMetadata::new(0, UNIX_EPOCH),
        Some(caller),
        api_type.call_context_id(),
    );
    let canister_memory_limit = NumBytes::from(4 << 30);
    let canister_current_memory_usage = NumBytes::from(0);
    let canister_current_message_memory_usage = NumBytes::from(0);

    SystemApiImpl::new(
        api_type,
        static_system_state,
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        ExecutionParameters {
            instruction_limits: InstructionLimits::new(
                FlagStatus::Disabled,
                instruction_limit,
                instruction_limit,
            ),
            canister_memory_limit,
            wasm_memory_limit: None,
            memory_allocation: MemoryAllocation::default(),
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
            subnet_memory_saturation: ResourceSaturation::default(),
        },
        *MAX_SUBNET_AVAILABLE_MEMORY,
        EmbeddersConfig::default()
            .feature_flags
            .wasm_native_stable_memory,
        EmbeddersConfig::default().feature_flags.canister_backtrace,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        Rc::new(DefaultOutOfInstructionsHandler::new(instruction_limit)),
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
      (import "ic0" "stable64_read"
        (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
      (import "ic0" "stable_write"
        (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))
      (import "ic0" "stable64_write"
        (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))

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

      ;; stable_read of non-zero length
      (func $test_stable_read_nonzero
        (drop (call $ic0_stable_grow (i32.const 1)))
        (call $ic0_stable_read (i32.const 0) (i32.const 0) (i32.const {STABLE_OP_BYTES}))
      )

      ;; stable64_read of non-zero length
      (func $test_stable64_read_nonzero
        (drop (call $ic0_stable_grow (i32.const 1)))
        (call $ic0_stable64_read (i64.const 0) (i64.const 0) (i64.const {STABLE_OP_BYTES}))
      )

      ;; stable_write of non-zero length
      (func $test_stable_write_nonzero
        (drop (call $ic0_stable_grow (i32.const 1)))
        (call $ic0_stable_write (i32.const 0) (i32.const 0) (i32.const {STABLE_OP_BYTES}))
      )

      ;; stable64_write of non-zero length
      (func $test_stable64_write_nonzero
        (drop (call $ic0_stable_grow (i32.const 1)))
        (call $ic0_stable64_write (i64.const 0) (i64.const 0) (i64.const {STABLE_OP_BYTES}))
      )

      (memory $memory {HEAP_SIZE})
      (export "memory" (memory $memory))
      (export "canister_query dump_heap" (func $dump_heap))
      (export "canister_update write_bytes" (func $write_bytes))
      (export "canister_update test_stable_read" (func $test_stable_read))
      (export "canister_update test_stable_read_nonzero" (func $test_stable_read_nonzero))
      (export "canister_update test_stable64_read_nonzero" (func $test_stable_read_nonzero))
      (export "canister_update test_stable_write_nonzero" (func $test_stable_write_nonzero))
      (export "canister_update test_stable64_write_nonzero" (func $test_stable64_write_nonzero))
    )"#,
        HEAP_SIZE = heap_size
    )
}

fn make_module_wat_for_api_calls(heap_size: usize) -> String {
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
      (import "ic0" "msg_caller_copy"
        (func $ic0_msg_caller_copy (param i32) (param i32) (param i32)))
      (import "ic0" "msg_caller_size"
        (func $ic0_msg_caller_size (result i32)))
      (import "ic0" "canister_self_copy"
        (func $ic0_canister_self_copy (param i32) (param i32) (param i32)))
      (import "ic0" "canister_self_size"
        (func $ic0_canister_self_size (result i32)))

      (import "ic0" "canister_cycle_balance128"
        (func $ic0_canister_cycle_balance128 (param i32)))

      (import "ic0" "stable_grow"
        (func $ic0_stable_grow (param $pages i32) (result i32)))
      (import "ic0" "stable_read"
        (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
      (import "ic0" "stable_write"
        (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))

      (func $touch_heap_with_api_calls
        (call $ic0_msg_caller_copy (i32.const 4096) (i32.const 0) (call $ic0_msg_caller_size))
        (call $ic0_msg_arg_data_copy (i32.const 12288) (i32.const 0) (call $ic0_msg_arg_data_size))
        (call $ic0_canister_self_copy (i32.const 20480) (i32.const 0) (call $ic0_canister_self_size))
        (call $ic0_canister_cycle_balance128 (i32.const 36864))

        (; Write some data to page 10 using stable_read, by first copying 4
        bytes from the second page to stable memory, then copying back ;)
        (drop (call $ic0_stable_grow (i32.const 1)))
        (call $ic0_stable_write (i32.const 0) (i32.const 4096) (i32.const 4))
        (call $ic0_stable_read (i32.const 40960) (i32.const 0) (i32.const 4))
      )

      (memory $memory {HEAP_SIZE})
      (export "memory" (memory $memory))
      (export "canister_update touch_heap_with_api_calls" (func $touch_heap_with_api_calls))
    )"#,
        HEAP_SIZE = heap_size
    )
}

fn make_module64_wat_for_api_calls(heap_size: usize) -> String {
    format!(
        r#"
    (module
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i64) (param i64)))
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i64)))
      (import "ic0" "msg_caller_copy"
        (func $ic0_msg_caller_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_caller_size"
        (func $ic0_msg_caller_size (result i64)))
      (import "ic0" "canister_self_copy"
        (func $ic0_canister_self_copy (param i64) (param i64) (param i64)))
      (import "ic0" "canister_self_size"
        (func $ic0_canister_self_size (result i64)))

      (import "ic0" "canister_cycle_balance128"
        (func $ic0_canister_cycle_balance128 (param i64)))

      (import "ic0" "stable64_grow"
        (func $ic0_stable64_grow (param $pages i64) (result i64)))
      (import "ic0" "stable64_read"
        (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
      (import "ic0" "stable64_write"
        (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))

      (func $touch_heap_with_api_calls
        (call $ic0_msg_caller_copy (i64.const 4096) (i64.const 0) (call $ic0_msg_caller_size))
        (call $ic0_msg_arg_data_copy (i64.const 12288) (i64.const 0) (call $ic0_msg_arg_data_size))
        (call $ic0_canister_self_copy (i64.const 20480) (i64.const 0) (call $ic0_canister_self_size))
        (call $ic0_canister_cycle_balance128 (i64.const 36864))

        (; Write some data to page 10 using stable_read, by first copying 4
        bytes from the second page to stable memory, then copying back ;)
        (drop (call $ic0_stable64_grow (i64.const 1)))
        (call $ic0_stable64_write (i64.const 0) (i64.const 4096) (i64.const 4))
        (call $ic0_stable64_read (i64.const 40960) (i64.const 0) (i64.const 4))
      )

      (memory $memory i64 {HEAP_SIZE})
      (export "memory" (memory $memory))
      (export "canister_update touch_heap_with_api_calls" (func $touch_heap_with_api_calls))
    )"#,
        HEAP_SIZE = heap_size
    )
}

fn make_module_wat_with_write_fun(heap_size: usize, write_fun: &str) -> String {
    format!(
        r#"
    (module
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i32)))

      ;; write to memory
      {WRITE_FUN}

      (memory $memory {HEAP_SIZE})
      (export "memory" (memory $memory))
      (export "canister_update write_bytes" (func $write_bytes))
    )"#,
        WRITE_FUN = write_fun,
        HEAP_SIZE = heap_size
    )
}

fn make_backward_store_module_wat(
    heap_size: usize,
    store_inst_data_size: usize,
    store_inst: &str,
    load_inst: &str,
) -> String {
    let write_fun = format!(
        r#"
      (func $write_bytes
        (local $i i32)
        ;; copy payload to the beginning of the heap
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (call $ic0_msg_arg_data_size) ;; len
        )
        ;; now copy the payload[4..] using I32.store to the heap[addr;size-4]
        (local.set $i (i32.sub (call $ic0_msg_arg_data_size) (i32.const 4)))
        (loop $copy_loop
          (i32.sub (local.get $i) (i32.const {store_inst_data_size}))
          (local.set $i)

          ({store_inst}
            (i32.add (i32.load (i32.const 0)) (local.get $i))
            ({load_inst} (i32.add (local.get $i) (i32.const 4)))
          )

          (i32.gt_s (local.get $i) (i32.const 0))
          br_if $copy_loop
        )
        (call $msg_reply)
      )
      "#,
        store_inst_data_size = store_inst_data_size,
        store_inst = store_inst,
        load_inst = load_inst,
    );
    make_module_wat_with_write_fun(heap_size, &write_fun)
}

/// Note: this module may not actually do the write properly if the payload is
/// large enough to read the destination address, because we first copy the
/// payload to address 4 and then move it to the destination in the forward
/// direction.
fn make_i32_store_forward_module_wat(heap_size: usize) -> String {
    let write_fun = r#"
      (func $write_bytes
        (local $i i32)
        ;; copy payload to the beginning of the heap
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (call $ic0_msg_arg_data_size) ;; len
        )
        ;; now copy the payload[4..] using I32.store to the heap[addr;size-4]
        (local.set $i (i32.const 0))
        (loop $copy_loop
          (i32.store
            (i32.add (i32.load (i32.const 0)) (local.get $i))
            (i32.load (i32.add (local.get $i) (i32.const 4)))
          )

          (i32.add (local.get $i) (i32.const 4))
          (local.set $i)

          (i32.lt_u (local.get $i) (i32.sub (call $ic0_msg_arg_data_size) (i32.const 4)))
          br_if $copy_loop
        )
        (call $msg_reply)
      )
      "#;
    make_module_wat_with_write_fun(heap_size, write_fun)
}

#[derive(Clone, Debug)]
pub struct Write {
    dst: u32,
    bytes: Vec<u8>,
}

fn random_writes(
    heap_size: usize,
    num_writes: usize,
    quant_size: usize,
) -> impl Strategy<Value = Vec<Write>> {
    // Start generating writes at address 4096 (or higher) to avoid generating
    // writes to the first OS page. This is because we must first copy the
    // offset from the payload to Wasm memory. We store the 4-byte offset at
    // addr=0, hence dirtying the first OS page.
    let write_strategy = (4096..(heap_size as u32)).prop_flat_map(move |dst| {
        // up to 128 bytes
        let remain = (heap_size - dst as usize) % 128;
        prop::collection::vec(any::<u8>(), 0..=remain).prop_map(move |mut bytes| {
            bytes.truncate(bytes.len() - bytes.len() % quant_size);
            Write { dst, bytes }
        })
    });
    prop::collection::vec(write_strategy, 1..num_writes)
}

fn corner_case_writes(heap_size: usize, quant_size: usize) -> Vec<Vec<Write>> {
    assert!(heap_size > 4096 * 3); // These cases assume we have at least three pages.

    vec![
        // Write zero to second page so that the contents doesn't actually
        // change and it is no longer considered dirty.
        vec![Write {
            dst: 4096,
            bytes: vec![0; quant_size],
        }],
        // Write that crosses a page boundary.
        vec![Write {
            dst: (4096 * 2 - if quant_size == 1 { 1 } else { quant_size - 1 }) as u32,
            bytes: vec![5; if quant_size == 1 { 2 } else { quant_size }],
        }],
        // Write that just fits on the second page.
        vec![Write {
            dst: (4096 * 2 - quant_size) as u32,
            bytes: vec![5; quant_size],
        }],
    ]
}

fn buf_apply_write(heap: &mut [u8], write: &Write, copies_data_to_first_page: bool) {
    // match the behavior of write_bytes: copy the i32 `addr` to heap[0;4]
    heap[0..4].copy_from_slice(&write.dst.to_le_bytes());
    if copies_data_to_first_page {
        heap[4..4 + write.bytes.len()].copy_from_slice(&write.bytes);
    }
    heap[write.dst as usize..(write.dst as usize + write.bytes.len())].copy_from_slice(&write.bytes)
}

const TEST_HEAP_SIZE_BYTES: usize = WASM_PAGE_SIZE_BYTES * TEST_NUM_PAGES;
const TEST_NUM_PAGES: usize = 800;
const TEST_NUM_WRITES: usize = 2000;
const WASM_PAGE_SIZE_BYTES: usize = 65536;
const BYTES_PER_INSTRUCTION: usize = 1;

fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wat::Error> {
    wat::parse_str(wat).map(BinaryEncodedWasm::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_embedders::{
        wasm_executor::compute_page_delta, wasm_utils::instrumentation::instruction_to_cost,
        wasmtime_embedder::CanisterMemoryType,
    };
    // Get .current() trait method
    use ic_interfaces::execution_environment::{HypervisorError, SystemApi};
    use ic_logger::ReplicaLogger;
    use ic_replicated_state::{PageIndex, PageMap};
    use ic_system_api::ModificationTracking;
    use ic_test_utilities_types::ids::canister_test_id;
    use proptest::strategy::ValueTree;

    fn apply_writes_and_check_heap(
        writes: &[Write],
        modification_tracking: ModificationTracking,
        wat: &str,
        copies_data_to_first_page: bool,
    ) {
        with_test_replica_logger(|log| {
            let wasm = wat2wasm(wat).unwrap();

            let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), log);
            let (embedder_cache, result) = compile(&embedder, &wasm);
            result.unwrap();

            // We will perform identical writes to wasm module's heap and this buffer.
            let mut test_heap = vec![0; TEST_HEAP_SIZE_BYTES];
            // Use SIGSEGV tracking and later compare against /proc/pic/pagemap.
            let mut page_map = PageMap::new_for_testing();
            let mut dirty_pages: BTreeSet<u64> = BTreeSet::new();

            for write in writes {
                let mut payload = write.dst.to_le_bytes().to_vec();
                payload.extend(write.bytes.iter());

                let api = test_api_for_update(
                    no_op_logger(),
                    None,
                    payload,
                    SubnetType::Application,
                    MAX_NUM_INSTRUCTIONS,
                );
                let instruction_limit = api.slice_instruction_limit();
                let mut instance = embedder
                    .new_instance(
                        canister_test_id(1),
                        &embedder_cache,
                        None,
                        &Memory::new(page_map.clone(), NumWasmPages::from(0)),
                        &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                        modification_tracking,
                        Some(api),
                    )
                    .map_err(|r| r.0)
                    .expect("Failed to create instance");
                instance.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());

                // Apply the write to the test buffer.
                buf_apply_write(&mut test_heap, write, copies_data_to_first_page);

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
                    let addr = instance.heap_addr(CanisterMemoryType::Heap);
                    let size_in_bytes =
                        instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_BYTES;
                    std::slice::from_raw_parts_mut(addr as *mut _, size_in_bytes)
                };
                let start = write.dst as usize;
                let end = start + write.bytes.len();
                assert_eq!(wasm_heap[start..end], test_heap[start..end]);

                if modification_tracking == ModificationTracking::Track {
                    dirty_pages.extend(result.wasm_dirty_pages.iter().map(|x| x.get()));

                    // Verify that wasm heap and test buffer are the same.
                    let i = result.wasm_dirty_pages.last().unwrap().get();
                    let offset = i as usize * PAGE_SIZE;
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
                    page_map.update(&compute_page_delta(
                        &mut instance,
                        &result.wasm_dirty_pages,
                        CanisterMemoryType::Heap,
                    ));
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
                    for Write { dst, bytes } in writes {
                        if !bytes.is_empty() {
                            if embedder.config().feature_flags.write_barrier == FlagStatus::Disabled
                            {
                                // A page will not actually be considered dirty
                                // unless the contents has changed. Memory is
                                // initially all 0, so this means we should ignore
                                // all zero bytes.
                                result.extend(
                                    bytes
                                        .iter()
                                        .enumerate()
                                        .filter(|(_, b)| **b != 0)
                                        .map(|(addr, _)| {
                                            (*dst as u64 + addr as u64) / PAGE_SIZE as u64
                                        })
                                        .collect::<BTreeSet<_>>(),
                                );
                            } else {
                                result.extend(
                                    *dst as u64 / PAGE_SIZE as u64
                                        ..=(*dst as u64 + bytes.len() as u64 - 1)
                                            / PAGE_SIZE as u64,
                                );
                            }
                        }
                    }
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
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 1)
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

            let config = EmbeddersConfig::default();
            let embedder = WasmtimeEmbedder::new(config, log.clone());
            let (cache, result) = compile(&embedder, &wasm);
            result.unwrap();

            let api = test_api_for_update(
                log,
                None,
                payload,
                SubnetType::Application,
                MAX_NUM_INSTRUCTIONS,
            );
            let instruction_limit = api.slice_instruction_limit();
            let mut inst = embedder
                .new_instance(
                    canister_test_id(1),
                    &cache,
                    None,
                    &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                    &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                    ModificationTracking::Ignore,
                    Some(api),
                )
                .map_err(|r| r.0)
                .expect("Failed to create instance");
            inst.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());

            let _result = inst.run(FuncRef::Method(WasmMethod::Update("func_trap".into())));

            // The amount of instructions consumed: 2 constants, trap() (21 instructions)
            // plus equivalent of `num_bytes` in instructions.
            let instruction_counter = inst.instruction_counter();
            let instructions_executed = inst
                .store_data()
                .system_api()
                .unwrap()
                .slice_instructions_executed(instruction_counter);

            // (call $trap (i32.const 0) (i32.const 2147483648)) ;; equivalent to 2 ^ 31
            let expected_instructions = 1 // Function is 1 instruction.
                + instruction_to_cost(&wasmparser::Operator::Call { function_index: 0 })
                + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::TRAP.get()
                + 2 * instruction_to_cost(&wasmparser::Operator::I32Const { value: 1 });
            assert_eq!(
                instructions_executed.get(),
                expected_instructions + (num_bytes / BYTES_PER_INSTRUCTION) as u64
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
            let max_num_instructions = NumInstructions::new(10_000);

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
                Err(HypervisorError::InstructionLimitExceeded(
                    max_num_instructions
                ))
            )
        })
    }

    mod stable_api_charges {
        //! These tests check the proper instructions are charged for various
        //! stable API operations.  Each function contains a single stable read
        //! or write, in addition to 7 instructions required for setup.

        use super::{
            get_num_instructions_consumed, SubnetType, MAX_NUM_INSTRUCTIONS, STABLE_OP_BYTES,
        };
        use ic_config::subnet_config::SchedulerConfig;
        use ic_embedders::wasm_utils::instrumentation::instruction_to_cost;
        use ic_logger::replica_logger::no_op_logger;

        // (drop (call $ic0_stable_grow (i32.const 1)))
        // (call $ic0_stable64_read (i64.const 0) (i64.const 0) (i64.const {STABLE_OP_BYTES}))
        fn setup_instruction_overhead() -> u64 {
            instruction_to_cost(&wasmparser::Operator::Drop)
                + instruction_to_cost(&wasmparser::Operator::Call { function_index: 0 })
                + ic_embedders::wasmtime_embedder::system_api_complexity::overhead_native::STABLE_GROW.get()
                + instruction_to_cost(&wasmparser::Operator::I32Const { value: 1 })
                + instruction_to_cost(&wasmparser::Operator::Call { function_index: 0 })
                + 3 * instruction_to_cost(&wasmparser::Operator::I32Const { value: 1 })
                + 1 // Function is 1 instruction.
        }

        #[test]
        fn empty_stable_read_charge() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable_read",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::Application,
            )
            .unwrap();
            // Additional charge for an empty read should just be the overhead.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_READ
                        .get()
            );
        }

        #[test]
        fn nonempty_stable_read_charge() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable_read_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::Application,
            )
            .unwrap();
            // Read of `STABLE_OP_BYTES` should cost an additional instruction
            // for each byte.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_READ
                        .get()
                    + STABLE_OP_BYTES
            );
        }

        #[test]
        fn nonempty_stable64_read_charge() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable64_read_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::Application,
            )
            .unwrap();
            // Read of `STABLE_OP_BYTES` should cost an additional instruction
            // for each byte.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE64_READ
                        .get()
                    + STABLE_OP_BYTES
            );
        }

        #[test]
        fn stable_read_charge_system_subnet() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable_read_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::System,
            )
            .unwrap();
            // Only the fixed cost is charged on system subnets.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_READ
                        .get()
            );
        }

        #[test]
        fn nonempty_stable_write_charge() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable_write_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::Application,
            )
            .unwrap();
            // Read of `STABLE_OP_BYTES` should cost an additional instruction
            // for each byte and an extra charge for one dirty page.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_WRITE
                        .get()
                    + STABLE_OP_BYTES
                    + SchedulerConfig::application_subnet()
                        .dirty_page_overhead
                        .get()
            );
        }

        #[test]
        fn nonempty_stable_write_charge_system_subnet() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable_write_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::System,
            )
            .unwrap();
            // Only the extra charge for the dirty page.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_WRITE
                        .get()
                    + SchedulerConfig::system_subnet().dirty_page_overhead.get()
            );
        }

        #[test]
        fn nonempty_stable64_write_charge() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable64_write_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::Application,
            )
            .unwrap();
            // Read of `STABLE_OP_BYTES` should cost an additional instruction
            // for each byte and an extra charge for one dirty page.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_WRITE
                        .get()
                    + STABLE_OP_BYTES
                    + SchedulerConfig::application_subnet()
                        .dirty_page_overhead
                        .get()
            );
        }

        #[test]
        fn nonempty_stable64_write_charge_system_subnet() {
            let instructions_consumed = get_num_instructions_consumed(
                no_op_logger(),
                "test_stable64_write_nonzero",
                vec![],
                MAX_NUM_INSTRUCTIONS,
                SubnetType::System,
            )
            .unwrap();
            // Only the extra charge for the dirty page.
            assert_eq!(
                instructions_consumed.get(),
                setup_instruction_overhead()
                    + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::STABLE_WRITE
                        .get()
                    + SchedulerConfig::system_subnet().dirty_page_overhead.get()
            );
        }
    }

    #[test]
    fn test_proportional_instructions_consumption_to_data_size() {
        with_test_replica_logger(|log| {
            let subnet_type = SubnetType::Application;
            let dst: u32 = 0;

            let dirty_heap_cost = match EmbeddersConfig::default().metering_type {
                ic_config::embedders::MeteringType::New => SchedulerConfig::application_subnet()
                    .dirty_page_overhead
                    .get(),
                _ => 0,
            };

            let mut payload: Vec<u8> = dst.to_le_bytes().to_vec();
            payload.extend(random_payload());
            let payload_size = payload.len() - 4;

            let mut double_size_payload: Vec<u8> = payload.clone();
            double_size_payload.extend(random_payload());

            let (instructions_consumed_without_data, dry_run_stats) = run_and_get_stats(
                log.clone(),
                "write_bytes",
                dst.to_le_bytes().to_vec(),
                MAX_NUM_INSTRUCTIONS,
                subnet_type,
            )
            .unwrap();
            let dry_run_dirty_heap = dry_run_stats.wasm_dirty_pages.len() as u64;

            {
                // Number of instructions consumed only for copying the payload.
                let (consumed_instructions, run_stats) = run_and_get_stats(
                    log.clone(),
                    "write_bytes",
                    payload,
                    MAX_NUM_INSTRUCTIONS,
                    subnet_type,
                )
                .unwrap();
                let dirty_heap = run_stats.wasm_dirty_pages.len() as u64;
                let consumed_instructions =
                    consumed_instructions - instructions_consumed_without_data;
                assert_eq!(
                    (consumed_instructions.get() - dirty_heap * dirty_heap_cost) as usize,
                    (payload_size / BYTES_PER_INSTRUCTION)
                        - (dry_run_dirty_heap * dirty_heap_cost) as usize,
                );
            }

            {
                // Number of instructions consumed increased with the size of the data.
                let (consumed_instructions, run_stats) = run_and_get_stats(
                    log,
                    "write_bytes",
                    double_size_payload,
                    MAX_NUM_INSTRUCTIONS,
                    subnet_type,
                )
                .unwrap();
                let dirty_heap = run_stats.wasm_dirty_pages.len() as u64;
                let consumed_instructions =
                    consumed_instructions - instructions_consumed_without_data;

                assert_eq!(
                    (consumed_instructions.get() - dirty_heap * dirty_heap_cost) as usize,
                    (2 * payload_size / BYTES_PER_INSTRUCTION)
                        - (dry_run_dirty_heap * dirty_heap_cost) as usize
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

    fn run_and_get_stats(
        log: ReplicaLogger,
        method: &str,
        payload: Vec<u8>,
        max_num_instructions: NumInstructions,
        subnet_type: SubnetType,
    ) -> Result<(NumInstructions, ic_embedders::InstanceRunResult), HypervisorError> {
        let wat = make_module_wat(2 * TEST_NUM_PAGES);
        let wasm = wat2wasm(&wat).unwrap();

        let config = EmbeddersConfig {
            subnet_type,
            dirty_page_overhead: match subnet_type {
                SubnetType::System => SchedulerConfig::system_subnet(),
                SubnetType::Application => SchedulerConfig::application_subnet(),
                SubnetType::VerifiedApplication => SchedulerConfig::verified_application_subnet(),
            }
            .dirty_page_overhead,
            ..EmbeddersConfig::default()
        };
        let embedder = WasmtimeEmbedder::new(config, log.clone());
        let (cache, result) = compile(&embedder, &wasm);
        result.unwrap();
        let api = test_api_for_update(log, None, payload, subnet_type, max_num_instructions);
        let instruction_limit = api.slice_instruction_limit();
        let mut inst = embedder
            .new_instance(
                canister_test_id(1),
                &cache,
                None,
                &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                ModificationTracking::Track,
                Some(api),
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        inst.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());

        let res = inst.run(FuncRef::Method(WasmMethod::Update(method.into())))?;

        let instruction_counter = inst.instruction_counter();
        let instructions_executed = inst
            .store_data()
            .system_api()
            .unwrap()
            .slice_instructions_executed(instruction_counter);

        Ok((instructions_executed, res))
    }

    fn get_num_instructions_consumed(
        log: ReplicaLogger,
        method: &str,
        payload: Vec<u8>,
        max_num_instructions: NumInstructions,
        subnet_type: SubnetType,
    ) -> Result<NumInstructions, HypervisorError> {
        let (num_instructions, _) =
            run_and_get_stats(log, method, payload, max_num_instructions, subnet_type)?;
        Ok(num_instructions)
    }

    #[test]
    fn wasmtime_random_memory_writes() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_module_wat(TEST_NUM_PAGES);
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 1);
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 1)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, false)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, false);
    }

    #[test]
    fn wasmtime_random_memory_writes_i32store() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 4, "i32.store", "i32.load");
        let wat2 = make_i32_store_forward_module_wat(TEST_NUM_PAGES);
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 4)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 4);
        for writes in &corner_writes {
            apply_writes_and_check_heap(writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);

        for writes in &corner_writes {
            apply_writes_and_check_heap(writes, ModificationTracking::Track, &wat2, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat2, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_i32store8() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 1, "i32.store8", "i32.load8_u");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 1)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 1);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_i32store16() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 2, "i32.store16", "i32.load16_u");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 2)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 2);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_i64store() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 8, "i64.store", "i64.load");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 8)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 8);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_i64store8() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 1, "i64.store8", "i64.load8_u");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 1)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 1);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_i64store16() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 2, "i64.store16", "i64.load16_u");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 2)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 2);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_i64store32() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 4, "i64.store32", "i64.load32_u");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 4)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 4);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_f32store() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 4, "f32.store", "f32.load");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 4)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 4);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn wasmtime_random_memory_writes_f64store() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_backward_store_module_wat(TEST_NUM_PAGES, 8, "f64.store", "f64.load");
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 8)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 8);
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, true);
    }

    #[test]
    fn touch_heap_with_api_calls() {
        with_test_replica_logger(|log| {
            let wat = make_module_wat_for_api_calls(TEST_NUM_PAGES);
            let wasm = wat2wasm(&wat).unwrap();
            let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), log);
            let (embedder_cache, result) = compile(&embedder, &wasm);
            result.unwrap();

            let mut dirty_pages: BTreeSet<u64> = BTreeSet::new();

            let payload = vec![0, 1, 2, 3, 4, 5, 6, 7];

            let api = test_api_for_update(
                no_op_logger(),
                None,
                payload,
                SubnetType::Application,
                MAX_NUM_INSTRUCTIONS,
            );
            let instruction_limit = api.slice_instruction_limit();
            let mut instance = embedder
                .new_instance(
                    canister_test_id(1),
                    &embedder_cache,
                    None,
                    &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                    &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                    ModificationTracking::Track,
                    Some(api),
                )
                .map_err(|r| r.0)
                .expect("Failed to create instance");
            instance.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());

            let result = instance
                .run(FuncRef::Method(WasmMethod::Update(
                    "touch_heap_with_api_calls".to_string(),
                )))
                .expect("call to touch_heap_with_api_calls failed");
            dirty_pages.extend(result.wasm_dirty_pages.iter().map(|x| x.get()));

            let mut expected_dirty_pages: BTreeSet<u64> = BTreeSet::new();
            expected_dirty_pages.insert(1); // caller_copy
            expected_dirty_pages.insert(3); // data_copy
            expected_dirty_pages.insert(5); // canister_self_copy
            expected_dirty_pages.insert(9); // canister_cycle_balance128
            expected_dirty_pages.insert(9); // msg_cycles_available128
            expected_dirty_pages.insert(10); // stable_read

            assert_eq!(expected_dirty_pages, dirty_pages);
        });
    }

    #[test]
    fn touch_heap64_with_api_calls() {
        with_test_replica_logger(|log| {
            let wat = make_module64_wat_for_api_calls(TEST_NUM_PAGES);
            let wasm = wat2wasm(&wat).unwrap();
            let mut config = EmbeddersConfig::default();
            config.feature_flags.wasm64 = FlagStatus::Enabled;
            let embedder = WasmtimeEmbedder::new(config, log);
            let (embedder_cache, result) = compile(&embedder, &wasm);
            result.unwrap();

            let mut dirty_pages: BTreeSet<u64> = BTreeSet::new();

            let payload = vec![0, 1, 2, 3, 4, 5, 6, 7];

            let api = test_api_for_update(
                no_op_logger(),
                None,
                payload,
                SubnetType::Application,
                MAX_NUM_INSTRUCTIONS,
            );
            let instruction_limit = api.slice_instruction_limit();
            let mut instance = embedder
                .new_instance(
                    canister_test_id(1),
                    &embedder_cache,
                    None,
                    &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                    &Memory::new(PageMap::new_for_testing(), NumWasmPages::from(0)),
                    ModificationTracking::Track,
                    Some(api),
                )
                .map_err(|r| r.0)
                .expect("Failed to create instance");
            instance.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());

            let result = instance
                .run(FuncRef::Method(WasmMethod::Update(
                    "touch_heap_with_api_calls".to_string(),
                )))
                .expect("call to touch_heap_with_api_calls failed");
            dirty_pages.extend(result.wasm_dirty_pages.iter().map(|x| x.get()));

            let mut expected_dirty_pages: BTreeSet<u64> = BTreeSet::new();
            expected_dirty_pages.insert(1); // caller_copy
            expected_dirty_pages.insert(3); // data_copy
            expected_dirty_pages.insert(5); // canister_self_copy
            expected_dirty_pages.insert(9); // canister_cycle_balance128
            expected_dirty_pages.insert(9); // msg_cycles_available128
            expected_dirty_pages.insert(10); // stable_read

            assert_eq!(expected_dirty_pages, dirty_pages);
        });
    }

    #[test]
    fn wasmtime_random_memory_writes_ignore_dirty_pages() {
        // The seed value will always be the same for a particular version of
        // Proptest and algorithm, but may change across releases.
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let wat = make_module_wat(TEST_NUM_PAGES);
        let corner_writes = corner_case_writes(TEST_HEAP_SIZE_BYTES, 1);
        // Random, *non-empty* writes
        let writes: Vec<Write> = random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES, 1)
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .iter()
            .filter(|w| !w.bytes.is_empty())
            .cloned()
            .collect();
        for writes in corner_writes {
            apply_writes_and_check_heap(&writes, ModificationTracking::Track, &wat, false)
        }
        apply_writes_and_check_heap(&writes, ModificationTracking::Ignore, &wat, false);
    }
}
