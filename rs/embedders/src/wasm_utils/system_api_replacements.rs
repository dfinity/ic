//! Wasm implementations of the "ic0" "stable*" APIs to be injected into the
//! module and replace the imported functions.
//!
//! The functions will generally replace read/write/grow/size operations with
//! memory.copy/memory.grow/memory.size operations on the injected additional
//! stable memory. Additional work is needed to:
//!
//! - properly report errors in a backwards-compatible way
//! - convert between integer types and check for overflows
//! - track accesses and dirty pages
//! - charge for instructions
//!

use crate::{
    InternalErrorCode,
    wasm_utils::instrumentation::{InjectedCounters, InjectedFunctions, WasmMemoryType},
    wasmtime_embedder::system_api_complexity::overhead_native,
};
use ic_interfaces::execution_environment::StableMemoryApi;
use ic_sys::PAGE_SIZE;
use ic_types::NumInstructions;
use wirm::{DataType, ir::types::Instructions, wasmparser::BlockType};

use ic_types::NumBytes;

use super::SystemApiFunc;

const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: i64 = 64 * 1024; // 4GiB
const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;

fn make_body(
    locals: Vec<(u32, DataType)>,
    instructions: Vec<wirm::wasmparser::Operator>,
) -> wirm::ir::types::Body {
    wirm::ir::types::Body {
        num_locals: locals.len() as u32,
        num_instructions: instructions.len(),
        locals,
        instructions: Instructions::new(instructions),
        name: None,
    }
}

pub(super) type ReplacementFunction = (
    // Function parameters.
    Vec<wirm::DataType>,
    // Function results.
    Vec<wirm::DataType>,
    wirm::ir::types::Body<'static>,
);

pub(super) fn replacement_functions(
    injected_functions: &InjectedFunctions,
    injected_counters: &InjectedCounters,
    stable_memory_index: u32,
    dirty_page_overhead: NumInstructions,
    main_memory_type: WasmMemoryType,
    max_wasm_memory_size: NumBytes,
) -> Vec<(SystemApiFunc, ReplacementFunction)> {
    let count_clean_pages_fn_index = injected_counters.count_clean_pages_fn;
    let dirty_pages_counter_index = injected_counters.dirty_pages_counter;
    let accessed_pages_counter_index = injected_counters.accessed_pages_counter;
    let decr_instruction_counter_fn = injected_counters.decr_instruction_counter_fn;

    use wirm::wasmparser::Operator::*;
    let page_size_shift = PAGE_SIZE.trailing_zeros() as i32;
    let stable_memory_bytemap_index = stable_memory_index + 1;

    let cast_to_heap_addr_type = match main_memory_type {
        WasmMemoryType::Wasm32 => I32WrapI64,
        WasmMemoryType::Wasm64 => Nop,
    };

    let max_heap_address = match main_memory_type {
        // If we are in Wasm32 mode, we can't have a heap address that is larger than u32::MAX, which is 4 GiB.
        // In Wasm64 mode, we can have heap addresses that are larger than u32::MAX.
        // The embedders config passes along the largest heap size in Wasm64 mode.
        // We need to therefore allow the heap addresses to be larger than u32::MAX in Wasm64 mode
        // for stable_read and stable_write.
        WasmMemoryType::Wasm32 => u32::MAX as u64,
        WasmMemoryType::Wasm64 => max_wasm_memory_size.get(),
    };

    vec![
        (
            SystemApiFunc::StableSize,
            (
                vec![],
                vec![DataType::I32],
                make_body(
                    vec![],
                    vec![
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: MAX_32_BIT_STABLE_MEMORY_IN_PAGES,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryTooBigFor32Bit as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I32WrapI64,
                    ],
                ),
            ),
        ),
        (
            SystemApiFunc::Stable64Size,
            (
                vec![],
                vec![DataType::I64],
                make_body(
                    vec![],
                    vec![MemorySize {
                        mem: stable_memory_index,
                    }],
                ),
            ),
        ),
        (
            SystemApiFunc::StableGrow,
            (
                vec![DataType::I32],
                vec![DataType::I32],
                make_body(
                    vec![(1, DataType::I64)],
                    vec![
                        // Call try_grow_stable_memory API.
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        I32Const {
                            value: StableMemoryApi::Stable32 as i32,
                        },
                        Call {
                            function_index: injected_functions.try_grow_stable_memory,
                        },
                        // If result is -1, return -1
                        I64Const { value: -1 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const { value: -1 },
                        Return,
                        End,
                        // If successful, do the actual grow.
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        MemoryGrow {
                            mem: stable_memory_index,
                        },
                        LocalTee { local_index: 1 },
                        // If result is -1 then grow instruction failed - this
                        // shouldn't happen because the try grow API should have
                        // checked everything.
                        I64Const { value: -1 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableGrowFailed as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // Grow succeeded, return result of memory.grow.
                        LocalGet { local_index: 1 },
                        // We've already checked the resulting size is valid for 32-bit API when calling
                        // the try_grow_stable_memory API.
                        I32WrapI64,
                    ],
                ),
            ),
        ),
        (
            SystemApiFunc::Stable64Grow,
            (
                vec![DataType::I64],
                vec![DataType::I64],
                make_body(
                    vec![(1, DataType::I64)],
                    vec![
                        // Call try_grow_stable_memory API.
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        LocalGet { local_index: 0 },
                        I32Const {
                            value: StableMemoryApi::Stable64 as i32,
                        },
                        Call {
                            function_index: injected_functions.try_grow_stable_memory,
                        },
                        // If result is -1, return -1
                        I64Const { value: -1 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I64Const { value: -1 },
                        Return,
                        End, // End try_grow_stable_memory check.
                        // Actually do the grow, store result in local 1.
                        LocalGet { local_index: 0 },
                        MemoryGrow {
                            mem: stable_memory_index,
                        },
                        LocalTee { local_index: 1 },
                        // If result is -1 then grow instruction failed - this
                        // shouldn't happen because the try grow API should have
                        // checked everything.
                        I64Const { value: -1 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableGrowFailed as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // Return the result of memory.grow.
                        LocalGet { local_index: 1 },
                    ],
                ),
            ),
        ),
        (
            SystemApiFunc::StableRead,
            (vec![DataType::I32, DataType::I32, DataType::I32], vec![], {
                const DST: u32 = 0;
                const SRC: u32 = 1;
                const LEN: u32 = 2;
                const BYTEMAP_START: u32 = 3;
                const BYTEMAP_END: u32 = 4;
                const ACCESSED_PAGE_COUNT: u32 = 5;
                const BYTEMAP_ITERATOR: u32 = 6;
                const SHOULD_CALL_READ_API: u32 = 7;
                make_body(
                    vec![(5, DataType::I32)], // src on bytemap, src + len on bytemap, accessed page cnt, mark bytemap iterator, should call first read api
                    vec![
                        // Decrement instruction counter by the size of the copy
                        // and fixed overhead.
                        LocalGet { local_index: LEN },
                        I64ExtendI32U,
                        I64Const {
                            value: overhead_native::STABLE_READ.get() as i64,
                        },
                        I64Add,
                        Call {
                            function_index: decr_instruction_counter_fn,
                        },
                        Drop,
                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return errors if addresses are out of bounds
                        // in this case
                        LocalGet { local_index: LEN },
                        I32Const { value: 0 },
                        I32Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        // If memory is too big for 32bit api, we trap
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: MAX_32_BIT_STABLE_MEMORY_IN_PAGES,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryTooBigFor32Bit as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // check bounds on stable memory (fail if src + size > mem_size)
                        LocalGet { local_index: SRC },
                        I64ExtendI32U,
                        LocalGet { local_index: LEN },
                        I64ExtendI32U,
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: WASM_PAGE_SIZE as i64,
                        },
                        I64Mul,
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // src
                        LocalGet { local_index: SRC },
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        LocalTee {
                            local_index: BYTEMAP_START,
                        },
                        // bytemap_end
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        I32Add,
                        I32Const { value: 1 },
                        I32Sub,
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        I32Const { value: 1 },
                        I32Add,
                        LocalTee {
                            local_index: BYTEMAP_END,
                        },
                        Call {
                            function_index: count_clean_pages_fn_index,
                        },
                        // On top of the stack we have the number of pages
                        // that haven't been accessed in the given range.
                        // We need to call the first read API if this
                        // matches the total range.
                        LocalTee {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        LocalGet {
                            local_index: BYTEMAP_END,
                        },
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        I32Sub,
                        I32Eq,
                        LocalSet {
                            local_index: SHOULD_CALL_READ_API,
                        },
                        Drop, // Drop the number of unwritten pages.
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        // fail if accessed pages limit exhausted
                        I64ExtendI32U,
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::MemoryAccessLimitExceeded as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // mark accessed pages if there are any to be marked
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        I32Const { value: 0 },
                        I32GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        LocalSet {
                            local_index: BYTEMAP_ITERATOR,
                        }, // it
                        Loop {
                            blockty: BlockType::Empty,
                        },
                        LocalGet {
                            local_index: BYTEMAP_ITERATOR,
                        }, // it as arg for store
                        LocalGet {
                            local_index: BYTEMAP_ITERATOR,
                        }, // it as arg for load
                        I32Load8U {
                            memarg: wirm::wasmparser::MemArg {
                                align: 0,
                                max_align: 0,
                                offset: 0,
                                // We assume the bytemap for stable memory is always
                                // inserted directly after the stable memory.
                                memory: stable_memory_index + 1,
                            },
                        },
                        I32Const { value: 2 }, // READ_BIT
                        I32Or,
                        I32Store8 {
                            memarg: wirm::wasmparser::MemArg {
                                align: 0,
                                max_align: 0,
                                offset: 0,
                                // We assume the bytemap for stable memory is always
                                // inserted directly after the stable memory.
                                memory: stable_memory_index + 1,
                            },
                        },
                        LocalGet {
                            local_index: BYTEMAP_ITERATOR,
                        },
                        I32Const { value: 1 },
                        I32Add,
                        LocalTee {
                            local_index: BYTEMAP_ITERATOR,
                        },
                        LocalGet {
                            local_index: BYTEMAP_END,
                        },
                        I32LtU,
                        BrIf { relative_depth: 0 },
                        End, // end loop
                        End, // end if
                        // perform the copy, calling API if it's the first access.
                        LocalGet {
                            local_index: SHOULD_CALL_READ_API,
                        },
                        If {
                            blockty: BlockType::Empty,
                        },
                        LocalGet { local_index: DST },
                        I64ExtendI32U,
                        LocalGet { local_index: SRC },
                        I64ExtendI32U,
                        LocalGet { local_index: LEN },
                        I64ExtendI32U,
                        Call {
                            function_index: injected_functions.stable_read_first_access,
                        },
                        Else,
                        LocalGet { local_index: DST },
                        LocalGet { local_index: SRC },
                        I64ExtendI32U,
                        LocalGet { local_index: LEN },
                        MemoryCopy {
                            dst_mem: 0,
                            src_mem: stable_memory_index,
                        },
                        End, // End actual copy.
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Sub,
                        GlobalSet {
                            global_index: accessed_pages_counter_index,
                        },
                    ],
                )
            }),
        ),
        (
            SystemApiFunc::Stable64Read,
            (vec![DataType::I64, DataType::I64, DataType::I64], vec![], {
                const DST: u32 = 0;
                const SRC: u32 = 1;
                const LEN: u32 = 2;
                const BYTEMAP_START: u32 = 3;
                const BYTEMAP_END: u32 = 4;
                const ACCESSED_PAGE_COUNT: u32 = 5;
                const BYTEMAP_ITERATOR: u32 = 6;
                const SHOULD_CALL_READ_API: u32 = 7;
                make_body(
                    vec![(5, DataType::I32)], // src on bytemap, src + len on bytemap, accessed page cnt, mark bytemap iterator, should call first read api
                    vec![
                        // Decrement instruction counter by the size of the copy
                        // and fixed overhead.
                        LocalGet { local_index: LEN },
                        I64Const {
                            value: overhead_native::STABLE64_READ.get() as i64,
                        },
                        I64Add,
                        Call {
                            function_index: decr_instruction_counter_fn,
                        },
                        Drop,
                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return errors if addresses are out of bounds
                        // in this case
                        LocalGet { local_index: LEN },
                        I64Const { value: 0 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        // check bounds on stable memory (fail if dst + size > mem_size)
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        I64Add,
                        LocalGet { local_index: SRC },
                        // overflow (size != 0 because we checked earlier)
                        I64LeU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: WASM_PAGE_SIZE as i64,
                        },
                        I64Mul,
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // check if these i64 hold valid heap addresses
                        // check dst
                        LocalGet { local_index: DST },
                        I64Const {
                            value: max_heap_address as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // check len
                        LocalGet { local_index: LEN },
                        I64Const {
                            value: max_heap_address as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // src
                        LocalGet { local_index: SRC },
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        I32WrapI64,
                        LocalTee {
                            local_index: BYTEMAP_START,
                        },
                        // bytemap_end
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        I64Add,
                        I64Const { value: 1 },
                        I64Sub,
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        I64Const { value: 1 },
                        I64Add,
                        I32WrapI64,
                        LocalTee {
                            local_index: BYTEMAP_END,
                        },
                        Call {
                            function_index: count_clean_pages_fn_index,
                        },
                        // On top of the stack we have the number of pages
                        // that haven't been accessed in the given range.
                        // We need to call the first read API if this
                        // matches the total range.
                        LocalTee {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        LocalGet {
                            local_index: BYTEMAP_END,
                        },
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        I32Sub,
                        I32Eq,
                        LocalSet {
                            local_index: SHOULD_CALL_READ_API,
                        }, // Should use first read API
                        Drop, // Drop the number of unwritten pages.
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        }, // unaccessed pages
                        // fail if accessed pages limit exhausted
                        I64ExtendI32U,
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::MemoryAccessLimitExceeded as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // mark accessed pages if there are any to be marked
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        I32Const { value: 0 },
                        I32GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        LocalSet {
                            local_index: BYTEMAP_ITERATOR,
                        }, // it
                        Loop {
                            blockty: BlockType::Empty,
                        },
                        LocalGet {
                            local_index: BYTEMAP_ITERATOR,
                        }, // it as arg for store
                        LocalGet {
                            local_index: BYTEMAP_ITERATOR,
                        }, // it as arg for load
                        I32Load8U {
                            memarg: wirm::wasmparser::MemArg {
                                align: 0,
                                max_align: 0,
                                offset: 0,
                                // We assume the bytemap for stable memory is always
                                // inserted directly after the stable memory.
                                memory: stable_memory_index + 1,
                            },
                        },
                        I32Const { value: 2 }, // READ_BIT
                        I32Or,
                        I32Store8 {
                            memarg: wirm::wasmparser::MemArg {
                                align: 0,
                                max_align: 0,
                                offset: 0,
                                // We assume the bytemap for stable memory is always
                                // inserted directly after the stable memory.
                                memory: stable_memory_index + 1,
                            },
                        },
                        LocalGet {
                            local_index: BYTEMAP_ITERATOR,
                        },
                        I32Const { value: 1 },
                        I32Add,
                        LocalTee {
                            local_index: BYTEMAP_ITERATOR,
                        },
                        LocalGet {
                            local_index: BYTEMAP_END,
                        },
                        I32LtU,
                        BrIf { relative_depth: 0 },
                        End, // end loop
                        End, // end if
                        // perform the copy, calling API if it's the first access.
                        LocalGet {
                            local_index: SHOULD_CALL_READ_API,
                        },
                        If {
                            blockty: BlockType::Empty,
                        },
                        LocalGet { local_index: DST },
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        Call {
                            function_index: injected_functions.stable_read_first_access,
                        },
                        Else,
                        LocalGet { local_index: DST },
                        cast_to_heap_addr_type.clone(),
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        cast_to_heap_addr_type.clone(),
                        MemoryCopy {
                            dst_mem: 0,
                            src_mem: stable_memory_index,
                        },
                        End, // End actual copy.
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Sub,
                        GlobalSet {
                            global_index: accessed_pages_counter_index,
                        },
                    ],
                )
            }),
        ),
        (
            SystemApiFunc::StableWrite,
            (vec![DataType::I32, DataType::I32, DataType::I32], vec![], {
                const DST: u32 = 0;
                const SRC: u32 = 1;
                const LEN: u32 = 2;
                const BYTEMAP_START: u32 = 3;
                const BYTEMAP_END: u32 = 4;
                const DIRTY_PAGE_COUNT: u32 = 5;
                const ACCESSED_PAGE_COUNT: u32 = 6;
                make_body(
                    vec![(4, DataType::I32)], // dst on bytemap, dst + len on bytemap, dirty page cnt, accessed page cnt
                    vec![
                        // Decrement instruction counter by the size of the copy
                        // and fixed overhead.
                        LocalGet { local_index: LEN },
                        I64ExtendI32U,
                        I64Const {
                            value: overhead_native::STABLE_WRITE.get() as i64,
                        },
                        I64Add,
                        Call {
                            function_index: decr_instruction_counter_fn,
                        },
                        Drop,
                        // If memory is too big for 32bit api, we trap
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: MAX_32_BIT_STABLE_MEMORY_IN_PAGES,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryTooBigFor32Bit as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // check bounds on stable memory (fail if dst + size > mem_size)
                        LocalGet { local_index: DST },
                        I64ExtendI32U,
                        LocalGet { local_index: LEN },
                        I64ExtendI32U,
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: WASM_PAGE_SIZE as i64,
                        },
                        I64Mul,
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // mark writes in the bytemap

                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return error if src address is out of bounds
                        // in this case
                        LocalGet { local_index: LEN },
                        I32Const { value: 0 },
                        I32Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        LocalGet { local_index: DST },
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        LocalTee {
                            local_index: BYTEMAP_START,
                        },
                        // bytemap_end
                        LocalGet { local_index: DST },
                        LocalGet { local_index: LEN },
                        I32Add,
                        I32Const { value: 1 },
                        I32Sub,
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        I32Const { value: 1 },
                        I32Add,
                        LocalTee {
                            local_index: BYTEMAP_END,
                        },
                        // count pages already dirty
                        Call {
                            function_index: count_clean_pages_fn_index,
                        },
                        LocalTee {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        // fail if accessed pages limit exhausted
                        I64ExtendI32U,
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::MemoryAccessLimitExceeded as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        LocalTee {
                            local_index: DIRTY_PAGE_COUNT,
                        },
                        // fail if dirty pages limit exhausted
                        I64ExtendI32U,
                        GlobalGet {
                            global_index: dirty_pages_counter_index,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::MemoryWriteLimitExceeded as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // Decrement instruction counter to charge for dirty pages
                        LocalGet {
                            local_index: DIRTY_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Const {
                            value: dirty_page_overhead.get().try_into().unwrap(),
                        },
                        I64Mul,
                        // Bounds check above should guarantee that we don't
                        // overflow as the over head is a small constant.
                        Call {
                            function_index: decr_instruction_counter_fn,
                        },
                        Drop,
                        // perform memory fill
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        // value to fill with
                        I32Const { value: 3 },
                        // calculate bytemap_size
                        // bytemap_end = (dst + size - 1) / PAGE_SIZE + 1
                        // bytemap_len = bytemap_end - bytemap_start
                        LocalGet {
                            local_index: BYTEMAP_END,
                        },
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        // bytemap_end - bytemap_start
                        I32Sub,
                        MemoryFill {
                            mem: stable_memory_bytemap_index,
                        },
                        // copy memory contents
                        LocalGet { local_index: DST },
                        I64ExtendI32U,
                        LocalGet { local_index: SRC },
                        LocalGet { local_index: LEN },
                        MemoryCopy {
                            dst_mem: stable_memory_index,
                            src_mem: 0,
                        },
                        GlobalGet {
                            global_index: dirty_pages_counter_index,
                        },
                        LocalGet {
                            local_index: DIRTY_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Sub,
                        GlobalSet {
                            global_index: dirty_pages_counter_index,
                        },
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Sub,
                        GlobalSet {
                            global_index: accessed_pages_counter_index,
                        },
                    ],
                )
            }),
        ),
        (
            SystemApiFunc::Stable64Write,
            (vec![DataType::I64, DataType::I64, DataType::I64], vec![], {
                const DST: u32 = 0;
                const SRC: u32 = 1;
                const LEN: u32 = 2;
                const BYTEMAP_START: u32 = 3;
                const BYTEMAP_END: u32 = 4;
                const DIRTY_PAGE_COUNT: u32 = 5;
                const ACCESSED_PAGE_COUNT: u32 = 6;
                make_body(
                    vec![(4, DataType::I32)], // dst on bytemap, dst + len on bytemap, dirty page cnt, accessed page cnt
                    vec![
                        // Decrement instruction counter by the size of the copy
                        // and fixed overhead.
                        LocalGet { local_index: LEN },
                        I64Const {
                            value: overhead_native::STABLE64_WRITE.get() as i64,
                        },
                        I64Add,
                        Call {
                            function_index: decr_instruction_counter_fn,
                        },
                        Drop,
                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return errors if addresses are out of bounds
                        // in this case
                        LocalGet { local_index: LEN },
                        I64Const { value: 0 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        // check bounds on stable memory (fail if dst + size > mem_size)
                        LocalGet { local_index: DST },
                        LocalGet { local_index: LEN },
                        I64Add,
                        LocalGet { local_index: DST },
                        // overflow (size != 0 because we checked earlier)
                        I64LeU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        LocalGet { local_index: DST },
                        LocalGet { local_index: LEN },
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                        },
                        I64Const {
                            value: WASM_PAGE_SIZE as i64,
                        },
                        I64Mul,
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // check if these i64 hold valid heap addresses
                        // check src
                        LocalGet { local_index: SRC },
                        I64Const {
                            value: max_heap_address as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // check len
                        LocalGet { local_index: LEN },
                        I64Const {
                            value: max_heap_address as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        LocalGet { local_index: DST },
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        I32WrapI64,
                        LocalTee {
                            local_index: BYTEMAP_START,
                        },
                        // bytemap_end
                        LocalGet { local_index: DST },
                        LocalGet { local_index: LEN },
                        I64Add,
                        I64Const { value: 1 },
                        I64Sub,
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        I64Const { value: 1 },
                        I64Add,
                        I32WrapI64,
                        LocalTee {
                            local_index: BYTEMAP_END,
                        },
                        Call {
                            function_index: count_clean_pages_fn_index,
                        },
                        LocalTee {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        // fail if accessed pages limit exhausted
                        I64ExtendI32U,
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::MemoryAccessLimitExceeded as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        LocalTee {
                            local_index: DIRTY_PAGE_COUNT,
                        },
                        // fail if dirty pages limit exhausted
                        I64ExtendI32U,
                        GlobalGet {
                            global_index: dirty_pages_counter_index,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::MemoryWriteLimitExceeded as i32,
                        },
                        Call {
                            function_index: injected_functions.internal_trap,
                        },
                        End,
                        // Decrement instruction counter to charge for dirty pages
                        LocalGet {
                            local_index: DIRTY_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Const {
                            value: dirty_page_overhead.get().try_into().unwrap(),
                        },
                        I64Mul,
                        // Bounds check above should guarantee that we don't
                        // overflow as the over head is a small constant.
                        Call {
                            function_index: decr_instruction_counter_fn,
                        },
                        Drop,
                        // perform memory fill
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        // value to fill with
                        I32Const { value: 3 },
                        // calculate bytemap_size
                        // bytemap_end = (dst + size - 1) / PAGE_SIZE + 1
                        // bytemap_len = bytemap_end - bytemap_start
                        LocalGet {
                            local_index: BYTEMAP_END,
                        },
                        LocalGet {
                            local_index: BYTEMAP_START,
                        },
                        // bytemap_end - bytemap_start
                        I32Sub,
                        MemoryFill {
                            mem: stable_memory_bytemap_index,
                        },
                        // copy memory contents
                        LocalGet { local_index: DST },
                        LocalGet { local_index: SRC },
                        cast_to_heap_addr_type.clone(),
                        LocalGet { local_index: LEN },
                        cast_to_heap_addr_type,
                        MemoryCopy {
                            dst_mem: stable_memory_index,
                            src_mem: 0,
                        },
                        GlobalGet {
                            global_index: dirty_pages_counter_index,
                        },
                        LocalGet {
                            local_index: DIRTY_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Sub,
                        GlobalSet {
                            global_index: dirty_pages_counter_index,
                        },
                        GlobalGet {
                            global_index: accessed_pages_counter_index,
                        },
                        LocalGet {
                            local_index: ACCESSED_PAGE_COUNT,
                        },
                        I64ExtendI32U,
                        I64Sub,
                        GlobalSet {
                            global_index: accessed_pages_counter_index,
                        },
                    ],
                )
            }),
        ),
    ]
}
