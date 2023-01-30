use crate::wasm_utils::instrumentation::InjectedImports;
use crate::InternalErrorCode;
use ic_interfaces::execution_environment::StableMemoryApi;
use ic_sys::PAGE_SIZE;
use wasmparser::{BlockType, FuncType, Operator, Type, ValType};
use wasmtime_environ::WASM_PAGE_SIZE;

use super::{wasm_transform::Body, SystemApiFunc};

const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: i64 = 64 * 1024; // 4GiB

pub(super) fn replacement_functions(
    stable_memory_index: u32,
) -> Vec<(SystemApiFunc, (Type, Body<'static>))> {
    use Operator::*;
    let page_size_shift = PAGE_SIZE.trailing_zeros() as i32;
    let stable_memory_bytemap_index = stable_memory_index + 1;
    vec![
        (
            SystemApiFunc::StableSize,
            (
                Type::Func(FuncType::new([], [ValType::I32])),
                Body {
                    locals: vec![],
                    instructions: vec![
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
                        },
                        I32WrapI64,
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::Stable64Size,
            (
                Type::Func(FuncType::new([], [ValType::I64])),
                Body {
                    locals: vec![],
                    instructions: vec![
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
                        },
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::StableGrow,
            (
                Type::Func(FuncType::new([ValType::I32], [ValType::I32])),
                Body {
                    locals: vec![(1, ValType::I64)],
                    instructions: vec![
                        // Call try_grow_stable_memory API.
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
                        },
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        I32Const {
                            value: StableMemoryApi::Stable32 as i32,
                        },
                        Call {
                            function_index: InjectedImports::TryGrowStableMemory as u32,
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
                            mem_byte: 0, // This is ignored when serializing
                        },
                        LocalTee { local_index: 1 },
                        I64Const { value: -1 },
                        I64Eq,
                        // Grow failed and we need to deallocate pages and return -1.
                        If {
                            blockty: BlockType::Empty,
                        },
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        Call {
                            function_index: InjectedImports::DeallocatePages as u32,
                        },
                        I32Const { value: -1 },
                        Return,
                        End,
                        // Grow succeeded, return result of memory.grow.
                        LocalGet { local_index: 1 },
                        // We've already checked the resulting size is valid for 32-bit API when calling
                        // the try_grow_stable_memory API.
                        I32WrapI64,
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::Stable64Grow,
            (
                Type::Func(FuncType::new([ValType::I64], [ValType::I64])),
                Body {
                    locals: vec![(1, ValType::I64)],
                    instructions: vec![
                        // Call try_grow_stable_memory API.
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
                        },
                        LocalGet { local_index: 0 },
                        I32Const {
                            value: StableMemoryApi::Stable64 as i32,
                        },
                        Call {
                            function_index: InjectedImports::TryGrowStableMemory as u32,
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
                            mem_byte: 0, // This is ignored when serializing
                        },
                        LocalTee { local_index: 1 },
                        // Return the pages if grow failed.
                        I64Const { value: -1 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        LocalGet { local_index: 0 },
                        Call {
                            function_index: InjectedImports::DeallocatePages as u32,
                        },
                        I64Const { value: -1 },
                        Return,
                        End, // End check on memory.grow result.
                        // Return the result of memory.grow.
                        LocalGet { local_index: 1 },
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::StableRead,
            (
                Type::Func(FuncType::new(
                    [ValType::I32, ValType::I32, ValType::I32],
                    [],
                )),
                Body {
                    locals: vec![],
                    instructions: vec![
                        // If memory is too big for 32bit api, we trap
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // check bounds on stable memory (fail if src + size > mem_size)
                        LocalGet { local_index: 1 },
                        I64ExtendI32U,
                        LocalGet { local_index: 2 },
                        I64ExtendI32U,
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // perform the copy
                        LocalGet { local_index: 0 },
                        LocalGet { local_index: 1 },
                        I64ExtendI32U,
                        LocalGet { local_index: 2 },
                        MemoryCopy {
                            dst_mem: 0,
                            src_mem: stable_memory_index,
                        },
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::Stable64Read,
            (
                Type::Func(FuncType::new(
                    [ValType::I64, ValType::I64, ValType::I64],
                    [],
                )),
                Body {
                    locals: vec![],
                    instructions: vec![
                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return errors if addresses are out of bounds
                        // in this case
                        LocalGet { local_index: 2 },
                        I64Const { value: 0 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        // check bounds on stable memory (fail if dst + size > mem_size)
                        LocalGet { local_index: 1 },
                        LocalGet { local_index: 2 },
                        I64Add,
                        LocalGet { local_index: 1 },
                        // overflow (size != 0 because we checked earlier)
                        I64LeU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        LocalGet { local_index: 1 },
                        LocalGet { local_index: 2 },
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // check if these i64 hold valid i32 heap addresses
                        // check dst
                        LocalGet { local_index: 0 },
                        I64Const {
                            value: u32::MAX as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // check len
                        LocalGet { local_index: 2 },
                        I64Const {
                            value: u32::MAX as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // perform the copy
                        LocalGet { local_index: 0 },
                        I32WrapI64,
                        LocalGet { local_index: 1 },
                        LocalGet { local_index: 2 },
                        I32WrapI64,
                        MemoryCopy {
                            dst_mem: 0,
                            src_mem: stable_memory_index,
                        },
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::StableWrite,
            (
                Type::Func(FuncType::new(
                    [ValType::I32, ValType::I32, ValType::I32],
                    [],
                )),
                Body {
                    locals: vec![],
                    instructions: vec![
                        // If memory is too big for 32bit api, we trap
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // check bounds on stable memory (fail if dst + size > mem_size)
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        LocalGet { local_index: 2 },
                        I64ExtendI32U,
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // mark writes in the bytemap

                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return error if src address is out of bounds
                        // in this case
                        LocalGet { local_index: 2 },
                        I32Const { value: 0 },
                        I32Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        // dst
                        LocalGet { local_index: 0 },
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        // value to fill with
                        I32Const { value: 1 },
                        // calculate b_size
                        // b_end = (dst + size - 1) / PAGE_SIZE + 1
                        // b_len = b_end - b_start

                        // b_end
                        LocalGet { local_index: 0 },
                        LocalGet { local_index: 2 },
                        I32Add,
                        I32Const { value: 1 },
                        I32Sub,
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        I32Const { value: 1 },
                        I32Add,
                        // b_start
                        LocalGet { local_index: 0 },
                        I32Const {
                            value: page_size_shift,
                        },
                        I32ShrU,
                        // b_end - b_start
                        I32Sub,
                        MemoryFill {
                            mem: stable_memory_bytemap_index,
                        },
                        // copy memory contents
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        LocalGet { local_index: 1 },
                        LocalGet { local_index: 2 },
                        MemoryCopy {
                            dst_mem: stable_memory_index,
                            src_mem: 0,
                        },
                        End,
                    ],
                },
            ),
        ),
        (
            SystemApiFunc::Stable64Write,
            (
                Type::Func(FuncType::new(
                    [ValType::I64, ValType::I64, ValType::I64],
                    [],
                )),
                Body {
                    locals: vec![],
                    instructions: vec![
                        // if size is 0 we return
                        // (correctness of the code that follows depends on the size being > 0)
                        // note that we won't return errors if addresses are out of bounds
                        // in this case
                        LocalGet { local_index: 2 },
                        I64Const { value: 0 },
                        I64Eq,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Return,
                        End,
                        // check bounds on stable memory (fail if dst + size > mem_size)
                        LocalGet { local_index: 0 },
                        LocalGet { local_index: 2 },
                        I64Add,
                        LocalGet { local_index: 0 },
                        // overflow (size != 0 because we checked earlier)
                        I64LeU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::StableMemoryOutOfBounds as i32,
                        },
                        Call {
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        LocalGet { local_index: 0 },
                        LocalGet { local_index: 2 },
                        I64Add,
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
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
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // check if these i64 hold valid i32 heap addresses
                        // check src
                        LocalGet { local_index: 1 },
                        I64Const {
                            value: u32::MAX as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // check len
                        LocalGet { local_index: 2 },
                        I64Const {
                            value: u32::MAX as i64,
                        },
                        I64GtU,
                        If {
                            blockty: BlockType::Empty,
                        },
                        I32Const {
                            value: InternalErrorCode::HeapOutOfBounds as i32,
                        },
                        Call {
                            function_index: InjectedImports::InternalTrap as u32,
                        },
                        End,
                        // dst
                        LocalGet { local_index: 0 },
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        I32WrapI64,
                        // value to fill with
                        I32Const { value: 1 },
                        // calculate b_size
                        // b_end = (dst + size - 1) / PAGE_SIZE + 1
                        // b_len = b_end - b_start

                        // b_end
                        LocalGet { local_index: 0 },
                        LocalGet { local_index: 2 },
                        I64Add,
                        I64Const { value: 1 },
                        I64Sub,
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        I64Const { value: 1 },
                        I64Add,
                        // b_start
                        LocalGet { local_index: 0 },
                        I64Const {
                            value: page_size_shift as i64,
                        },
                        I64ShrU,
                        // b_end - b_start
                        I64Sub,
                        I32WrapI64,
                        MemoryFill {
                            mem: stable_memory_bytemap_index,
                        },
                        // copy memory contents
                        LocalGet { local_index: 0 },
                        LocalGet { local_index: 1 },
                        I32WrapI64,
                        LocalGet { local_index: 2 },
                        I32WrapI64,
                        MemoryCopy {
                            dst_mem: stable_memory_index,
                            src_mem: 0,
                        },
                        End,
                    ],
                },
            ),
        ),
    ]
}
