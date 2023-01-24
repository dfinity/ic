use crate::wasm_utils::instrumentation::InjectedImports;
use crate::InternalErrorCode;
use ic_interfaces::execution_environment::StableMemoryApi;
use wasmparser::{BlockType, FuncType, Operator, Type, ValType};

use super::{wasm_transform::Body, SystemApiFunc};

const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: i64 = 64 * 1024; // 4GiB

pub(super) fn replacement_functions(
    stable_memory_index: u32,
) -> Vec<(SystemApiFunc, (Type, Body<'static>))> {
    use Operator::*;
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
