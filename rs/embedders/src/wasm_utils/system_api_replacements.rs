use ic_interfaces::execution_environment::StableMemoryApi;
use wasmparser::{BlockType, FuncType, Operator, Type, ValType};

use super::{wasm_transform::Body, SystemApiFunc};

const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: i64 = 64 * 1024; // 4GiB

pub(super) fn replacement_functions(
    stable_memory_index: u32,
    try_grow_stable_memory_func: u32,
    deallocate_pages_func: u32,
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
                        Unreachable,
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
                            function_index: try_grow_stable_memory_func,
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
                            function_index: deallocate_pages_func,
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
                            function_index: try_grow_stable_memory_func,
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
                            function_index: deallocate_pages_func,
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
    ]
}
