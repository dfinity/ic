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
                            blockty: BlockType::Type(ValType::I32),
                        },
                        Unreachable,
                        Else,
                        MemorySize {
                            mem: stable_memory_index,
                            mem_byte: 0, // This is ignored when serializing
                        },
                        I32WrapI64,
                        End,
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
                            blockty: BlockType::Type(ValType::I32),
                        },
                        I32Const { value: -1 },
                        // If successful, do the actual grow.
                        Else,
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
                            blockty: BlockType::Type(ValType::I32),
                        },
                        LocalGet { local_index: 0 },
                        I64ExtendI32U,
                        Call {
                            function_index: deallocate_pages_func,
                        },
                        I32Const { value: -1 },
                        // Grow succeeded, return result of memory.grow.
                        Else,
                        LocalGet { local_index: 1 },
                        // We've already checked the resulting size is valid for 32-bit API when calling
                        // the try_grow_stable_memory API.
                        I32WrapI64,
                        End, // End check on memory.grow.
                        End, // End check on try_grow_stable_memory.
                        End, // End function.
                    ],
                },
            ),
        ),
        // TODO: Handle 64-bit versions of the APIs.
    ]
}
