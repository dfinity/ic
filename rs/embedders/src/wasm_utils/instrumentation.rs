//! This module is responsible for instrumenting wasm binaries on the Internet
//! Computer.
//!
//! Supports 64-bit main memory by using `wasm64`.
//!
//! It exports the function [`instrument`] which takes a Wasm binary and
//! injects some instrumentation that allows to:
//!  * Quantify the amount of execution every function of that module conducts.
//!    This quantity is approximated by the sum of cost of instructions executed
//!    on the taken execution path.
//!  * Verify that no successful `memory.grow` results in exceeding the
//!    available memory allocated to the canister.
//!
//! Moreover, it exports the function referred to by the `start` section under
//! the name `canister_start` and removes the section. (This is needed so that
//! we can run the initialization after we have set the instructions counter to
//! some value).
//!
//! After instrumentation any function of that module will only be able to
//! execute as long as at every reentrant basic block of its execution path, the
//! counter is verified to be above zero. Otherwise, the function will trap (via
//! calling a special system API call). If the function returns before the
//! counter overflows, the value of the counter is the initial value minus the
//! sum of cost of all executed instructions.
//!
//! In more details, first, it inserts up to five System API functions:
//!
//! ```wasm
//! (import "__" "out_of_instructions" (func (;0;) (func)))
//! (import "__" "update_available_memory" (func (;1;) ((param i32 i32 i32) (result i32))))
//! (import "__" "update_available_memory_64" (func (;1;) ((param i64 i64 i32) (result i64))))
//! (import "__" "try_grow_stable_memory" (func (;1;) ((param i64 i64 i32) (result i64))))
//! (import "__" "internal_trap" (func (;1;) ((param i32))))
//! (import "__" "stable_read_first_access" (func ((param i64) (param i64) (param i64))))
//! ```
//! Where the last three will only be inserted if Wasm-native stable memory is enabled.
//!
//! It then inserts (and exports) a global mutable counter:
//! ```wasm
//! (global (;0;) (mut i64) (i64.const 0))
//! (export "canister counter_instructions" (global 0)))
//! ```
//!
//! An additional function is also inserted to handle updates to the instruction
//! counter for bulk memory instructions whose cost can only be determined at
//! runtime:
//!
//! ```wasm
//! (func (;5;) (type 4) (param i32) (result i32)
//!   global.get 0
//!   local.get 0
//!   i64.extend_i32_u
//!   i64.sub
//!   global.set 0
//!   global.get 0
//!   i64.const 0
//!   i64.lt_s
//!   if  ;; label = @1
//!     call 0           # the `out_of_instructions` function
//!   end
//!   local.get 0)
//! ```
//!
//! The `counter_instructions` global should be set before the execution of
//! canister code. After execution the global can be read to determine the
//! number of instructions used.
//!
//! Moreover, it injects a decrementation of the instructions counter (by the
//! sum of cost of all instructions inside this block) at the beginning of every
//! non-reentrant block:
//!
//! ```wasm
//! global.get 0
//! i64.const 2
//! i64.sub
//! global.set 0
//! ```
//!
//! and a decrementation with a counter overflow check at the beginning of every
//! reentrant block (a function or a loop body):
//!
//! ```wasm
//! global.get 0
//! i64.const 8
//! i64.sub
//! global.set 0
//! global.get 0
//! i64.const 0
//! i64.lt_s
//! if  ;; label = @1
//!   (call x)
//! end
//! ```
//!
//! Before every bulk memory operation, a call is made to the function which
//! will decrement the instruction counter by the "size" argument of the bulk
//! memory instruction.
//!
//! Note that we omit checking for the counter overflow at the non-reentrant
//! blocks to optimize for performance. The maximal overflow in that case is
//! bound by the length of the longest execution path consisting of
//! non-reentrant basic blocks.
//!
//! # Wasm-native stable memory
//!
//! Two additional memories are inserted for stable memory. One is the actual
//! stable memory and the other is a bytemap to track dirty pages in the stable
//! memory.
//! Index of stable memory bytemap = index of stable memory + 1
//! ```wasm
//! (memory (export "stable_memory") i64 (i64.const 0) (i64.const MAX_STABLE_MEMORY_SIZE))
//! (memory (export "stable_memory_bytemap") i32 (i64.const STABLE_BYTEMAP_SIZE) (i64.const STABLE_BYTEMAP_SIZE))
//! ```
//!

use super::system_api_replacements::replacement_functions;
use super::validation::API_VERSION_IC0;
use super::{InstrumentationOutput, Segments, SystemApiFunc};
use ic_config::embedders::MeteringType;
use ic_config::flag_status::FlagStatus;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NumWasmPages;
use ic_sys::PAGE_SIZE;
use ic_types::{methods::WasmMethod, MAX_WASM_MEMORY_IN_BYTES};
use ic_types::{NumInstructions, MAX_STABLE_MEMORY_IN_BYTES};
use ic_wasm_types::{BinaryEncodedWasm, WasmError, WasmInstrumentationError};
use wasmtime_environ::WASM_PAGE_SIZE;

use crate::wasm_utils::wasm_transform::{self, Global, Module};
use crate::wasmtime_embedder::{
    STABLE_BYTEMAP_MEMORY_NAME, STABLE_MEMORY_NAME, WASM_HEAP_BYTEMAP_MEMORY_NAME,
    WASM_HEAP_MEMORY_NAME,
};
use wasmparser::{
    BlockType, Export, ExternalKind, FuncType, GlobalType, Import, MemoryType, Operator,
    StructuralType, SubType, TypeRef, ValType,
};

use std::collections::BTreeMap;
use std::convert::TryFrom;

// The indicies of injected function imports.
pub(crate) enum InjectedImports {
    OutOfInstructions = 0,
    UpdateAvailableMemory = 1,
    // Optional native stable memory functions
    TryGrowStableMemory = 2,
    InternalTrap = 3,
    StableReadFirstAccess = 4,
    // Optional 64-bit main memory support functions
    MainReadPageGuard,
    MainWritePageGuard,
    MainBulkAccessGuard,
}

impl InjectedImports {
    const BASIC_FUNCTIONS_COUNT: usize = 2;
    const OPTIONAL_STABLE_FUNCTIONS_COUNT: usize = 3;
    const OPTIONAL_MEMORY64_FUNCTIONS_COUNT: usize = 3;

    fn count(main_memory_mode: MemoryMode, wasm_native_stable_memory: FlagStatus) -> usize {
        let mut count = Self::BASIC_FUNCTIONS_COUNT;
        if wasm_native_stable_memory == FlagStatus::Enabled {
            count += Self::OPTIONAL_STABLE_FUNCTIONS_COUNT;
        }
        if main_memory_mode == MemoryMode::Memory64 {
            count += Self::OPTIONAL_MEMORY64_FUNCTIONS_COUNT;
        }
        count
    }

    fn get_index(
        &self,
        main_memory_mode: MemoryMode,
        wasm_native_stable_memory: FlagStatus,
    ) -> usize {
        let optional_stable_functions_count = if wasm_native_stable_memory == FlagStatus::Enabled {
            Self::OPTIONAL_STABLE_FUNCTIONS_COUNT
        } else {
            0
        };
        let functions_count_base = Self::BASIC_FUNCTIONS_COUNT + optional_stable_functions_count;
        match self {
            InjectedImports::MainReadPageGuard => {
                assert!(main_memory_mode == MemoryMode::Memory64);
                functions_count_base
            }
            InjectedImports::MainWritePageGuard => {
                assert!(main_memory_mode == MemoryMode::Memory64);
                functions_count_base + 1
            }
            InjectedImports::MainBulkAccessGuard => {
                assert!(main_memory_mode == MemoryMode::Memory64);
                functions_count_base + 2
            }
            _ => unimplemented!(),
        }
    }
}

// Gets the cost of an instruction.
pub fn instruction_to_cost(i: &Operator) -> u64 {
    match i {
        // The following instructions are mostly signaling the start/end of code blocks,
        // so we assign 0 cost to them.
        Operator::Block { .. } => 0,
        Operator::Else => 0,
        Operator::End => 0,
        Operator::Loop { .. } => 0,

        // Default cost of an instruction is 1.
        _ => 1,
    }
}

// Gets the cost of an instruction.
pub fn instruction_to_cost_new(i: &Operator) -> u64 {
    // This aims to be a complete list of all instructions that can be executed, with certain exceptions.
    // The exceptions are: SIMD instructions, atomic instructions, and the dynamic cost of
    // of operations such as table/memory fill, copy, init. This
    // dynamic cost is treated separately. Here we only assign a static cost to these instructions.
    match i {
        // The following instructions are mostly signaling the start/end of code blocks,
        // so we assign 0 cost to them.
        Operator::Block { .. } => 0,
        Operator::Else => 0,
        Operator::End => 0,
        Operator::Loop { .. } => 0,

        // The following instructions generate register/immediate code most of the time,
        // so we assign 1 cost to them because these are not very costly to execute,
        // they simply take out resources (registers or instr cache).
        Operator::I32Const { .. }
        | Operator::I64Const { .. }
        | Operator::F32Const { .. }
        | Operator::F64Const { .. } => 1,

        // All integer arithmetic instructions (32 bit and 64 bit) are of cost 1 with the
        // exception of division and remainder instructions, which are of cost 10. Validated
        // in benchmarks.
        Operator::I32Add { .. }
        | Operator::I32Sub { .. }
        | Operator::I32Mul { .. }
        | Operator::I32And { .. }
        | Operator::I32Or { .. }
        | Operator::I32Xor { .. }
        | Operator::I32Shl { .. }
        | Operator::I32ShrS { .. }
        | Operator::I32ShrU { .. }
        | Operator::I32Rotl { .. }
        | Operator::I32Rotr { .. }
        | Operator::I64Add { .. }
        | Operator::I64Sub { .. }
        | Operator::I64Mul { .. }
        | Operator::I64And { .. }
        | Operator::I64Or { .. }
        | Operator::I64Xor { .. }
        | Operator::I64Shl { .. }
        | Operator::I64ShrS { .. }
        | Operator::I64ShrU { .. }
        | Operator::I64Rotl { .. }
        | Operator::I64Rotr { .. } => 1,

        Operator::I32DivS { .. }
        | Operator::I32DivU { .. }
        | Operator::I32RemS { .. }
        | Operator::I32RemU { .. }
        | Operator::I64DivS { .. }
        | Operator::I64DivU { .. }
        | Operator::I64RemS { .. }
        | Operator::I64RemU { .. } => 10,

        // All integer (32 and 64 bit) comparison operations are of cost 1.
        // That is because they boil down to simple arithmetic operations, which are also
        // of cost 1. Validated in Benchmarks.
        Operator::I32Eqz { .. }
        | Operator::I32Eq { .. }
        | Operator::I32Ne { .. }
        | Operator::I32LtS { .. }
        | Operator::I32LtU { .. }
        | Operator::I32GtS { .. }
        | Operator::I32GtU { .. }
        | Operator::I32LeS { .. }
        | Operator::I32LeU { .. }
        | Operator::I32GeS { .. }
        | Operator::I32GeU { .. }
        | Operator::I64Eqz { .. }
        | Operator::I64Eq { .. }
        | Operator::I64Ne { .. }
        | Operator::I64LtS { .. }
        | Operator::I64LtU { .. }
        | Operator::I64GtS { .. }
        | Operator::I64GtU { .. }
        | Operator::I64LeS { .. }
        | Operator::I64LeU { .. }
        | Operator::I64GeS { .. }
        | Operator::I64GeU { .. } => 1,

        // All floating point instructions (32 and 64 bit) are of cost 50 because they are expensive CPU operations.
        //The exception is neg, abs, and copysign, which are cost 2, as they are more efficient.
        // Comparing floats is cost 1. Validated in Benchmarks.
        // The cost is adjusted to 20 after benchmarking with real canisters.
        Operator::F32Add { .. }
        | Operator::F32Sub { .. }
        | Operator::F32Mul { .. }
        | Operator::F32Div { .. }
        | Operator::F32Min { .. }
        | Operator::F32Max { .. }
        | Operator::F32Ceil { .. }
        | Operator::F32Floor { .. }
        | Operator::F32Trunc { .. }
        | Operator::F32Nearest { .. }
        | Operator::F32Sqrt { .. }
        | Operator::F64Add { .. }
        | Operator::F64Sub { .. }
        | Operator::F64Mul { .. }
        | Operator::F64Div { .. }
        | Operator::F64Min { .. }
        | Operator::F64Max { .. }
        | Operator::F64Ceil { .. }
        | Operator::F64Floor { .. }
        | Operator::F64Trunc { .. }
        | Operator::F64Nearest { .. }
        | Operator::F64Sqrt { .. } => 20,

        Operator::F32Abs { .. }
        | Operator::F32Neg { .. }
        | Operator::F32Copysign { .. }
        | Operator::F64Abs { .. }
        | Operator::F64Neg { .. }
        | Operator::F64Copysign { .. } => 2,

        // Comparison operations for floats are of cost 3 because they are usually implemented
        // as arithmetic operations on integers (the individual components, sign, exp, mantissa,
        // see https://en.wikipedia.org/wiki/Floating-point_arithmetic#Comparison).
        // Validated in benchmarks.
        Operator::F32Eq { .. }
        | Operator::F32Ne { .. }
        | Operator::F32Lt { .. }
        | Operator::F32Gt { .. }
        | Operator::F32Le { .. }
        | Operator::F32Ge { .. }
        | Operator::F64Eq { .. }
        | Operator::F64Ne { .. }
        | Operator::F64Lt { .. }
        | Operator::F64Gt { .. }
        | Operator::F64Le { .. }
        | Operator::F64Ge { .. } => 3,

        // All Extend instructions are of cost 1.
        Operator::I32WrapI64 { .. }
        | Operator::I32Extend8S { .. }
        | Operator::I32Extend16S { .. }
        | Operator::I64Extend8S { .. }
        | Operator::I64Extend16S { .. }
        | Operator::I64Extend32S { .. }
        | Operator::F64ReinterpretI64 { .. }
        | Operator::I64ReinterpretF64 { .. }
        | Operator::I32ReinterpretF32 { .. }
        | Operator::F32ReinterpretI32 { .. }
        | Operator::I64ExtendI32S { .. }
        | Operator::I64ExtendI32U { .. } => 1,

        // Convert to signed is cheaper than converting to unsigned, validated in benchmarks.
        Operator::F32ConvertI32S { .. }
        | Operator::F64ConvertI64S { .. }
        | Operator::F32ConvertI64S { .. }
        | Operator::F64ConvertI32S { .. } => 3,

        Operator::F64ConvertI32U { .. }
        | Operator::F32ConvertI64U { .. }
        | Operator::F32ConvertI32U { .. }
        | Operator::F64ConvertI64U { .. } => 16,

        // TruncSat ops are expensive because of floating point manipulation. Cost is 50,
        // validated in benchmarks.
        // The cost is adjusted to 20 after benchmarking with real canisters.
        Operator::I64TruncSatF32S { .. }
        | Operator::I64TruncSatF32U { .. }
        | Operator::I64TruncSatF64S { .. }
        | Operator::I64TruncSatF64U { .. }
        | Operator::I32TruncSatF32S { .. }
        | Operator::I32TruncSatF32U { .. }
        | Operator::I32TruncSatF64S { .. }
        | Operator::I32TruncSatF64U { .. } => 20,

        // Promote and demote are of cost 1.
        Operator::F32DemoteF64 { .. } | Operator::F64PromoteF32 { .. } => 1,

        // Trunc ops are expensive because of floating point manipulation. Cost is 30, validated in benchmarks.
        // The cost is adjusted to 20 after benchmarking with real canisters.
        Operator::I32TruncF32S { .. }
        | Operator::I32TruncF32U { .. }
        | Operator::I32TruncF64S { .. }
        | Operator::I32TruncF64U { .. }
        | Operator::I64TruncF32S { .. }
        | Operator::I64TruncF32U { .. }
        | Operator::I64TruncF64S { .. }
        | Operator::I64TruncF64U { .. } => 20,

        // All load/store instructions are of cost 2.
        // Validated in benchmarks.
        // The cost is adjusted to 1 after benchmarking with real canisters.
        Operator::I32Load { .. }
        | Operator::I64Load { .. }
        | Operator::F32Load { .. }
        | Operator::F64Load { .. }
        | Operator::I32Load8S { .. }
        | Operator::I32Load8U { .. }
        | Operator::I32Load16S { .. }
        | Operator::I32Load16U { .. }
        | Operator::I64Load8S { .. }
        | Operator::I64Load8U { .. }
        | Operator::I64Load16S { .. }
        | Operator::I64Load16U { .. }
        | Operator::I64Load32S { .. }
        | Operator::I64Load32U { .. }
        | Operator::I32Store { .. }
        | Operator::I64Store { .. }
        | Operator::F32Store { .. }
        | Operator::F64Store { .. }
        | Operator::I32Store8 { .. }
        | Operator::I32Store16 { .. }
        | Operator::I64Store8 { .. }
        | Operator::I64Store16 { .. }
        | Operator::I64Store32 { .. } => 1,

        // Global get/set operations are similarly expensive to loads/stores.
        Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => 2,

        // TableGet and TableSet are expensive operations because they
        // are translated into memory manipulation oprations.
        // Results based on benchmarks.
        Operator::TableGet { .. } => 5,
        Operator::TableSet { .. } => 5,

        // LocalGet and LocalSet, LocalTee and Select are of cost 1.
        // In principle, they should be equivalent to load/store (cost 2), but they perform load/store
        // from the stack, which is "nearby" memory, which is likely to be in the cache.
        Operator::LocalGet { .. }
        | Operator::LocalSet { .. }
        | Operator::LocalTee { .. }
        | Operator::Select { .. } => 1,

        // Memory Grow and Table Grow Size expensive operations because they call
        // into the system, hence their cost is 300. Memory Size and Table Size are
        // cheaper, their cost is 20. Results validated in benchmarks.
        Operator::TableGrow { .. } | Operator::MemoryGrow { .. } => 300,
        Operator::TableSize { .. } | Operator::MemorySize { .. } => 20,

        // Bulk memory ops are of cost 100. They are heavy operations because
        // they are translated into function calls in the x86 dissasembly. Validated
        // in benchmarks.
        Operator::MemoryFill { .. }
        | Operator::MemoryCopy { .. }
        | Operator::TableFill { .. }
        | Operator::TableCopy { .. }
        | Operator::MemoryInit { .. }
        | Operator::TableInit { .. } => 100,

        // Data and Elem drop are of cost 300.
        Operator::DataDrop { .. } | Operator::ElemDrop { .. } => 300,

        // Call instructions are of cost 20. Validated in benchmarks.
        // The cost is adjusted to 10 after benchmarking with real canisters.
        Operator::Call { .. }
        | Operator::CallIndirect { .. }
        | Operator::ReturnCall { .. }
        | Operator::ReturnCallIndirect { .. } => 10,

        // Return, drop, unreachable and nop instructions are of cost 1.
        Operator::Return { .. } | Operator::Drop | Operator::Unreachable | Operator::Nop => 1,

        // Branching instructions should be of cost 2.
        Operator::If { .. }
        | Operator::Br { .. }
        | Operator::BrIf { .. }
        | Operator::BrTable { .. } => 2,

        // Popcnt and Clz instructions are cost 1. Validated in benchmarks.
        Operator::I32Popcnt { .. }
        | Operator::I64Popcnt { .. }
        | Operator::I32Clz { .. }
        | Operator::I32Ctz { .. }
        | Operator::I64Clz { .. }
        | Operator::I64Ctz { .. } => 1,

        // Null references are cheap, validated in benchmarks.
        Operator::RefNull { .. } => 1,
        // Checking for null references is the same as branching
        //but with an added complexity of memory manipulation. Validated in benchmarks.
        Operator::RefIsNull { .. } => 5,
        // Function pointers are heavy because they get
        // translated to memory manipulation. Validated in benchmarks.
        Operator::RefFunc { .. } => 130,

        // Default cost of an instruction is 1.
        _ => 1,
    }
}

const INSTRUMENTED_FUN_MODULE: &str = "__";
const OUT_OF_INSTRUCTIONS_FUN_NAME: &str = "out_of_instructions";
const UPDATE_MEMORY_FUN_NAME: &str = "update_available_memory";
const UPDATE_MEMORY_64_FUN_NAME: &str = "update_available_memory_64";
const TRY_GROW_STABLE_MEMORY_FUN_NAME: &str = "try_grow_stable_memory";
const INTERNAL_TRAP_FUN_NAME: &str = "internal_trap";
const STABLE_READ_FIRST_ACCESS_NAME: &str = "stable_read_first_access";
const MAIN_READ_PAGE_GUARD_NAME: &str = "main_read_page_guard";
const MAIN_WRITE_PAGE_GUARD_NAME: &str = "main_write_page_guard";
const MAIN_BULK_ACCESS_GUARD_NAME: &str = "main_bulk_access_guard";
const TABLE_STR: &str = "table";
pub(crate) const INSTRUCTIONS_COUNTER_GLOBAL_NAME: &str = "canister counter_instructions";
pub(crate) const DIRTY_PAGES_COUNTER_GLOBAL_NAME: &str = "canister counter_dirty_pages";
pub(crate) const STABLE_ACCESSED_PAGES_COUNTER_GLOBAL_NAME: &str =
    "canister counter_accessed_pages";
pub(crate) const MAIN_ACCESSED_PAGES_COUNTER_GLOBAL_NAME: &str =
    "canister accessed_main_memory_pages";
const CANISTER_START_STR: &str = "canister_start";

/// There is one byte for each OS page in the wasm heap.
const BYTEMAP_SIZE_IN_WASM_PAGES: u64 =
    MAX_WASM_MEMORY_IN_BYTES / (PAGE_SIZE as u64) / (WASM_PAGE_SIZE as u64);

const MAX_STABLE_MEMORY_IN_WASM_PAGES: u64 = MAX_STABLE_MEMORY_IN_BYTES / (WASM_PAGE_SIZE as u64);
/// There is one byte for each OS page in the stable memory.
const STABLE_BYTEMAP_SIZE_IN_WASM_PAGES: u64 = MAX_STABLE_MEMORY_IN_WASM_PAGES / (PAGE_SIZE as u64);

fn add_func_type(module: &mut Module, ty: FuncType) -> u32 {
    for (idx, existing_subtype) in module.types.iter().enumerate() {
        if let StructuralType::Func(existing_ty) = &existing_subtype.structural_type {
            if *existing_ty == ty {
                return idx as u32;
            }
        }
    }
    module.types.push(SubType {
        is_final: false,
        supertype_idx: None,
        structural_type: StructuralType::Func(ty),
    });
    (module.types.len() - 1) as u32
}

fn mutate_function_indices(module: &mut Module, f: impl Fn(u32) -> u32) {
    fn mutate_instructions(f: &impl Fn(u32) -> u32, ops: &mut [Operator]) {
        for op in ops {
            match op {
                Operator::Call { function_index }
                | Operator::ReturnCall { function_index }
                | Operator::RefFunc { function_index } => {
                    *function_index = f(*function_index);
                }
                _ => {}
            }
        }
    }

    for func_body in &mut module.code_sections {
        mutate_instructions(&f, &mut func_body.instructions)
    }

    for exp in &mut module.exports {
        if let ExternalKind::Func = exp.kind {
            exp.index = f(exp.index);
        }
    }

    for (_, elem_items) in &mut module.elements {
        match elem_items {
            wasm_transform::ElementItems::Functions(fun_items) => {
                for idx in fun_items {
                    *idx = f(*idx);
                }
            }
            wasm_transform::ElementItems::ConstExprs { ty: _, exprs } => {
                for ops in exprs {
                    mutate_instructions(&f, ops)
                }
            }
        }
    }

    for global in &mut module.globals {
        mutate_instructions(&f, &mut global.init_expr)
    }

    for data_segment in &mut module.data {
        match &mut data_segment.kind {
            wasm_transform::DataSegmentKind::Passive => {}
            wasm_transform::DataSegmentKind::Active {
                memory_index: _,
                offset_expr,
            } => {
                let mut temp = [offset_expr.clone()];
                mutate_instructions(&f, &mut temp);
                *offset_expr = temp.into_iter().next().unwrap();
            }
        }
    }

    if let Some(start_idx) = module.start.as_mut() {
        *start_idx = f(*start_idx);
    }
}

/// Injects hidden api functions.
///
/// Note that these functions are injected as the first imports, so that we
/// can increment all function indices unconditionally. (If they would be
/// added as the last imports, we'd need to increment only non imported
/// functions, since imported functions precede all others in the function index
/// space, but this would be error-prone).
fn inject_helper_functions(
    mut module: Module,
    wasm_native_stable_memory: FlagStatus,
    main_memory_mode: MemoryMode,
) -> Module {
    // insert types
    let ooi_type = FuncType::new([], []);
    let uam_type = match main_memory_mode {
        MemoryMode::Memory32 => {
            FuncType::new([ValType::I32, ValType::I32, ValType::I32], [ValType::I32])
        }
        MemoryMode::Memory64 => {
            FuncType::new([ValType::I64, ValType::I64, ValType::I32], [ValType::I64])
        }
    };

    let ooi_type_idx = add_func_type(&mut module, ooi_type);
    let uam_type_idx = add_func_type(&mut module, uam_type);

    // push_front imports
    let ooi_imp = Import {
        module: INSTRUMENTED_FUN_MODULE,
        name: OUT_OF_INSTRUCTIONS_FUN_NAME,
        ty: TypeRef::Func(ooi_type_idx),
    };

    let uam_name = match main_memory_mode {
        MemoryMode::Memory32 => UPDATE_MEMORY_FUN_NAME,
        MemoryMode::Memory64 => UPDATE_MEMORY_64_FUN_NAME,
    };
    let uam_imp = Import {
        module: INSTRUMENTED_FUN_MODULE,
        name: uam_name,
        ty: TypeRef::Func(uam_type_idx),
    };

    let mut old_imports = module.imports;
    module.imports = Vec::with_capacity(
        old_imports.len() + InjectedImports::count(main_memory_mode, wasm_native_stable_memory),
    );
    module.imports.push(ooi_imp);
    module.imports.push(uam_imp);

    if wasm_native_stable_memory == FlagStatus::Enabled {
        let tgsm_type = FuncType::new([ValType::I64, ValType::I64, ValType::I32], [ValType::I64]);
        let tgsm_type_idx = add_func_type(&mut module, tgsm_type);
        let tgsm_imp = Import {
            module: INSTRUMENTED_FUN_MODULE,
            name: TRY_GROW_STABLE_MEMORY_FUN_NAME,
            ty: TypeRef::Func(tgsm_type_idx),
        };
        module.imports.push(tgsm_imp);

        let it_type = FuncType::new([ValType::I32], []);
        let it_type_idx = add_func_type(&mut module, it_type);
        let it_imp = Import {
            module: INSTRUMENTED_FUN_MODULE,
            name: INTERNAL_TRAP_FUN_NAME,
            ty: TypeRef::Func(it_type_idx),
        };
        module.imports.push(it_imp);

        let fr_type = FuncType::new([ValType::I64, ValType::I64, ValType::I64], []);
        let fr_type_idx = add_func_type(&mut module, fr_type);
        let fr_imp = Import {
            module: INSTRUMENTED_FUN_MODULE,
            name: STABLE_READ_FIRST_ACCESS_NAME,
            ty: TypeRef::Func(fr_type_idx),
        };
        module.imports.push(fr_imp);
    }

    if main_memory_mode == MemoryMode::Memory64 {
        let page_guard_type = FuncType::new([ValType::I32], []);

        let read_page_guard_index = add_func_type(&mut module, page_guard_type.clone());
        let read_page_guard_import = Import {
            module: INSTRUMENTED_FUN_MODULE,
            name: MAIN_READ_PAGE_GUARD_NAME,
            ty: TypeRef::Func(read_page_guard_index),
        };
        module.imports.push(read_page_guard_import);

        let write_page_guard_index = add_func_type(&mut module, page_guard_type);
        let write_page_guard_import = Import {
            module: INSTRUMENTED_FUN_MODULE,
            name: MAIN_WRITE_PAGE_GUARD_NAME,
            ty: TypeRef::Func(write_page_guard_index),
        };
        module.imports.push(write_page_guard_import);

        let bulk_access_guard_type = FuncType::new([ValType::I64, ValType::I64, ValType::I32], []);
        let bulk_access_guard_index = add_func_type(&mut module, bulk_access_guard_type);
        let bulk_access_guard_import = Import {
            module: INSTRUMENTED_FUN_MODULE,
            name: MAIN_BULK_ACCESS_GUARD_NAME,
            ty: TypeRef::Func(bulk_access_guard_index),
        };
        module.imports.push(bulk_access_guard_import);
    }

    module.imports.append(&mut old_imports);

    // now increment all function references by InjectedImports::Count
    let cnt = InjectedImports::count(main_memory_mode, wasm_native_stable_memory) as u32;
    mutate_function_indices(&mut module, |i| i + cnt);

    debug_assert!(
        module.imports[InjectedImports::OutOfInstructions as usize].name == "out_of_instructions"
    );
    debug_assert!(
        module.imports[InjectedImports::UpdateAvailableMemory as usize].name
            == "update_available_memory"
            || module.imports[InjectedImports::UpdateAvailableMemory as usize].name
                == "update_available_memory_64"
    );
    if wasm_native_stable_memory == FlagStatus::Enabled {
        debug_assert!(
            module.imports[InjectedImports::TryGrowStableMemory as usize].name
                == "try_grow_stable_memory"
        );
        debug_assert!(
            module.imports[InjectedImports::InternalTrap as usize].name == "internal_trap"
        );
        debug_assert!(
            module.imports[InjectedImports::StableReadFirstAccess as usize].name
                == "stable_read_first_access"
        );
    }
    if main_memory_mode == MemoryMode::Memory64 {
        debug_assert_eq!(
            module.imports[InjectedImports::MainReadPageGuard
                .get_index(main_memory_mode, wasm_native_stable_memory)]
            .name,
            "main_read_page_guard"
        );
        debug_assert_eq!(
            module.imports[InjectedImports::MainWritePageGuard
                .get_index(main_memory_mode, wasm_native_stable_memory)]
            .name,
            "main_write_page_guard"
        );
        debug_assert_eq!(
            module.imports[InjectedImports::MainBulkAccessGuard
                .get_index(main_memory_mode, wasm_native_stable_memory)]
            .name,
            "main_bulk_access_guard"
        )
    }

    module
}

/// Indices of functions, globals, etc that will be need in the later parts of
/// instrumentation.
#[derive(Default)]
pub(super) struct SpecialIndices {
    pub instructions_counter_ix: u32,
    pub dirty_pages_counter_ix: Option<u32>,
    pub stable_accessed_pages_counter_ix: Option<u32>,
    pub main_accessed_pages_counter_ix: Option<u32>,
    pub decr_instruction_counter_fn: u32,
    pub count_clean_pages_fn: Option<u32>,
    pub start_fn_ix: Option<u32>,
    pub stable_memory_index: u32,
}

// Address space used in a Wasm memory.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum MemoryMode {
    Memory32,
    Memory64,
}

impl MemoryMode {
    pub fn get(module: &Module<'_>) -> MemoryMode {
        if module.memories.iter().any(|memory| memory.memory64) {
            MemoryMode::Memory64
        } else {
            MemoryMode::Memory32
        }
    }
}

/// Takes a Wasm binary and inserts the instructions metering and memory grow
/// instrumentation.
///
/// Returns an [`InstrumentationOutput`] or an error if the input binary could
/// not be instrumented.
pub(super) fn instrument(
    module: Module<'_>,
    cost_to_compile_wasm_instruction: NumInstructions,
    write_barrier: FlagStatus,
    wasm_native_stable_memory: FlagStatus,
    metering_type: MeteringType,
    subnet_type: SubnetType,
    dirty_page_overhead: NumInstructions,
) -> Result<InstrumentationOutput, WasmInstrumentationError> {
    let stable_memory_index;
    let main_memory_mode = MemoryMode::get(&module);
    let mut module = inject_helper_functions(module, wasm_native_stable_memory, main_memory_mode);
    module = export_table(module);
    (module, stable_memory_index) = update_memories(
        module,
        write_barrier,
        wasm_native_stable_memory,
        main_memory_mode,
    );

    let mut extra_strs: Vec<String> = Vec::new();
    module = export_mutable_globals(module, &mut extra_strs);

    let mut num_imported_functions = 0;
    let mut num_imported_globals = 0;
    for imp in &module.imports {
        match imp.ty {
            TypeRef::Func(_) => {
                num_imported_functions += 1;
            }
            TypeRef::Global(_) => {
                num_imported_globals += 1;
            }
            _ => (),
        }
    }

    let mut num_functions = (module.functions.len() + num_imported_functions) as u32;
    let mut num_globals = (module.globals.len() + num_imported_globals) as u32;

    let instructions_counter_ix = num_globals;
    num_globals += 1;
    let decr_instruction_counter_fn = num_functions;
    num_functions += 1;

    let dirty_pages_counter_ix;
    let stable_accessed_pages_counter_ix;
    let count_clean_pages_fn;
    match wasm_native_stable_memory {
        FlagStatus::Enabled => {
            dirty_pages_counter_ix = Some(num_globals);
            stable_accessed_pages_counter_ix = Some(num_globals + 1);
            num_globals += 2;
            count_clean_pages_fn = Some(num_functions);
            // num_functions += 1;
        }
        FlagStatus::Disabled => {
            dirty_pages_counter_ix = None;
            stable_accessed_pages_counter_ix = None;
            count_clean_pages_fn = None;
        }
    };

    let main_accessed_pages_counter_ix;
    match main_memory_mode {
        MemoryMode::Memory64 => {
            main_accessed_pages_counter_ix = Some(num_globals);
            // num_globals += 1;
        }
        MemoryMode::Memory32 => {
            main_accessed_pages_counter_ix = None;
        }
    };

    let special_indices = SpecialIndices {
        instructions_counter_ix,
        dirty_pages_counter_ix,
        stable_accessed_pages_counter_ix,
        main_accessed_pages_counter_ix,
        decr_instruction_counter_fn,
        count_clean_pages_fn,
        start_fn_ix: module.start,
        stable_memory_index,
    };

    if special_indices.start_fn_ix.is_some() {
        module.start = None;
    }

    // inject instructions counter decrementation
    for func_body in &mut module.code_sections {
        inject_metering(
            &mut func_body.instructions,
            &special_indices,
            metering_type,
            main_memory_mode,
        );
    }

    // Collect all the function types of the locally defined functions inside the
    // module.
    //
    // The main reason to create this vector of function types is because we can't
    // mix a mutable (to inject instructions) and immutable (to look up the function
    // type) reference to the `code_section`.
    let mut func_types = Vec::new();
    for i in 0..module.code_sections.len() {
        if let StructuralType::Func(t) = &module.types[module.functions[i] as usize].structural_type
        {
            func_types.push((i, t.clone()));
        } else {
            return Err(WasmInstrumentationError::InvalidFunctionType(format!(
                "Function has type which is not a function type. Found type: {:?}",
                &module.types[module.functions[i] as usize].structural_type
            )));
        }
    }

    // Inject `update_available_memory` to functions with `memory.grow`
    // instructions.
    if !func_types.is_empty() {
        let func_bodies = &mut module.code_sections;
        for (func_ix, func_type) in func_types.into_iter() {
            inject_update_available_memory(&mut func_bodies[func_ix], &func_type, main_memory_mode);
            if write_barrier == FlagStatus::Enabled || main_memory_mode == MemoryMode::Memory64 {
                inject_mem_barrier(
                    &mut func_bodies[func_ix],
                    &func_type,
                    main_memory_mode,
                    wasm_native_stable_memory,
                );
            }
        }
    }

    module = export_additional_symbols(
        module,
        &special_indices,
        wasm_native_stable_memory,
        main_memory_mode,
    );

    if wasm_native_stable_memory == FlagStatus::Enabled {
        replace_system_api_functions(
            &mut module,
            special_indices,
            subnet_type,
            dirty_page_overhead,
            metering_type,
            main_memory_mode,
        )
    }

    let exported_functions = module
        .exports
        .iter()
        .filter_map(|export| WasmMethod::try_from(export.name.to_string()).ok())
        .collect();

    let expected_memories =
        1 + match (write_barrier, main_memory_mode) {
            (FlagStatus::Enabled, _) | (_, MemoryMode::Memory64) => 1,
            (FlagStatus::Disabled, MemoryMode::Memory32) => 0,
        } + match wasm_native_stable_memory {
            FlagStatus::Enabled => 2,
            FlagStatus::Disabled => 0,
        };
    if module.memories.len() > expected_memories {
        return Err(WasmInstrumentationError::IncorrectNumberMemorySections {
            expected: expected_memories,
            got: module.memories.len(),
        });
    }

    let initial_limit = if module.memories.is_empty() {
        // if Wasm does not declare any memory section (mostly tests), use this default
        0
    } else {
        module.memories[0].initial
    };

    // pull out the data from the data section
    let data = get_data(&mut module.data)?;
    data.validate(NumWasmPages::from(initial_limit as usize))?;

    let mut wasm_instruction_count: u64 = 0;
    for body in &module.code_sections {
        wasm_instruction_count += body.instructions.len() as u64;
    }
    for glob in &module.globals {
        wasm_instruction_count += glob.init_expr.len() as u64;
    }

    let result = module.encode().map_err(|err| {
        WasmInstrumentationError::WasmSerializeError(WasmError::new(err.to_string()))
    })?;

    Ok(InstrumentationOutput {
        exported_functions,
        data,
        binary: BinaryEncodedWasm::new(result),
        compilation_cost: cost_to_compile_wasm_instruction * wasm_instruction_count,
    })
}

fn calculate_api_indexes(module: &Module<'_>) -> BTreeMap<SystemApiFunc, u32> {
    module
        .imports
        .iter()
        .filter(|imp| matches!(imp.ty, TypeRef::Func(_)))
        .enumerate()
        .filter_map(|(func_index, import)| {
            if import.module == API_VERSION_IC0 {
                // The imports get function indexes before defined functions (so
                // starting at zero) and these are required to fit in 32-bits.
                SystemApiFunc::from_import_name(import.name).map(|api| (api, func_index as u32))
            } else {
                None
            }
        })
        .collect()
}

fn replace_system_api_functions(
    module: &mut Module<'_>,
    special_indices: SpecialIndices,
    subnet_type: SubnetType,
    dirty_page_overhead: NumInstructions,
    metering_type: MeteringType,
    main_memory_mode: MemoryMode,
) {
    let api_indexes = calculate_api_indexes(module);
    let number_of_func_imports = module
        .imports
        .iter()
        .filter(|i| matches!(i.ty, TypeRef::Func(_)))
        .count();

    // Collect a single map of all the function indexes that need to be
    // replaced.
    let mut func_index_replacements = BTreeMap::new();
    for (api, (ty, body)) in replacement_functions(
        special_indices,
        subnet_type,
        dirty_page_overhead,
        metering_type,
        main_memory_mode,
    ) {
        if let Some(old_index) = api_indexes.get(&api) {
            let type_idx = add_func_type(module, ty);
            let new_index = (number_of_func_imports + module.functions.len()) as u32;
            module.functions.push(type_idx);
            module.code_sections.push(body);
            func_index_replacements.insert(*old_index, new_index);
        }
    }

    // Perform all the replacements in a single pass.
    mutate_function_indices(module, |idx| {
        *func_index_replacements.get(&idx).unwrap_or(&idx)
    });
}

// Helper function used by instrumentation to export additional symbols.
//
// Returns the new module or panics in debug mode if a symbol is not reserved.
fn export_additional_symbols<'a>(
    mut module: Module<'a>,
    special_indices: &SpecialIndices,
    wasm_native_stable_memory: FlagStatus,
    main_memory_mode: MemoryMode,
) -> Module<'a> {
    // push function to decrement the instruction counter

    let func_type = FuncType::new([ValType::I64], [ValType::I64]);

    use Operator::*;

    let instructions = vec![
        // Subtract the parameter amount from the instruction counter
        GlobalGet {
            global_index: special_indices.instructions_counter_ix,
        },
        LocalGet { local_index: 0 },
        I64Sub,
        // Store the new counter value in the local
        LocalTee { local_index: 1 },
        // If `new_counter > old_counter` there was underflow, so set counter to
        // minimum value. Otherwise set it to the new counter value.
        GlobalGet {
            global_index: special_indices.instructions_counter_ix,
        },
        I64GtS,
        If {
            blockty: BlockType::Type(ValType::I64),
        },
        I64Const { value: i64::MIN },
        Else,
        LocalGet { local_index: 1 },
        End,
        GlobalSet {
            global_index: special_indices.instructions_counter_ix,
        },
        // Call out_of_instructions() if `new_counter < 0`.
        GlobalGet {
            global_index: special_indices.instructions_counter_ix,
        },
        I64Const { value: 0 },
        I64LtS,
        If {
            blockty: BlockType::Empty,
        },
        Call {
            function_index: InjectedImports::OutOfInstructions as u32,
        },
        End,
        // Return the original param so this function doesn't alter the stack
        LocalGet { local_index: 0 },
        End,
    ];

    let func_body = wasm_transform::Body {
        locals: vec![(1, ValType::I64)],
        instructions,
    };

    let type_idx = add_func_type(&mut module, func_type);
    module.functions.push(type_idx);
    module.code_sections.push(func_body);

    if wasm_native_stable_memory == FlagStatus::Enabled {
        // function to count clean pages in a given range
        // Arg 0 - start of the range
        // Arg 1 - end of the range
        // Return index 0 is the number of pages that haven't been written to in the given range
        // Return index 1 is the number of pages that haven't been accessed in the given range.
        let func_type = FuncType::new([ValType::I32, ValType::I32], [ValType::I32, ValType::I32]);
        let it = 2; // iterator index
        let tmp = 3;
        let acc_w = 4; // accumulator index
        let acc_a = 5; // accumulator index
        let instructions = vec![
            LocalGet { local_index: 0 },
            LocalGet { local_index: 1 },
            I32GeU,
            If {
                blockty: BlockType::Empty,
            },
            // If range is empty, return early
            I32Const { value: 0 },
            I32Const { value: 0 },
            Return,
            End,
            LocalGet { local_index: 0 },
            LocalSet { local_index: it },
            Loop {
                blockty: BlockType::Empty,
            },
            LocalGet { local_index: it },
            // TODO read in bigger chunks (i64Load)
            I32Load8U {
                memarg: wasmparser::MemArg {
                    align: 0,
                    max_align: 0,
                    offset: 0,
                    // We assume the bytemap for stable memory is always
                    // inserted directly after the stable memory.
                    memory: special_indices.stable_memory_index + 1,
                },
            },
            LocalTee { local_index: tmp },
            I32Const { value: 1 }, //write bit
            I32And,
            // update acc_w
            LocalGet { local_index: acc_w },
            I32Add,
            LocalSet { local_index: acc_w },
            // get access bit
            LocalGet { local_index: tmp },
            I32Const { value: 1 },
            I32ShrU,
            I32Const { value: 1 },
            I32And,
            // update acc_a
            LocalGet { local_index: acc_a },
            I32Add,
            LocalSet { local_index: acc_a },
            LocalGet { local_index: it },
            I32Const { value: 1 },
            I32Add,
            LocalTee { local_index: it },
            LocalGet { local_index: 1 },
            I32LtU,
            BrIf { relative_depth: 0 },
            End,
            // clean pages = len - dirty_count
            LocalGet { local_index: 1 },
            LocalGet { local_index: 0 },
            I32Sub,
            LocalGet { local_index: acc_w },
            I32Sub,
            // non-accessed pages
            LocalGet { local_index: 1 },
            LocalGet { local_index: 0 },
            I32Sub,
            LocalGet { local_index: acc_a },
            I32Sub,
            End,
        ];
        let func_body = wasm_transform::Body {
            locals: vec![(4, ValType::I32)],
            instructions,
        };
        let type_idx = add_func_type(&mut module, func_type);
        module.functions.push(type_idx);
        module.code_sections.push(func_body);
    }

    // globals must be exported to be accessible to hypervisor or persisted
    let counter_export = Export {
        name: INSTRUCTIONS_COUNTER_GLOBAL_NAME,
        kind: ExternalKind::Global,
        index: special_indices.instructions_counter_ix,
    };
    debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&counter_export.name));
    module.exports.push(counter_export);

    if let Some(index) = special_indices.dirty_pages_counter_ix {
        let export = Export {
            name: DIRTY_PAGES_COUNTER_GLOBAL_NAME,
            kind: ExternalKind::Global,
            index,
        };
        debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&export.name));
        module.exports.push(export);
    }

    if let Some(index) = special_indices.stable_accessed_pages_counter_ix {
        let export = Export {
            name: STABLE_ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
            kind: ExternalKind::Global,
            index,
        };
        debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&export.name));
        module.exports.push(export);
    }

    if let Some(index) = special_indices.start_fn_ix {
        // push canister_start
        let start_export = Export {
            name: CANISTER_START_STR,
            kind: ExternalKind::Func,
            index,
        };
        debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&start_export.name));
        module.exports.push(start_export);
    }

    if let Some(index) = special_indices.main_accessed_pages_counter_ix {
        let export = Export {
            name: MAIN_ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
            kind: ExternalKind::Global,
            index,
        };
        debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&export.name));
        module.exports.push(export);
    }

    // push the instructions counter
    assert_eq!(
        module.globals.len(),
        special_indices.instructions_counter_ix as usize
    );
    module.globals.push(Global {
        ty: GlobalType {
            content_type: ValType::I64,
            mutable: true,
        },
        init_expr: vec![Operator::I64Const { value: 0 }, Operator::End],
    });

    if wasm_native_stable_memory == FlagStatus::Enabled {
        // push the dirty page counter
        assert_eq!(
            module.globals.len(),
            special_indices.dirty_pages_counter_ix.unwrap() as usize
        );
        module.globals.push(Global {
            ty: GlobalType {
                content_type: ValType::I64,
                mutable: true,
            },
            init_expr: vec![Operator::I64Const { value: 0 }, Operator::End],
        });
        // push the accessed stable memory page counter
        assert_eq!(
            module.globals.len(),
            special_indices.stable_accessed_pages_counter_ix.unwrap() as usize
        );
        module.globals.push(Global {
            ty: GlobalType {
                content_type: ValType::I64,
                mutable: true,
            },
            init_expr: vec![Operator::I64Const { value: 0 }, Operator::End],
        });
    }

    if main_memory_mode == MemoryMode::Memory64 {
        // push the accessed main memory page counter
        assert_eq!(
            module.globals.len(),
            special_indices.main_accessed_pages_counter_ix.unwrap() as usize
        );
        module.globals.push(Global {
            ty: GlobalType {
                content_type: ValType::I64,
                mutable: true,
            },
            init_expr: vec![Operator::I64Const { value: 0 }, Operator::End],
        });
    }

    module
}

// Represents a hint about the context of each static cost injection point in
// wasm.
#[derive(Copy, Clone, Debug, PartialEq)]
enum Scope {
    ReentrantBlockStart,
    NonReentrantBlockStart,
    BlockEnd,
}

// Describes how to calculate the instruction cost at this injection point.
// `StaticCost` injection points contain information about the cost of the
// following basic block. `DynamicCost` injection points assume there is an
// i32 on 32-bit Wasm or an i64 on Wasm Memory64 on the stack which should
// be decremented from the instruction counter.
#[derive(Copy, Clone, Debug, PartialEq)]
enum InjectionPointCostDetail {
    StaticCost { scope: Scope, cost: u64 },
    DynamicCost,
}

impl InjectionPointCostDetail {
    /// If the cost is statically known, increment it by the given amount.
    /// Otherwise do nothing.
    fn increment_cost(&mut self, additonal_cost: u64) {
        match self {
            Self::StaticCost { scope: _, cost } => *cost += additonal_cost,
            Self::DynamicCost => {}
        }
    }
}

// Represents a instructions metering injection point.
#[derive(Copy, Clone, Debug)]
struct InjectionPoint {
    cost_detail: InjectionPointCostDetail,
    position: usize,
}

impl InjectionPoint {
    fn new_static_cost(position: usize, scope: Scope) -> Self {
        InjectionPoint {
            cost_detail: InjectionPointCostDetail::StaticCost { scope, cost: 0 },
            position,
        }
    }

    fn new_dynamic_cost(position: usize) -> Self {
        InjectionPoint {
            cost_detail: InjectionPointCostDetail::DynamicCost,
            position,
        }
    }
}

// This function iterates over the injection points, and inserts three different
// pieces of Wasm code:
// - we insert a simple instructions counter decrementation in a beginning of
//   every non-reentrant block
// - we insert a counter decrementation and an overflow check at the beginning
//   of every reentrant block (a loop or a function call).
// - we insert a function call before each dynamic cost instruction which
//   performs an overflow check and then decrements the counter by the value at
//   the top of the stack.
fn inject_metering(
    code: &mut Vec<Operator>,
    export_data_module: &SpecialIndices,
    metering_type: MeteringType,
    main_memory_mode: MemoryMode,
) {
    let points = match metering_type {
        MeteringType::Old => injections_old(code),
        MeteringType::None => Vec::new(),
        MeteringType::New => injections_new(code),
    };
    let points = points.iter().filter(|point| match point.cost_detail {
        InjectionPointCostDetail::StaticCost {
            scope: Scope::ReentrantBlockStart,
            cost: _,
        } => true,
        InjectionPointCostDetail::StaticCost { scope: _, cost } => cost > 0,
        InjectionPointCostDetail::DynamicCost => true,
    });
    let orig_elems = code;
    let mut elems: Vec<Operator> = Vec::new();
    let mut last_injection_position = 0;

    use Operator::*;

    for point in points {
        elems.extend_from_slice(&orig_elems[last_injection_position..point.position]);
        match point.cost_detail {
            InjectionPointCostDetail::StaticCost { scope, cost } => {
                elems.extend_from_slice(&[
                    GlobalGet {
                        global_index: export_data_module.instructions_counter_ix,
                    },
                    I64Const { value: cost as i64 },
                    I64Sub,
                    GlobalSet {
                        global_index: export_data_module.instructions_counter_ix,
                    },
                ]);
                if scope == Scope::ReentrantBlockStart {
                    elems.extend_from_slice(&[
                        GlobalGet {
                            global_index: export_data_module.instructions_counter_ix,
                        },
                        I64Const { value: 0 },
                        I64LtS,
                        If {
                            blockty: BlockType::Empty,
                        },
                        Call {
                            function_index: InjectedImports::OutOfInstructions as u32,
                        },
                        End,
                    ]);
                }
            }
            InjectionPointCostDetail::DynamicCost => {
                let call = Call {
                    function_index: export_data_module.decr_instruction_counter_fn,
                };

                match main_memory_mode {
                    MemoryMode::Memory32 => {
                        elems.extend_from_slice(&[
                            I64ExtendI32U,
                            call,
                            // decr_instruction_counter returns it's argument unchanged,
                            // so we can convert back to I32 without worrying about
                            // overflows.
                            I32WrapI64,
                        ]);
                    }
                    MemoryMode::Memory64 => {
                        elems.extend_from_slice(&[call]);
                    }
                };
            }
        }
        last_injection_position = point.position;
    }
    elems.extend_from_slice(&orig_elems[last_injection_position..]);
    *orig_elems = elems;
}

// This function adds mem barrier writes, assuming that arguments
// of the original store operation are on the stack
fn write_barrier_instructions<'a>(
    offset: u64,
    val_arg_idx: u32,
    addr_arg_idx: u32,
) -> Vec<Operator<'a>> {
    use Operator::*;
    let page_size_shift = PAGE_SIZE.trailing_zeros() as i32;
    let tracking_mem_idx = 1;
    if offset % PAGE_SIZE as u64 == 0 {
        vec![
            LocalSet {
                local_index: val_arg_idx,
            }, // value
            LocalTee {
                local_index: addr_arg_idx,
            }, // address
            I32Const {
                value: page_size_shift,
            },
            I32ShrU,
            I32Const { value: 1 },
            I32Store8 {
                memarg: wasmparser::MemArg {
                    align: 0,
                    max_align: 0,
                    offset: offset >> page_size_shift,
                    memory: tracking_mem_idx,
                },
            },
            // Put original params on the stack
            LocalGet {
                local_index: addr_arg_idx,
            },
            LocalGet {
                local_index: val_arg_idx,
            },
        ]
    } else {
        vec![
            LocalSet {
                local_index: val_arg_idx,
            }, // value
            LocalTee {
                local_index: addr_arg_idx,
            }, // address
            I32Const {
                value: offset as i32,
            },
            I32Add,
            I32Const {
                value: page_size_shift,
            },
            I32ShrU,
            I32Const { value: 1 },
            I32Store8 {
                memarg: wasmparser::MemArg {
                    align: 0,
                    max_align: 0,
                    offset: 0,
                    memory: tracking_mem_idx,
                },
            },
            // Put original params on the stack
            LocalGet {
                local_index: addr_arg_idx,
            },
            LocalGet {
                local_index: val_arg_idx,
            },
        ]
    }
}

enum AccessKind {
    Load,
    Store { value_argument_index: u32 },
}

/// Special read and write barriers used for 64-bit main memory.
/// * Guards the working set limit, maximum number of pages read or written
///   during a single message.
/// * Marks dirty pages in main memory, replacement for `write_barrier_instructions`.
///
/// Encoding used in the byte map, denoting access information per page during a message.
/// 0: Page has not yet been accessed.
/// 1: Page has been accessed, and at least one write access was involved.
/// 2: Page has only been read until now.
///
/// It assumes that the original arguments of a load or store operation are
/// on top of the Wasm evaluation stack.
///
/// Note: Accesses may be unaligned and cross an OS page boundary.
/// Therefore, the barrier potentially triggers two page guards for an unaligned access.
fn memory64_barrier_instructions<'a>(
    kind: AccessKind,
    offset: u64,
    size: u64,
    address_argument_index: u32,
    byte_map_index: u32,
    wasm_native_stable_memory: FlagStatus,
) -> Vec<Operator<'a>> {
    use Operator::*;
    let page_size_shift = PAGE_SIZE.trailing_zeros() as i32;
    let tracking_mem_idx = 1;

    let mut instructions = vec![];

    // Backup value of a store operation.
    match kind {
        AccessKind::Load => {}
        AccessKind::Store {
            value_argument_index,
        } => {
            instructions.push(LocalSet {
                local_index: value_argument_index,
            });
        }
    }

    const _: () = assert!(MAX_WASM_MEMORY_IN_BYTES / PAGE_SIZE as u64 <= u32::MAX as u64);

    instructions.append(&mut vec![
        // Backup the address argument of the access operation.
        LocalTee {
            local_index: address_argument_index,
        },
        // Read the page-associated information in the byte map.
        // TODO: Possibly optimize for `offset % PAGE_SIZE == 0`, analogous to `write_barrier_instructions`.
        I64Const {
            value: offset as i64,
        },
        I64Add,
        I64Const {
            value: page_size_shift as i64,
        },
        I64ShrU,
        // See assertion above: Assumes that the maximum main memory can be mapped to a 32-bit byte map.
        I32WrapI64,
        LocalTee {
            local_index: byte_map_index,
        },
        I32Load8U {
            memarg: wasmparser::MemArg {
                align: 0,
                max_align: 0,
                offset: 0,
                memory: tracking_mem_idx,
            },
        },
    ]);

    // Check whether page guard should be triggered for the page of the first accessed byte:
    // * For read accesses, if it has not yet been previously read or written (i.e. state `0`).
    // * For write accesses, if it has not yet been previously written (i.e. state is not `1`).
    // Unaligned accesses crossing pages are handled later.
    match kind {
        AccessKind::Load => instructions.push(I32Eqz),
        AccessKind::Store { .. } => instructions.append(&mut vec![I32Const { value: 1 }, I32Ne]),
    }

    // Trigger page guard for the first accessed byte only if needed.
    let page_guard_import = match kind {
        AccessKind::Load => InjectedImports::MainReadPageGuard,
        AccessKind::Store { .. } => InjectedImports::MainWritePageGuard,
    };
    let page_guard_function_index =
        page_guard_import.get_index(MemoryMode::Memory64, wasm_native_stable_memory) as u32;

    instructions.append(&mut vec![
        If {
            blockty: BlockType::Empty,
        },
        LocalGet {
            local_index: byte_map_index,
        },
        Call {
            function_index: page_guard_function_index,
        },
        End,
    ]);

    assert!(size <= PAGE_SIZE as u64);
    if size > 1 {
        // Handle potential unaligned accesses.
        instructions.append(&mut vec![
            // Compute the last accessed byte.
            LocalGet {
                local_index: address_argument_index,
            },
            I64Const {
                value: (offset + size - 1) as i64,
            },
            I64Add,
            I64Const {
                value: page_size_shift as i64,
            },
            I64ShrU,
            // See assertion above: Assumes that the maximum main memory can be mapped to a 32-bit byte map.
            I32WrapI64,
            // Compare against the first accessed byte.
            LocalGet {
                local_index: byte_map_index,
            },
            I32Ne,
            If {
                blockty: BlockType::Empty,
            },
            // Page-crossing access. At most one subsequent page can be accessed because `size <= PAGE_SIZE`.
            // The guard is unconditionally triggered for the second accessed page. The guard logic checks whether
            // this access needs specific handling (updating the byte map and guarding the working set limit).
            LocalGet {
                local_index: byte_map_index,
            },
            I32Const { value: 1 },
            I32Add,
            Call {
                function_index: page_guard_function_index,
            },
            End,
        ]);
    }

    instructions.append(&mut vec![
        // Restore the address argument of the access operation.
        LocalGet {
            local_index: address_argument_index,
        },
    ]);

    // Restore value of a store operation.
    match kind {
        AccessKind::Load => {}
        AccessKind::Store {
            value_argument_index,
        } => {
            instructions.push(LocalGet {
                local_index: value_argument_index,
            });
        }
    }
    instructions
}

const IS_BULK_READ: i32 = 0;
const IS_BULK_WRITE: i32 = 1;

fn memory_copy_barrier_instructions<'a>(
    destination_argument_index: u32,
    source_argument_index: u32,
    length_argument_index: u32,
    wasm_native_stable_memory: FlagStatus,
) -> Vec<Operator<'a>> {
    use Operator::*;
    let bulk_access_guard_index = InjectedImports::MainBulkAccessGuard
        .get_index(MemoryMode::Memory64, wasm_native_stable_memory)
        as u32;
    vec![
        // Backup arguments.
        LocalSet {
            local_index: length_argument_index,
        },
        LocalSet {
            local_index: source_argument_index,
        },
        LocalSet {
            local_index: destination_argument_index,
        },
        // Bulk read guard on the source segment.
        LocalGet {
            local_index: source_argument_index,
        },
        LocalGet {
            local_index: length_argument_index,
        },
        I32Const {
            value: IS_BULK_READ,
        },
        Call {
            function_index: bulk_access_guard_index,
        },
        // Bulk write guard on the destination segment.
        LocalGet {
            local_index: destination_argument_index,
        },
        LocalGet {
            local_index: length_argument_index,
        },
        I32Const {
            value: IS_BULK_WRITE,
        },
        Call {
            function_index: bulk_access_guard_index,
        },
        // Restore arguments
        LocalGet {
            local_index: destination_argument_index,
        },
        LocalGet {
            local_index: source_argument_index,
        },
        LocalGet {
            local_index: length_argument_index,
        },
    ]
}

fn memory_fill_barrier_instructions<'a>(
    destination_argument_index: u32,
    val_i32_index: u32,
    length_argument_index: u32,
    wasm_native_stable_memory: FlagStatus,
) -> Vec<Operator<'a>> {
    use Operator::*;
    let bulk_access_guard_index = InjectedImports::MainBulkAccessGuard
        .get_index(MemoryMode::Memory64, wasm_native_stable_memory)
        as u32;
    vec![
        // Backup arguments.
        LocalSet {
            local_index: length_argument_index,
        },
        LocalSet {
            local_index: val_i32_index,
        },
        LocalSet {
            local_index: destination_argument_index,
        },
        // Bulk write guard on the destination segment.
        LocalGet {
            local_index: destination_argument_index,
        },
        LocalGet {
            local_index: length_argument_index,
        },
        I32Const {
            value: IS_BULK_WRITE,
        },
        Call {
            function_index: bulk_access_guard_index,
        },
        // Restore arguments
        LocalGet {
            local_index: destination_argument_index,
        },
        LocalGet {
            local_index: val_i32_index,
        },
        LocalGet {
            local_index: length_argument_index,
        },
    ]
}

fn inject_mem_barrier(
    func_body: &mut wasm_transform::Body,
    func_type: &FuncType,
    main_memory_mode: MemoryMode,
    wasm_native_stable_memory: FlagStatus,
) {
    use Operator::*;
    let mut val_i32_needed = false;
    let mut val_i64_needed = false;
    let mut val_f32_needed = false;
    let mut val_f64_needed = false;
    let mut memory_length_needed = false;

    let mut injection_points: Vec<usize> = Vec::new();
    {
        for (idx, instr) in func_body.instructions.iter().enumerate() {
            match instr {
                I32Load { .. }
                | I32Load8U { .. }
                | I32Load8S { .. }
                | I32Load16U { .. }
                | I32Load16S { .. }
                    if main_memory_mode == MemoryMode::Memory64 =>
                {
                    val_i32_needed = true;
                    injection_points.push(idx)
                }
                I32Store { .. } | I32Store8 { .. } | I32Store16 { .. } => {
                    val_i32_needed = true;
                    injection_points.push(idx)
                }
                I64Load { .. }
                | I64Load8U { .. }
                | I64Load8S { .. }
                | I64Load16U { .. }
                | I64Load16S { .. }
                | I64Load32U { .. }
                | I64Load32S { .. }
                    if main_memory_mode == MemoryMode::Memory64 =>
                {
                    val_i64_needed = true;
                    injection_points.push(idx)
                }
                I64Store { .. } | I64Store8 { .. } | I64Store16 { .. } | I64Store32 { .. } => {
                    val_i64_needed = true;
                    injection_points.push(idx)
                }
                F32Load { .. } if main_memory_mode == MemoryMode::Memory64 => {
                    val_f32_needed = true;
                    injection_points.push(idx)
                }
                F32Store { .. } => {
                    val_f32_needed = true;
                    injection_points.push(idx)
                }
                F64Load { .. } if main_memory_mode == MemoryMode::Memory64 => {
                    val_f64_needed = true;
                    injection_points.push(idx)
                }
                F64Store { .. } => {
                    val_f64_needed = true;
                    injection_points.push(idx)
                }
                MemoryCopy { .. } if main_memory_mode == MemoryMode::Memory64 => {
                    val_i64_needed = true;
                    memory_length_needed = true;
                    injection_points.push(idx)
                }
                MemoryFill { .. } if main_memory_mode == MemoryMode::Memory64 => {
                    val_i32_needed = true;
                    memory_length_needed = true;
                    injection_points.push(idx)
                }
                _ => (),
            }
        }
    }

    // If we found some injection points, we need to instrument the code.
    if !injection_points.is_empty() {
        // We inject some locals to cache the arguments to `memory.store`.
        // The locals are stored as a vector of (count, ValType), so summing over the first field gives
        // the total number of locals.
        let n_locals: u32 = func_body.locals.iter().map(|x| x.0).sum();
        let mut next_local = func_type.params().len() as u32 + n_locals;

        let arg_address_idx = next_local;
        next_local += 1;
        let address_type = match main_memory_mode {
            MemoryMode::Memory64 => ValType::I64,
            MemoryMode::Memory32 => ValType::I32,
        };
        func_body.locals.push((1, address_type));

        // conditionally add following locals
        let arg_i32_val_idx;
        let arg_i64_val_idx;
        let arg_f32_val_idx;
        let arg_f64_val_idx;

        if val_i32_needed {
            arg_i32_val_idx = next_local;
            next_local += 1;
            func_body.locals.push((1, ValType::I32));
        } else {
            arg_i32_val_idx = u32::MAX; // not used
        }

        if val_i64_needed {
            arg_i64_val_idx = next_local;
            next_local += 1;
            func_body.locals.push((1, ValType::I64));
        } else {
            arg_i64_val_idx = u32::MAX;
        }

        if val_f32_needed {
            arg_f32_val_idx = next_local;
            next_local += 1;
            func_body.locals.push((1, ValType::F32));
        } else {
            arg_f32_val_idx = u32::MAX;
        }

        if val_f64_needed {
            arg_f64_val_idx = next_local;
            next_local += 1;
            func_body.locals.push((1, ValType::F64));
        } else {
            arg_f64_val_idx = u32::MAX;
        }

        let memory_length_index = if memory_length_needed {
            let memory_length_index = next_local;
            next_local += 1;
            func_body.locals.push((1, ValType::I64));
            Some(memory_length_index)
        } else {
            None
        };

        let byte_map_index = if main_memory_mode == MemoryMode::Memory64 {
            let byte_map_index = next_local;
            // next_local += 1;
            func_body.locals.push((1, ValType::I32));
            Some(byte_map_index)
        } else {
            None
        };

        let orig_elems = &func_body.instructions;
        let mut elems: Vec<Operator> = Vec::new();
        let mut last_injection_position = 0;
        for point in injection_points {
            let mem_instr = orig_elems[point].clone();
            elems.extend_from_slice(&orig_elems[last_injection_position..point]);
            let access_size = get_access_size(&mem_instr);

            match mem_instr {
                I32Load { memarg }
                | I32Load8U { memarg }
                | I32Load8S { memarg }
                | I32Load16U { memarg }
                | I32Load16S { memarg }
                    if main_memory_mode == MemoryMode::Memory64 =>
                {
                    elems.extend_from_slice(&memory64_barrier_instructions(
                        AccessKind::Load,
                        memarg.offset,
                        access_size.unwrap(),
                        arg_address_idx,
                        byte_map_index.unwrap(),
                        wasm_native_stable_memory,
                    ));
                }
                I32Store { memarg } | I32Store8 { memarg } | I32Store16 { memarg } => {
                    match main_memory_mode {
                        MemoryMode::Memory64 => {
                            elems.extend_from_slice(&memory64_barrier_instructions(
                                AccessKind::Store {
                                    value_argument_index: arg_i32_val_idx,
                                },
                                memarg.offset,
                                access_size.unwrap(),
                                arg_address_idx,
                                byte_map_index.unwrap(),
                                wasm_native_stable_memory,
                            ))
                        }
                        MemoryMode::Memory32 => {
                            elems.extend_from_slice(&write_barrier_instructions(
                                memarg.offset,
                                arg_i32_val_idx,
                                arg_address_idx,
                            ))
                        }
                    }
                }
                I64Load { memarg }
                | I64Load8U { memarg }
                | I64Load8S { memarg }
                | I64Load16U { memarg }
                | I64Load16S { memarg }
                | I64Load32U { memarg }
                | I64Load32S { memarg }
                    if main_memory_mode == MemoryMode::Memory64 =>
                {
                    elems.extend_from_slice(&memory64_barrier_instructions(
                        AccessKind::Load,
                        memarg.offset,
                        access_size.unwrap(),
                        arg_address_idx,
                        byte_map_index.unwrap(),
                        wasm_native_stable_memory,
                    ));
                }
                I64Store { memarg }
                | I64Store8 { memarg }
                | I64Store16 { memarg }
                | I64Store32 { memarg } => match main_memory_mode {
                    MemoryMode::Memory64 => {
                        elems.extend_from_slice(&memory64_barrier_instructions(
                            AccessKind::Store {
                                value_argument_index: arg_i64_val_idx,
                            },
                            memarg.offset,
                            access_size.unwrap(),
                            arg_address_idx,
                            byte_map_index.unwrap(),
                            wasm_native_stable_memory,
                        ))
                    }
                    MemoryMode::Memory32 => elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_i64_val_idx,
                        arg_address_idx,
                    )),
                },
                F32Load { memarg } if main_memory_mode == MemoryMode::Memory64 => {
                    elems.extend_from_slice(&memory64_barrier_instructions(
                        AccessKind::Load,
                        memarg.offset,
                        access_size.unwrap(),
                        arg_address_idx,
                        byte_map_index.unwrap(),
                        wasm_native_stable_memory,
                    ));
                }
                F32Store { memarg } => match main_memory_mode {
                    MemoryMode::Memory64 => {
                        elems.extend_from_slice(&memory64_barrier_instructions(
                            AccessKind::Store {
                                value_argument_index: arg_f32_val_idx,
                            },
                            memarg.offset,
                            access_size.unwrap(),
                            arg_address_idx,
                            byte_map_index.unwrap(),
                            wasm_native_stable_memory,
                        ))
                    }
                    MemoryMode::Memory32 => elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_f32_val_idx,
                        arg_address_idx,
                    )),
                },
                F64Load { memarg } if main_memory_mode == MemoryMode::Memory64 => {
                    elems.extend_from_slice(&memory64_barrier_instructions(
                        AccessKind::Load,
                        memarg.offset,
                        access_size.unwrap(),
                        arg_address_idx,
                        byte_map_index.unwrap(),
                        wasm_native_stable_memory,
                    ));
                }
                F64Store { memarg } => match main_memory_mode {
                    MemoryMode::Memory64 => {
                        elems.extend_from_slice(&memory64_barrier_instructions(
                            AccessKind::Store {
                                value_argument_index: arg_f64_val_idx,
                            },
                            memarg.offset,
                            access_size.unwrap(),
                            arg_address_idx,
                            byte_map_index.unwrap(),
                            wasm_native_stable_memory,
                        ))
                    }
                    MemoryMode::Memory32 => elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_f64_val_idx,
                        arg_address_idx,
                    )),
                },
                MemoryCopy { dst_mem, src_mem } if main_memory_mode == MemoryMode::Memory64 => {
                    assert_eq!(dst_mem, 0);
                    assert_eq!(src_mem, 0);
                    elems.extend_from_slice(&memory_copy_barrier_instructions(
                        arg_address_idx,
                        arg_i64_val_idx,
                        memory_length_index.unwrap(),
                        wasm_native_stable_memory,
                    ));
                }
                MemoryFill { mem } if main_memory_mode == MemoryMode::Memory64 => {
                    assert_eq!(mem, 0);
                    elems.extend_from_slice(&memory_fill_barrier_instructions(
                        arg_address_idx,
                        arg_i32_val_idx,
                        memory_length_index.unwrap(),
                        wasm_native_stable_memory,
                    ));
                }
                _ => {}
            }
            // add the original store instruction itself
            elems.push(mem_instr);

            last_injection_position = point + 1;
        }
        elems.extend_from_slice(&orig_elems[last_injection_position..]);
        func_body.instructions = elems;
    }
}

fn get_access_size(mem_instr: &Operator<'_>) -> Option<u64> {
    use Operator::*;
    match *mem_instr {
        I32Load8U { .. }
        | I32Load8S { .. }
        | I32Store8 { .. }
        | I64Load8U { .. }
        | I64Load8S { .. }
        | I64Store8 { .. } => Some(1),
        I32Load16U { .. }
        | I32Load16S { .. }
        | I32Store16 { .. }
        | I64Load16U { .. }
        | I64Load16S { .. }
        | I64Store16 { .. } => Some(2),
        I32Load { .. }
        | I32Store { .. }
        | I64Load32U { .. }
        | I64Load32S { .. }
        | I64Store32 { .. }
        | F32Load { .. }
        | F32Store { .. } => Some(4),
        I64Load { .. } | I64Store { .. } | F64Load { .. } | F64Store { .. } => Some(8),
        _ => None,
    }
}

// Scans through a function and adds instrumentation after each `memory.grow` or
// `table.grow` instruction to make sure that there's enough available memory
// left to support the requested extra memory. If no `memory.grow` or
// `table.grow` instructions are present then the code remains unchanged.
fn inject_update_available_memory(
    func_body: &mut wasm_transform::Body,
    func_type: &FuncType,
    main_memory_mode: MemoryMode,
) {
    // This is an overestimation of table element size computed based on the
    // existing canister limits.
    const TABLE_ELEMENT_SIZE: u32 = 1024;
    use Operator::*;
    let mut injection_points: Vec<(usize, u32)> = Vec::new();
    {
        for (idx, instr) in func_body.instructions.iter().enumerate() {
            if let MemoryGrow { .. } = instr {
                injection_points.push((idx, WASM_PAGE_SIZE));
            }
            if let TableGrow { .. } = instr {
                injection_points.push((idx, TABLE_ELEMENT_SIZE));
            }
        }
    }

    // If we found any injection points, we need to instrument the code.
    if !injection_points.is_empty() {
        // We inject a local to cache the argument to `memory.grow`.
        // The locals are stored as a vector of (count, ValType), so summing over the first field gives
        // the total number of locals.
        let n_locals: u32 = func_body.locals.iter().map(|x| x.0).sum();
        let memory_local_ix = func_type.params().len() as u32 + n_locals;

        let local_type = match main_memory_mode {
            MemoryMode::Memory32 => ValType::I32,
            MemoryMode::Memory64 => ValType::I64,
        };
        func_body.locals.push((1, local_type));

        let orig_elems = &func_body.instructions;
        let mut elems: Vec<Operator> = Vec::new();
        let mut last_injection_position = 0;
        for (point, element_size) in injection_points {
            let update_available_memory_instr = orig_elems[point].clone();
            elems.extend_from_slice(&orig_elems[last_injection_position..point]);
            // At this point we have a memory.grow so the argument to it will be on top of
            // the stack, which we just assign to `memory_local_ix` with a local.tee
            // instruction.
            elems.extend_from_slice(&[
                LocalTee {
                    local_index: memory_local_ix,
                },
                update_available_memory_instr,
                LocalGet {
                    local_index: memory_local_ix,
                },
                I32Const {
                    value: element_size as i32,
                },
                Call {
                    function_index: InjectedImports::UpdateAvailableMemory as u32,
                },
            ]);
            last_injection_position = point + 1;
        }
        elems.extend_from_slice(&orig_elems[last_injection_position..]);
        func_body.instructions = elems;
    }
}

// This function scans through the Wasm code and creates an injection point
// at the beginning of every basic block (straight-line sequence of instructions
// with no branches) and before each bulk memory instruction. An injection point
// contains a "hint" about the context of every basic block, specifically if
// it's re-entrant or not. This version over-estimates the cost of code with
// returns and jumps.
fn injections_old(code: &[Operator]) -> Vec<InjectionPoint> {
    let mut res = Vec::new();
    let mut stack = Vec::new();
    use Operator::*;
    // The function itself is a re-entrant code block.
    let mut curr = InjectionPoint::new_static_cost(0, Scope::ReentrantBlockStart);
    for (position, i) in code.iter().enumerate() {
        curr.cost_detail.increment_cost(instruction_to_cost(i));
        match i {
            // Start of a re-entrant code block.
            Loop { .. } => {
                stack.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::ReentrantBlockStart);
            }
            // Start of a non re-entrant code block.
            If { .. } | Block { .. } => {
                stack.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::NonReentrantBlockStart);
            }
            // End of a code block but still more code left.
            Else | Br { .. } | BrIf { .. } | BrTable { .. } => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd);
            }
            // `End` signals the end of a code block. If there's nothing more on the stack, we've
            // gone through all the code.
            End => {
                res.push(curr);
                curr = match stack.pop() {
                    Some(val) => val,
                    None => break,
                };
            }
            // Bulk memory instructions require injected metering __before__ the instruction
            // executes so that size arguments can be read from the stack at runtime.
            MemoryFill { .. }
            | MemoryCopy { .. }
            | MemoryInit { .. }
            | TableCopy { .. }
            | TableInit { .. }
            | TableFill { .. } => {
                res.push(InjectionPoint::new_dynamic_cost(position));
            }
            // Nothing special to be done for other instructions.
            _ => (),
        }
    }

    res.sort_by_key(|k| k.position);
    res
}

// This function scans through the Wasm code and creates an injection point
// at the beginning of every basic block (straight-line sequence of instructions
// with no branches) and before each bulk memory instruction. An injection point
// contains a "hint" about the context of every basic block, specifically if
// it's re-entrant or not.
fn injections_new(code: &[Operator]) -> Vec<InjectionPoint> {
    let mut res = Vec::new();
    use Operator::*;
    // The function itself is a re-entrant code block.
    let mut curr = InjectionPoint::new_static_cost(0, Scope::ReentrantBlockStart);
    for (position, i) in code.iter().enumerate() {
        curr.cost_detail.increment_cost(instruction_to_cost_new(i));
        match i {
            // Start of a re-entrant code block.
            Loop { .. } => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::ReentrantBlockStart);
            }
            // Start of a non re-entrant code block.
            If { .. } => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::NonReentrantBlockStart);
            }
            // End of a code block but still more code left.
            Else | Br { .. } | BrIf { .. } | BrTable { .. } => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd);
            }
            End => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd);
            }
            Return | Unreachable | ReturnCall { .. } | ReturnCallIndirect { .. } => {
                res.push(curr);
                // This injection point will be unreachable itself (most likely empty)
                // but we create it to keep the algorithm uniform
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd);
            }
            // Bulk memory instructions require injected metering __before__ the instruction
            // executes so that size arguments can be read from the stack at runtime.
            MemoryFill { .. }
            | MemoryCopy { .. }
            | MemoryInit { .. }
            | TableCopy { .. }
            | TableInit { .. }
            | TableFill { .. } => {
                res.push(InjectionPoint::new_dynamic_cost(position));
            }
            // Nothing special to be done for other instructions.
            _ => (),
        }
    }

    res.sort_by_key(|k| k.position);
    res
}

// Looks for the data section and if it is present, converts it to a vector of
// tuples (heap offset, bytes) and then deletes the section.
fn get_data(
    data_section: &mut Vec<wasm_transform::DataSegment>,
) -> Result<Segments, WasmInstrumentationError> {
    let res = data_section
        .iter()
        .map(|segment| {
            let offset = match &segment.kind {
                wasm_transform::DataSegmentKind::Active {
                    memory_index: _,
                    offset_expr,
                } => match offset_expr {
                    Operator::I32Const { value } => *value as usize,
                    Operator::I64Const { value } => *value as usize,
                    _ => return Err(WasmInstrumentationError::WasmDeserializeError(WasmError::new(
                        "complex initialization expressions for data segments are not supported!".into()
                    ))),
                },

                _ => return Err(WasmInstrumentationError::WasmDeserializeError(
                    WasmError::new("no offset found for the data segment".into())
                )),
            };

            Ok((offset, segment.data.to_vec()))
        })
        .collect::<Result<_,_>>()?;

    data_section.clear();
    Ok(res)
}

fn export_table(mut module: Module) -> Module {
    let mut table_already_exported = false;
    for export in &mut module.exports {
        if let ExternalKind::Table = export.kind {
            table_already_exported = true;
            export.name = TABLE_STR;
        }
    }

    if !table_already_exported && !module.tables.is_empty() {
        let table_export = Export {
            name: TABLE_STR,
            kind: ExternalKind::Table,
            index: 0,
        };
        module.exports.push(table_export);
    }

    module
}

/// Exports existing memories and injects new memories. Returns the index of an
/// injected stable memory when using wasm-native stable memory. The bytemap for
/// the stable memory will always be inserted directly after the stable memory.
fn update_memories(
    mut module: Module,
    write_barrier: FlagStatus,
    wasm_native_stable_memory: FlagStatus,
    main_memory_mode: MemoryMode,
) -> (Module, u32) {
    let mut stable_index = 0;

    let mut memory_already_exported = false;
    for export in &mut module.exports {
        if let ExternalKind::Memory = export.kind {
            memory_already_exported = true;
            export.name = WASM_HEAP_MEMORY_NAME;
        }
    }

    if !memory_already_exported && !module.memories.is_empty() {
        let memory_export = Export {
            name: WASM_HEAP_MEMORY_NAME,
            kind: ExternalKind::Memory,
            index: 0,
        };
        module.exports.push(memory_export);
    }

    if (write_barrier == FlagStatus::Enabled || main_memory_mode == MemoryMode::Memory64)
        && !module.memories.is_empty()
    {
        module.memories.push(MemoryType {
            memory64: false,
            shared: false,
            initial: BYTEMAP_SIZE_IN_WASM_PAGES,
            maximum: Some(BYTEMAP_SIZE_IN_WASM_PAGES),
        });

        module.exports.push(Export {
            name: WASM_HEAP_BYTEMAP_MEMORY_NAME,
            kind: ExternalKind::Memory,
            index: 1,
        });
    }

    if wasm_native_stable_memory == FlagStatus::Enabled {
        stable_index = module.memories.len() as u32;
        module.memories.push(MemoryType {
            memory64: true,
            shared: false,
            initial: 0,
            maximum: Some(MAX_STABLE_MEMORY_IN_WASM_PAGES),
        });

        module.exports.push(Export {
            name: STABLE_MEMORY_NAME,
            kind: ExternalKind::Memory,
            index: stable_index,
        });

        module.memories.push(MemoryType {
            memory64: false,
            shared: false,
            initial: STABLE_BYTEMAP_SIZE_IN_WASM_PAGES,
            maximum: Some(STABLE_BYTEMAP_SIZE_IN_WASM_PAGES),
        });

        module.exports.push(Export {
            name: STABLE_BYTEMAP_MEMORY_NAME,
            kind: ExternalKind::Memory,
            // Bytemap for a memory needs to be placed at the next index after the memory
            index: stable_index + 1,
        })
    }

    (module, stable_index)
}

// Mutable globals must be exported to be persisted.
fn export_mutable_globals<'a>(
    mut module: Module<'a>,
    extra_data: &'a mut Vec<String>,
) -> Module<'a> {
    let mut mutable_exported: Vec<(bool, bool)> = module
        .globals
        .iter()
        .map(|g| g.ty.mutable)
        .zip(std::iter::repeat(false))
        .collect();

    for export in &module.exports {
        if let ExternalKind::Global = export.kind {
            mutable_exported[export.index as usize].1 = true;
        }
    }

    for (ix, (mutable, exported)) in mutable_exported.iter().enumerate() {
        if *mutable && !exported {
            extra_data.push(format!("__persistent_mutable_global_{}", ix));
        }
    }
    let mut iy = 0;
    for (ix, (mutable, exported)) in mutable_exported.into_iter().enumerate() {
        if mutable && !exported {
            let global_export = Export {
                name: extra_data[iy].as_str(),
                kind: ExternalKind::Global,
                index: ix as u32,
            };
            module.exports.push(global_export);
            iy += 1;
        }
    }

    module
}
