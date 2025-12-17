//! This module is responsible for instrumenting wasm binaries on the Internet
//! Computer.
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
//! (import "__" "try_grow_wasm_memory" (func (;1;) ((param i32 i32) (result i32))))
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
use ic_replicated_state::NumWasmPages;
use ic_sys::PAGE_SIZE;
use ic_types::NumBytes;
use ic_types::NumInstructions;
use ic_types::methods::WasmMethod;
use ic_wasm_types::{BinaryEncodedWasm, WasmError, WasmInstrumentationError};
use wirm::{
    DataType, InitInstr,
    ir::{
        function::FunctionBuilder,
        id::ImportsID,
        module::{
            LocalOrImport,
            module_functions::{FuncKind, Function},
            module_globals::GlobalKind,
        },
        types::{Body, InitExpr, Instructions, Value},
    },
};

use crate::wasmtime_embedder::{
    STABLE_BYTEMAP_MEMORY_NAME, STABLE_MEMORY_NAME, WASM_HEAP_MEMORY_NAME,
};

use std::collections::BTreeMap;
use std::convert::TryFrom;

const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;

#[derive(Clone, Copy, Debug)]
pub enum WasmMemoryType {
    Wasm32,
    Wasm64,
}

pub(crate) fn main_memory_type(module: &wirm::Module<'_>) -> WasmMemoryType {
    let mut mem_type = WasmMemoryType::Wasm32;
    if let Some(memory) = module.memories.iter().next()
        && memory.ty.memory64
    {
        mem_type = WasmMemoryType::Wasm64;
    }
    mem_type
}

pub(crate) struct InjectedFunctions {
    pub out_of_instructions: u32,
    pub try_grow_wasm_memory: u32,
    pub try_grow_stable_memory: u32,
    pub internal_trap: u32,
    pub stable_read_first_access: u32,
}

// Gets the cost of an instruction.
pub fn instruction_to_cost(i: &wirm::wasmparser::Operator, mem_type: WasmMemoryType) -> u64 {
    use wirm::wasmparser::Operator;

    // This aims to be a complete list of all instructions that can be executed, with certain exceptions.
    // The exceptions are: atomic instructions, and the dynamic cost of
    // of operations such as table/memory fill, copy, init. This
    // dynamic cost is treated separately. Here we only assign a static cost to these instructions.
    // Cost for certain instructions differ based on the memory type (Wasm32 vs. Wasm64).
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

        // Weights determined by benchmarking.
        // Simple float operations for both sizes.
        Operator::F32Abs { .. }
        | Operator::F32Neg { .. }
        | Operator::F64Abs { .. }
        | Operator::F64Neg { .. } => 1,
        Operator::F32Add { .. }
        | Operator::F32Sub { .. }
        | Operator::F32Mul { .. }
        | Operator::F32Ceil { .. }
        | Operator::F32Floor { .. }
        | Operator::F32Trunc { .. }
        | Operator::F32Nearest { .. }
        | Operator::F64Add { .. }
        | Operator::F64Sub { .. }
        | Operator::F64Mul { .. }
        | Operator::F64Ceil { .. }
        | Operator::F64Floor { .. }
        | Operator::F64Trunc { .. }
        | Operator::F64Nearest { .. } => 2,

        // Weights determined by benchmarking.
        // More expensive float operations for both sizes.
        Operator::F32Div { .. } => 3,
        Operator::F64Div { .. } => 5,
        Operator::F32Min { .. }
        | Operator::F32Max { .. }
        | Operator::F64Min { .. }
        | Operator::F64Max { .. } => 18,
        Operator::F32Copysign { .. } => 2,
        Operator::F64Copysign { .. } => 3,
        Operator::F32Sqrt { .. } => 5,
        Operator::F64Sqrt { .. } => 8,

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

        // All load/store instructions are of cost 1 in Wasm32 mode.
        // Validated in benchmarks.
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
        | Operator::I64Store32 { .. } => match mem_type {
            WasmMemoryType::Wasm32 => 1,
            WasmMemoryType::Wasm64 => 2,
        },

        // Global get/set operations are similarly expensive to loads/stores.
        Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => 2,

        // TableGet and TableSet are expensive operations because they
        // are translated into memory manipulation operations.
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
        Operator::MemorySize { .. } => 20,
        Operator::TableSize { .. } => 100,

        // Bulk memory ops are of cost 100. They are heavy operations because
        // they are translated into function calls in the x86 disassembly. Validated
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
        // The cost is adjusted to 5 and 10 after benchmarking with real canisters.
        Operator::Call { .. } => 5,
        Operator::CallIndirect { .. } => 10,

        // ReturnCall is on average approx. 1.5 times faster than Call
        // instruction (shown by relative benchmarks).
        Operator::ReturnCall { .. } => 3,
        Operator::ReturnCallIndirect { .. } => 60,

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

        ////////////////////////////////////////////////////////////////
        // Wasm SIMD Operators

        // Load/store for SIMD cost 1 in Wasm32 mode and 2 in Wasm64 mode.
        Operator::V128Load { .. }
        | Operator::V128Load8x8S { .. }
        | Operator::V128Load8x8U { .. }
        | Operator::V128Load16x4S { .. }
        | Operator::V128Load16x4U { .. }
        | Operator::V128Load32x2S { .. }
        | Operator::V128Load32x2U { .. }
        | Operator::V128Load8Splat { .. }
        | Operator::V128Load16Splat { .. }
        | Operator::V128Load32Splat { .. }
        | Operator::V128Load64Splat { .. }
        | Operator::V128Load32Zero { .. }
        | Operator::V128Load64Zero { .. }
        | Operator::V128Store { .. }
        | Operator::V128Load8Lane { .. }
        | Operator::V128Load16Lane { .. }
        | Operator::V128Load32Lane { .. }
        | Operator::V128Load64Lane { .. }
        | Operator::V128Store8Lane { .. }
        | Operator::V128Store16Lane { .. }
        | Operator::V128Store32Lane { .. }
        | Operator::V128Store64Lane { .. } => match mem_type {
            WasmMemoryType::Wasm32 => 1,
            WasmMemoryType::Wasm64 => 2,
        },

        Operator::V128Const { .. } => 1,
        Operator::I8x16Shuffle { .. } => 3,
        Operator::I8x16ExtractLaneS { .. } => 1,
        Operator::I8x16ExtractLaneU { .. } => 1,
        Operator::I8x16ReplaceLane { .. } => 1,
        Operator::I16x8ExtractLaneS { .. } => 1,
        Operator::I16x8ExtractLaneU { .. } => 1,
        Operator::I16x8ReplaceLane { .. } => 1,
        Operator::I32x4ExtractLane { .. } => 1,
        Operator::I32x4ReplaceLane { .. } => 1,
        Operator::I64x2ExtractLane { .. } => 1,
        Operator::I64x2ReplaceLane { .. } => 1,
        Operator::F32x4ExtractLane { .. } => 1,
        Operator::F32x4ReplaceLane { .. } => 1,
        Operator::F64x2ExtractLane { .. } => 1,
        Operator::F64x2ReplaceLane { .. } => 1,
        Operator::I8x16Swizzle { .. } => 1,
        Operator::I8x16Splat { .. } => 1,
        Operator::I16x8Splat { .. } => 1,
        Operator::I32x4Splat { .. } => 1,
        Operator::I64x2Splat { .. } => 1,
        Operator::F32x4Splat { .. } => 1,
        Operator::F64x2Splat { .. } => 1,
        Operator::I8x16Eq { .. } => 1,
        Operator::I8x16Ne { .. } => 1,
        Operator::I8x16LtS { .. } => 1,
        Operator::I8x16LtU { .. } => 2,
        Operator::I8x16GtS { .. } => 1,
        Operator::I8x16GtU { .. } => 2,
        Operator::I8x16LeS { .. } => 1,
        Operator::I8x16LeU { .. } => 1,
        Operator::I8x16GeS { .. } => 1,
        Operator::I8x16GeU { .. } => 1,
        Operator::I16x8Eq { .. } => 1,
        Operator::I16x8Ne { .. } => 1,
        Operator::I16x8LtS { .. } => 1,
        Operator::I16x8LtU { .. } => 2,
        Operator::I16x8GtS { .. } => 1,
        Operator::I16x8GtU { .. } => 2,
        Operator::I16x8LeS { .. } => 1,
        Operator::I16x8LeU { .. } => 1,
        Operator::I16x8GeS { .. } => 1,
        Operator::I16x8GeU { .. } => 1,
        Operator::I32x4Eq { .. } => 1,
        Operator::I32x4Ne { .. } => 1,
        Operator::I32x4LtS { .. } => 1,
        Operator::I32x4LtU { .. } => 2,
        Operator::I32x4GtS { .. } => 1,
        Operator::I32x4GtU { .. } => 2,
        Operator::I32x4LeS { .. } => 1,
        Operator::I32x4LeU { .. } => 1,
        Operator::I32x4GeS { .. } => 1,
        Operator::I32x4GeU { .. } => 1,
        Operator::I64x2Eq { .. } => 1,
        Operator::I64x2Ne { .. } => 1,
        Operator::I64x2LtS { .. } => 1,
        Operator::I64x2GtS { .. } => 1,
        Operator::I64x2LeS { .. } => 1,
        Operator::I64x2GeS { .. } => 1,
        Operator::F32x4Eq { .. } => 1,
        Operator::F32x4Ne { .. } => 1,
        Operator::F32x4Lt { .. } => 1,
        Operator::F32x4Gt { .. } => 1,
        Operator::F32x4Le { .. } => 1,
        Operator::F32x4Ge { .. } => 1,
        Operator::F64x2Eq { .. } => 1,
        Operator::F64x2Ne { .. } => 1,
        Operator::F64x2Lt { .. } => 1,
        Operator::F64x2Gt { .. } => 1,
        Operator::F64x2Le { .. } => 1,
        Operator::F64x2Ge { .. } => 1,
        Operator::V128Not { .. } => 1,
        Operator::V128And { .. } => 1,
        Operator::V128AndNot { .. } => 1,
        Operator::V128Or { .. } => 1,
        Operator::V128Xor { .. } => 1,
        Operator::V128Bitselect { .. } => 1,
        Operator::V128AnyTrue { .. } => 1,
        Operator::I8x16Abs { .. } => 1,
        Operator::I8x16Neg { .. } => 1,
        Operator::I8x16Popcnt { .. } => 3,
        Operator::I8x16AllTrue { .. } => 1,
        Operator::I8x16Bitmask { .. } => 1,
        Operator::I8x16NarrowI16x8S { .. } => 1,
        Operator::I8x16NarrowI16x8U { .. } => 1,
        Operator::I8x16Shl { .. } => 3,
        Operator::I8x16ShrS { .. } => 3,
        Operator::I8x16ShrU { .. } => 2,
        Operator::I8x16Add { .. } => 1,
        Operator::I8x16AddSatS { .. } => 1,
        Operator::I8x16AddSatU { .. } => 1,
        Operator::I8x16Sub { .. } => 1,
        Operator::I8x16SubSatS { .. } => 1,
        Operator::I8x16SubSatU { .. } => 1,
        Operator::I8x16MinS { .. } => 1,
        Operator::I8x16MinU { .. } => 1,
        Operator::I8x16MaxS { .. } => 1,
        Operator::I8x16MaxU { .. } => 1,
        Operator::I8x16AvgrU { .. } => 1,
        Operator::I16x8ExtAddPairwiseI8x16S { .. } => 1,
        Operator::I16x8ExtAddPairwiseI8x16U { .. } => 2,
        Operator::I16x8Abs { .. } => 1,
        Operator::I16x8Neg { .. } => 1,
        Operator::I16x8Q15MulrSatS { .. } => 1,
        Operator::I16x8AllTrue { .. } => 1,
        Operator::I16x8Bitmask { .. } => 1,
        Operator::I16x8NarrowI32x4S { .. } => 1,
        Operator::I16x8NarrowI32x4U { .. } => 1,
        Operator::I16x8ExtendLowI8x16S { .. } => 1,
        Operator::I16x8ExtendHighI8x16S { .. } => 1,
        Operator::I16x8ExtendLowI8x16U { .. } => 1,
        Operator::I16x8ExtendHighI8x16U { .. } => 1,
        Operator::I16x8Shl { .. } => 2,
        Operator::I16x8ShrS { .. } => 2,
        Operator::I16x8ShrU { .. } => 2,
        Operator::I16x8Add { .. } => 1,
        Operator::I16x8AddSatS { .. } => 1,
        Operator::I16x8AddSatU { .. } => 1,
        Operator::I16x8Sub { .. } => 1,
        Operator::I16x8SubSatS { .. } => 1,
        Operator::I16x8SubSatU { .. } => 1,
        Operator::I16x8Mul { .. } => 1,
        Operator::I16x8MinS { .. } => 1,
        Operator::I16x8MinU { .. } => 1,
        Operator::I16x8MaxS { .. } => 1,
        Operator::I16x8MaxU { .. } => 1,
        Operator::I16x8AvgrU { .. } => 1,
        Operator::I16x8ExtMulLowI8x16S { .. } => 1,
        Operator::I16x8ExtMulHighI8x16S { .. } => 2,
        Operator::I16x8ExtMulLowI8x16U { .. } => 1,
        Operator::I16x8ExtMulHighI8x16U { .. } => 2,
        Operator::I32x4ExtAddPairwiseI16x8S { .. } => 1,
        Operator::I32x4ExtAddPairwiseI16x8U { .. } => 3,
        Operator::I32x4Abs { .. } => 1,
        Operator::I32x4Neg { .. } => 1,
        Operator::I32x4AllTrue { .. } => 1,
        Operator::I32x4Bitmask { .. } => 1,
        Operator::I32x4ExtendLowI16x8S { .. } => 1,
        Operator::I32x4ExtendHighI16x8S { .. } => 1,
        Operator::I32x4ExtendLowI16x8U { .. } => 1,
        Operator::I32x4ExtendHighI16x8U { .. } => 1,
        Operator::I32x4Shl { .. } => 2,
        Operator::I32x4ShrS { .. } => 2,
        Operator::I32x4ShrU { .. } => 2,
        Operator::I32x4Add { .. } => 1,
        Operator::I32x4Sub { .. } => 1,
        Operator::I32x4Mul { .. } => 2,
        Operator::I32x4MinS { .. } => 1,
        Operator::I32x4MinU { .. } => 1,
        Operator::I32x4MaxS { .. } => 1,
        Operator::I32x4MaxU { .. } => 1,
        Operator::I32x4DotI16x8S { .. } => 1,
        Operator::I32x4ExtMulLowI16x8S { .. } => 2,
        Operator::I32x4ExtMulHighI16x8S { .. } => 2,
        Operator::I32x4ExtMulLowI16x8U { .. } => 2,
        Operator::I32x4ExtMulHighI16x8U { .. } => 2,
        Operator::I64x2Abs { .. } => 1,
        Operator::I64x2Neg { .. } => 1,
        Operator::I64x2AllTrue { .. } => 1,
        Operator::I64x2Bitmask { .. } => 1,
        Operator::I64x2ExtendLowI32x4S { .. } => 1,
        Operator::I64x2ExtendHighI32x4S { .. } => 1,
        Operator::I64x2ExtendLowI32x4U { .. } => 1,
        Operator::I64x2ExtendHighI32x4U { .. } => 1,
        Operator::I64x2Shl { .. } => 2,
        Operator::I64x2ShrS { .. } => 3,
        Operator::I64x2ShrU { .. } => 2,
        Operator::I64x2Add { .. } => 1,
        Operator::I64x2Sub { .. } => 1,
        Operator::I64x2Mul { .. } => 4,
        Operator::I64x2ExtMulLowI32x4S { .. } => 1,
        Operator::I64x2ExtMulHighI32x4S { .. } => 1,
        Operator::I64x2ExtMulLowI32x4U { .. } => 1,
        Operator::I64x2ExtMulHighI32x4U { .. } => 1,
        Operator::F32x4Ceil { .. } => 2,
        Operator::F32x4Floor { .. } => 2,
        Operator::F32x4Trunc { .. } => 2,
        Operator::F32x4Nearest { .. } => 2,
        Operator::F32x4Abs { .. } => 2,
        Operator::F32x4Neg { .. } => 2,
        Operator::F32x4Sqrt { .. } => 5,
        Operator::F32x4Add { .. } => 2,
        Operator::F32x4Sub { .. } => 2,
        Operator::F32x4Mul { .. } => 2,
        Operator::F32x4Div { .. } => 10,
        Operator::F32x4Min { .. } => 4,
        Operator::F32x4Max { .. } => 4,
        Operator::F32x4PMin { .. } => 1,
        Operator::F32x4PMax { .. } => 1,
        Operator::F64x2Ceil { .. } => 2,
        Operator::F64x2Floor { .. } => 2,
        Operator::F64x2Trunc { .. } => 2,
        Operator::F64x2Nearest { .. } => 2,
        Operator::F64x2Abs { .. } => 2,
        Operator::F64x2Neg { .. } => 2,
        Operator::F64x2Sqrt { .. } => 14,
        Operator::F64x2Add { .. } => 2,
        Operator::F64x2Sub { .. } => 2,
        Operator::F64x2Mul { .. } => 2,
        Operator::F64x2Div { .. } => 12,
        Operator::F64x2Min { .. } => 4,
        Operator::F64x2Max { .. } => 5,
        Operator::F64x2PMin { .. } => 1,
        Operator::F64x2PMax { .. } => 1,
        Operator::I32x4TruncSatF32x4S { .. } => 2,
        Operator::I32x4TruncSatF32x4U { .. } => 4,
        Operator::F32x4ConvertI32x4S { .. } => 1,
        Operator::F32x4ConvertI32x4U { .. } => 4,
        Operator::I32x4TruncSatF64x2SZero { .. } => 2,
        Operator::I32x4TruncSatF64x2UZero { .. } => 3,
        Operator::F64x2ConvertLowI32x4S { .. } => 1,
        Operator::F64x2ConvertLowI32x4U { .. } => 1,
        Operator::F32x4DemoteF64x2Zero { .. } => 1,
        Operator::F64x2PromoteLowF32x4 { .. } => 1,

        // Default cost of an instruction is 1.
        _ => 1,
    }
}

const INSTRUMENTED_FUN_MODULE: &str = "__";
const OUT_OF_INSTRUCTIONS_FUN_NAME: &str = "out_of_instructions";
const TRY_GROW_WASM_MEMORY_FUN_NAME: &str = "try_grow_wasm_memory";
const TRY_GROW_STABLE_MEMORY_FUN_NAME: &str = "try_grow_stable_memory";
const INTERNAL_TRAP_FUN_NAME: &str = "internal_trap";
const STABLE_READ_FIRST_ACCESS_NAME: &str = "stable_read_first_access";
const TABLE_STR: &str = "table";
pub(crate) const INSTRUCTIONS_COUNTER_GLOBAL_NAME: &str = "canister counter_instructions";
pub(crate) const DIRTY_PAGES_COUNTER_GLOBAL_NAME: &str = "canister counter_dirty_pages";
pub(crate) const ACCESSED_PAGES_COUNTER_GLOBAL_NAME: &str = "canister counter_accessed_pages";
const CANISTER_START_STR: &str = "canister_start";

/// There is one byte for each OS page in the memory.
fn bytemap_size_in_wasm_pages(memory_size: NumBytes) -> u64 {
    memory_size.get() / (PAGE_SIZE as u64) / (WASM_PAGE_SIZE as u64)
}

fn max_memory_size_in_wasm_pages(memory_size: NumBytes) -> u64 {
    memory_size.get() / (WASM_PAGE_SIZE as u64)
}

/// Injects hidden api functions.
///
/// Note that these functions are injected as the first imports, so that we
/// can increment all function indices unconditionally. (If they would be
/// added as the last imports, we'd need to increment only non imported
/// functions, since imported functions precede all others in the function index
/// space, but this would be error-prone).
fn inject_helper_functions(
    module: &mut wirm::Module,
    mem_type: WasmMemoryType,
) -> InjectedFunctions {
    let ooi_type_idx = module.types.add_func_type(&[], &[]);
    let (out_of_instructions_fn_id, _) = module.add_import_func(
        INSTRUMENTED_FUN_MODULE.to_string(),
        OUT_OF_INSTRUCTIONS_FUN_NAME.to_string(),
        ooi_type_idx,
    );

    let (params, res) = match mem_type {
        WasmMemoryType::Wasm32 => ([DataType::I32, DataType::I32], [DataType::I32]),
        WasmMemoryType::Wasm64 => ([DataType::I64, DataType::I64], [DataType::I64]),
    };
    let tgwm_type_idx = module.types.add_func_type(&params, &res);
    let (try_grow_wasm_memory_fn_id, _) = module.add_import_func(
        INSTRUMENTED_FUN_MODULE.to_string(),
        TRY_GROW_WASM_MEMORY_FUN_NAME.to_string(),
        tgwm_type_idx,
    );

    let tgsm_type_idx = module.types.add_func_type(
        &[DataType::I64, DataType::I64, DataType::I32],
        &[DataType::I64],
    );
    let (try_grow_stable_memory_fn_id, _) = module.add_import_func(
        INSTRUMENTED_FUN_MODULE.to_string(),
        TRY_GROW_STABLE_MEMORY_FUN_NAME.to_string(),
        tgsm_type_idx,
    );

    let it_type_idx = module.types.add_func_type(&[DataType::I32], &[]);
    let (internal_trap_fn_id, _) = module.add_import_func(
        INSTRUMENTED_FUN_MODULE.to_string(),
        INTERNAL_TRAP_FUN_NAME.to_string(),
        it_type_idx,
    );

    let fr_type_idx = module
        .types
        .add_func_type(&[DataType::I64, DataType::I64, DataType::I64], &[]);
    let (stable_read_first_access_fn_id, _) = module.add_import_func(
        INSTRUMENTED_FUN_MODULE.to_string(),
        STABLE_READ_FIRST_ACCESS_NAME.to_string(),
        fr_type_idx,
    );

    InjectedFunctions {
        out_of_instructions: *out_of_instructions_fn_id,
        try_grow_wasm_memory: *try_grow_wasm_memory_fn_id,
        try_grow_stable_memory: *try_grow_stable_memory_fn_id,
        internal_trap: *internal_trap_fn_id,
        stable_read_first_access: *stable_read_first_access_fn_id,
    }
}

/// Indices for injected counters and functions to update them.
pub(super) struct InjectedCounters {
    pub instructions_counter: u32,
    pub dirty_pages_counter: u32,
    pub accessed_pages_counter: u32,
    /// Function to decrement the instruction counter.
    pub decr_instruction_counter_fn: u32,
    /// Function to count clean pages.
    pub count_clean_pages_fn: u32,
}

fn export_table(mut module: wirm::Module) -> wirm::Module {
    let mut table_already_exported = false;
    for export in module.exports.iter_mut() {
        if let wirm::wasmparser::ExternalKind::Table = export.kind {
            table_already_exported = true;
            export.name = TABLE_STR.to_string();
        }
    }

    if !table_already_exported && !module.tables.is_empty() {
        module.exports.add_export_table(TABLE_STR.to_string(), 0);
    }

    module
}

/// Exports existing memories and injects new memories. Returns the index of an
/// injected stable memory when using wasm-native stable memory. The bytemap for
/// the stable memory will always be inserted directly after the stable memory.
///
/// This function is also responsible for inserting maximum memory limits for all
/// defined memories. Checks in the system API will only check against dynamic
/// limits so we need to impose global limits for 32-bit heap, 64-bit heap, and
/// stable memory here.
fn update_memories(
    mut module: wirm::Module,
    max_wasm_memory_size: NumBytes,
    max_stable_memory_size: NumBytes,
) -> (wirm::Module, u32) {
    if let Some(mem) = module.memories.iter_mut().next() {
        let max_wasm_memory_size_in_wasm_pages =
            max_memory_size_in_wasm_pages(max_wasm_memory_size);
        match mem.ty.maximum {
            Some(max) => {
                // In case the maximum memory size is larger than the maximum allowed, cap it.
                if max > max_wasm_memory_size_in_wasm_pages {
                    mem.ty.maximum = Some(max_wasm_memory_size_in_wasm_pages);
                }
            }
            None => {
                mem.ty.maximum = Some(max_wasm_memory_size_in_wasm_pages);
            }
        }
    }

    let mut memory_already_exported = false;
    for export in module.exports.iter_mut() {
        if let wirm::wasmparser::ExternalKind::Memory = export.kind {
            memory_already_exported = true;
            export.name = WASM_HEAP_MEMORY_NAME.to_string();
        }
    }

    if !memory_already_exported && !module.memories.is_empty() {
        module
            .exports
            .add_export_mem(WASM_HEAP_MEMORY_NAME.to_string(), 0);
    }

    let stable_index = module.add_local_memory(wirm::wasmparser::MemoryType {
        memory64: true,
        shared: false,
        initial: 0,
        maximum: Some(max_memory_size_in_wasm_pages(max_stable_memory_size)),
        page_size_log2: None,
    });

    module
        .exports
        .add_export_mem(STABLE_MEMORY_NAME.to_string(), *stable_index);

    let stable_bytemap_size_in_wasm_pages = bytemap_size_in_wasm_pages(max_stable_memory_size);
    let stable_bytemap_index = module.add_local_memory(wirm::wasmparser::MemoryType {
        memory64: false,
        shared: false,
        initial: stable_bytemap_size_in_wasm_pages,
        maximum: Some(stable_bytemap_size_in_wasm_pages),
        page_size_log2: None,
    });

    module.exports.add_export_mem(
        STABLE_BYTEMAP_MEMORY_NAME.to_string(),
        *stable_bytemap_index,
    );

    (module, *stable_index)
}

// Mutable globals must be exported to be persisted.
fn export_mutable_globals<'a>(mut module: wirm::Module<'a>) -> wirm::Module<'a> {
    let mut mutable_exported: Vec<(bool, bool)> = module
        .globals
        .iter()
        .map(|g| match g.kind() {
            GlobalKind::Local(local_global) => local_global.ty.mutable,
            GlobalKind::Import(imported_global) => imported_global.ty.mutable,
        })
        .zip(std::iter::repeat(false))
        .collect();

    for export in module.exports.iter() {
        if let wirm::wasmparser::ExternalKind::Global = export.kind {
            mutable_exported[export.index as usize].1 = true;
        }
    }

    for (ix, (mutable, exported)) in mutable_exported.into_iter().enumerate() {
        if mutable && !exported {
            module
                .exports
                .add_export_global(format!("__persistent_mutable_global_{}", ix), ix as u32);
        }
    }

    module
}

// Helper function used by instrumentation to export additional symbols.
//
// Returns the new module or panics in debug mode if a symbol is not reserved.
fn export_additional_symbols<'a>(
    mut module: wirm::Module<'a>,
    injected_functions: &InjectedFunctions,
    stable_memory_index: u32,
) -> (InjectedCounters, wirm::Module<'a>) {
    use wirm::wasmparser::{BlockType, Operator::*, ValType};

    // push the instructions counter
    let instructions_counter = *module.add_global(
        InitExpr::new(vec![InitInstr::Value(Value::I64(0))]),
        DataType::I64,
        true,
        false,
    );

    // push the dirty page counter
    let dirty_pages_counter = *module.add_global(
        InitExpr::new(vec![InitInstr::Value(Value::I64(0))]),
        DataType::I64,
        true,
        false,
    );

    // push the accessed page counter
    let accessed_pages_counter = *module.add_global(
        InitExpr::new(vec![InitInstr::Value(Value::I64(0))]),
        DataType::I64,
        true,
        false,
    );

    // push function to decrement the instruction counter
    let instructions = vec![
        // Subtract the parameter amount from the instruction counter
        GlobalGet {
            global_index: instructions_counter,
        },
        LocalGet { local_index: 0 },
        I64Sub,
        // Store the new counter value in the local
        LocalTee { local_index: 1 },
        // If `new_counter > old_counter` there was underflow, so set counter to
        // minimum value. Otherwise set it to the new counter value.
        GlobalGet {
            global_index: instructions_counter,
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
            global_index: instructions_counter,
        },
        // Call out_of_instructions() if `new_counter < 0`.
        GlobalGet {
            global_index: instructions_counter,
        },
        I64Const { value: 0 },
        I64LtS,
        If {
            blockty: BlockType::Empty,
        },
        Call {
            function_index: injected_functions.out_of_instructions,
        },
        End,
        // Return the original param so this function doesn't alter the stack
        LocalGet { local_index: 0 },
    ];

    let num_instructions = instructions.len();
    let body = Body {
        locals: vec![(1, DataType::I64)],
        num_locals: 1,
        instructions: Instructions::new(instructions),
        num_instructions,
        name: None,
    };

    let mut builder = FunctionBuilder::new(&[DataType::I64], &[DataType::I64]);
    builder.body = body;
    let decr_instruction_counter_fn_id = builder.finish_module(&mut module);

    // function to count clean pages in a given range
    // Arg 0 - start of the range
    // Arg 1 - end of the range
    // Return index 0 is the number of pages that haven't been written to in the given range
    // Return index 1 is the number of pages that haven't been accessed in the given range.
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
            memarg: wirm::wasmparser::MemArg {
                align: 0,
                max_align: 0,
                offset: 0,
                // We assume the bytemap for stable memory is always
                // inserted directly after the stable memory.
                memory: stable_memory_index + 1,
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
    ];

    let num_instructions = instructions.len();
    let body = Body {
        locals: vec![(4, DataType::I32)],
        num_locals: 4,
        instructions: Instructions::new(instructions),
        num_instructions,
        name: None,
    };
    let mut builder = FunctionBuilder::new(
        &[DataType::I32, DataType::I32],
        &[DataType::I32, DataType::I32],
    );
    builder.body = body;
    let count_clean_pages_fn_id = builder.finish_module(&mut module);

    // globals must be exported to be accessible to hypervisor or persisted
    debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&INSTRUCTIONS_COUNTER_GLOBAL_NAME));
    module.exports.add_export_global(
        INSTRUCTIONS_COUNTER_GLOBAL_NAME.to_string(),
        instructions_counter,
    );

    debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&DIRTY_PAGES_COUNTER_GLOBAL_NAME));
    module.exports.add_export_global(
        DIRTY_PAGES_COUNTER_GLOBAL_NAME.to_string(),
        dirty_pages_counter,
    );

    debug_assert!(
        super::validation::RESERVED_SYMBOLS.contains(&ACCESSED_PAGES_COUNTER_GLOBAL_NAME)
    );
    module.exports.add_export_global(
        ACCESSED_PAGES_COUNTER_GLOBAL_NAME.to_string(),
        accessed_pages_counter,
    );

    if let Some(index) = module.start.map(|s| s.0) {
        // push canister_start
        debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&CANISTER_START_STR));
        module
            .exports
            .add_export_func(CANISTER_START_STR.to_string(), index)
    }

    (
        InjectedCounters {
            instructions_counter,
            dirty_pages_counter,
            accessed_pages_counter,
            decr_instruction_counter_fn: *decr_instruction_counter_fn_id,
            count_clean_pages_fn: *count_clean_pages_fn_id,
        },
        module,
    )
}

// Represents a hint about the context of each static cost injection point in
// wasm.
#[derive(Copy, Clone, PartialEq, Debug)]
enum Scope {
    ReentrantBlockStart,
    NonReentrantBlockStart,
    BlockEnd,
}

// Represents the type of the cost operand on the stack.
// Needed to determine the correct instruction to decrement the instruction counter.
#[derive(Copy, Clone, PartialEq, Debug)]
enum CostOperandOnStack {
    X32Bit,
    X64Bit,
}
// Describes how to calculate the instruction cost at this injection point.
// `StaticCost` injection points contain information about the cost of the
// following basic block. `DynamicCost` injection points assume there is an i32
// on the stack which should be decremented from the instruction counter.
#[derive(Copy, Clone, PartialEq, Debug)]
enum InjectionPointCostDetail {
    StaticCost {
        scope: Scope,
        cost: u64,
    },
    DynamicCost {
        operand_on_stack: CostOperandOnStack,
    },
}

impl InjectionPointCostDetail {
    /// If the cost is statically known, increment it by the given amount.
    /// Otherwise do nothing.
    fn increment_cost(&mut self, additional_cost: u64) {
        match self {
            Self::StaticCost { scope: _, cost } => *cost += additional_cost,
            Self::DynamicCost { .. } => {}
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
    fn new_static_cost(position: usize, scope: Scope, cost: u64) -> Self {
        InjectionPoint {
            cost_detail: InjectionPointCostDetail::StaticCost { scope, cost },
            position,
        }
    }

    fn new_dynamic_cost(position: usize, operand_on_stack: CostOperandOnStack) -> Self {
        InjectionPoint {
            cost_detail: InjectionPointCostDetail::DynamicCost { operand_on_stack },
            position,
        }
    }
}

// This function scans through the Wasm code and creates an injection point
// at the beginning of every basic block (straight-line sequence of instructions
// with no branches) and before each bulk memory instruction. An injection point
// contains a "hint" about the context of every basic block, specifically if
// it's re-entrant or not.
fn injections(
    code: &[wirm::wasmparser::Operator],
    mem_type: WasmMemoryType,
) -> Vec<InjectionPoint> {
    let mut res = Vec::new();
    use wirm::wasmparser::Operator::*;
    // The function itself is a re-entrant code block.
    // Start with at least one fuel being consumed because even empty
    // functions should consume at least some fuel.
    let mut curr = InjectionPoint::new_static_cost(0, Scope::ReentrantBlockStart, 1);
    for (position, i) in code.iter().enumerate() {
        curr.cost_detail
            .increment_cost(instruction_to_cost(i, mem_type));
        match i {
            // Start of a re-entrant code block.
            Loop { .. } => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::ReentrantBlockStart, 0);
            }
            // Start of a non re-entrant code block.
            If { .. } => {
                res.push(curr);
                curr =
                    InjectionPoint::new_static_cost(position + 1, Scope::NonReentrantBlockStart, 0);
            }
            // End of a code block but still more code left.
            Else | Br { .. } | BrIf { .. } | BrTable { .. } => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd, 0);
            }
            End => {
                res.push(curr);
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd, 0);
            }
            Return | Unreachable | ReturnCall { .. } | ReturnCallIndirect { .. } => {
                res.push(curr);
                // This injection point will be unreachable itself (most likely empty)
                // but we create it to keep the algorithm uniform
                curr = InjectionPoint::new_static_cost(position + 1, Scope::BlockEnd, 0);
            }
            // Bulk memory instructions require injected metering __before__ the instruction
            // executes so that size arguments can be read from the stack at runtime.
            MemoryFill { .. } | MemoryCopy { .. } | TableCopy { .. } | TableFill { .. } => {
                match mem_type {
                    WasmMemoryType::Wasm32 => {
                        // These ops in Wasm32 will need to extend the i32 to i64.
                        res.push(InjectionPoint::new_dynamic_cost(
                            position,
                            CostOperandOnStack::X32Bit,
                        ));
                    }
                    WasmMemoryType::Wasm64 => {
                        res.push(InjectionPoint::new_dynamic_cost(
                            position,
                            CostOperandOnStack::X64Bit,
                        ));
                    }
                }
            }
            // MemoryInit and TableInit have i32 arguments even in 64-bit mode.
            MemoryInit { .. } | TableInit { .. } => {
                res.push(InjectionPoint::new_dynamic_cost(
                    position,
                    CostOperandOnStack::X32Bit,
                ));
            }
            // Nothing special to be done for other instructions.
            _ => (),
        }
    }

    res.sort_by_key(|k| k.position);
    res
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
    body: &mut wirm::ir::types::Body,
    injected_counters: &InjectedCounters,
    injected_functions: &InjectedFunctions,
    metering_type: MeteringType,
    mem_type: WasmMemoryType,
) {
    let points = match metering_type {
        MeteringType::None => Vec::new(),
        MeteringType::New => injections(body.instructions.get_ops(), mem_type),
    };
    let points = points.iter().filter(|point| match point.cost_detail {
        InjectionPointCostDetail::StaticCost {
            scope: Scope::ReentrantBlockStart,
            cost: _,
        } => true,
        InjectionPointCostDetail::StaticCost { scope: _, cost } => cost > 0,
        InjectionPointCostDetail::DynamicCost { .. } => true,
    });
    let orig_elems = body.instructions.get_ops_mut();
    let mut elems: Vec<wirm::wasmparser::Operator> = Vec::new();
    let mut last_injection_position = 0;

    use wirm::wasmparser::Operator::*;

    for point in points {
        elems.extend_from_slice(&orig_elems[last_injection_position..point.position]);
        match point.cost_detail {
            InjectionPointCostDetail::StaticCost { scope, cost } => {
                elems.extend([
                    GlobalGet {
                        global_index: injected_counters.instructions_counter,
                    },
                    I64Const { value: cost as i64 },
                    I64Sub,
                    GlobalSet {
                        global_index: injected_counters.instructions_counter,
                    },
                ]);
                if scope == Scope::ReentrantBlockStart {
                    elems.extend([
                        GlobalGet {
                            global_index: injected_counters.instructions_counter,
                        },
                        I64Const { value: 0 },
                        I64LtS,
                        If {
                            blockty: wirm::wasmparser::BlockType::Empty,
                        },
                        Call {
                            function_index: injected_functions.out_of_instructions,
                        },
                        End,
                    ]);
                }
            }
            InjectionPointCostDetail::DynamicCost { operand_on_stack } => {
                match operand_on_stack {
                    CostOperandOnStack::X64Bit => {
                        elems.extend([Call {
                            function_index: injected_counters.decr_instruction_counter_fn,
                        }]);
                    }
                    CostOperandOnStack::X32Bit => {
                        elems.extend([
                            I64ExtendI32U,
                            Call {
                                function_index: injected_counters.decr_instruction_counter_fn,
                            },
                            // decr_instruction_counter returns its argument unchanged,
                            // so we can convert back to I32 without worrying about
                            // overflows.
                            I32WrapI64,
                        ]);
                    }
                }
            }
        }
        last_injection_position = point.position;
    }
    elems.extend_from_slice(&orig_elems[last_injection_position..]);
    let num_instructions = elems.len();
    *orig_elems = elems;
    body.num_instructions = num_instructions;
}

// Scans through the function and adds instrumentation after each `memory.grow`
// instruction to make sure that there's enough available memory left to support
// the requested extra memory.
fn inject_try_grow_wasm_memory(
    func_body: &mut wirm::ir::types::Body,
    num_params: u32,
    mem_type: WasmMemoryType,
    injected_functions: &InjectedFunctions,
) {
    use wirm::wasmparser::Operator::*;
    let mut injection_points: Vec<usize> = Vec::new();
    {
        for (idx, instr) in func_body.instructions.get_ops().iter().enumerate() {
            if let MemoryGrow { .. } = instr {
                injection_points.push(idx);
            }
        }
    }

    // If we found any injection points, we need to instrument the code.
    if !injection_points.is_empty() {
        // We inject a local to cache the argument to `memory.grow`.
        // The locals are stored as a vector of (count, ValType), so summing
        // over the first field gives the total number of locals.
        let n_locals: u32 = func_body.locals.iter().map(|x| x.0).sum();
        let memory_local_ix = num_params + n_locals;
        match mem_type {
            WasmMemoryType::Wasm32 => func_body.locals.push((1, DataType::I32)),
            WasmMemoryType::Wasm64 => func_body.locals.push((1, DataType::I64)),
        };

        let orig_elems = func_body.instructions.get_ops_mut();
        let mut elems: Vec<wirm::wasmparser::Operator> = Vec::new();
        let mut last_injection_position = 0;
        for point in injection_points {
            let memory_grow_instr = orig_elems[point].clone();
            elems.extend_from_slice(&orig_elems[last_injection_position..point]);
            // At this point we have a memory.grow so the argument to it will be on top of
            // the stack, which we just assign to `memory_local_ix` with a local.tee
            // instruction.
            elems.extend([
                LocalTee {
                    local_index: memory_local_ix,
                },
                memory_grow_instr,
                LocalGet {
                    local_index: memory_local_ix,
                },
                Call {
                    function_index: injected_functions.try_grow_wasm_memory,
                },
            ]);
            last_injection_position = point + 1;
        }
        elems.extend_from_slice(&orig_elems[last_injection_position..]);
        let num_instructions = elems.len();
        func_body.instructions = Instructions::new(elems);
        func_body.num_instructions = num_instructions;
    }
}

fn calculate_api_indexes(module: &wirm::Module<'_>) -> BTreeMap<SystemApiFunc, u32> {
    module
        .imports
        .iter()
        .filter(|imp| matches!(imp.ty, wirm::wasmparser::TypeRef::Func(_)))
        .enumerate()
        .filter_map(|(func_index, import)| {
            if import.module == API_VERSION_IC0 {
                // The imports get function indexes before defined functions (so
                // starting at zero) and these are required to fit in 32-bits.
                SystemApiFunc::from_import_name(&import.name).map(|api| (api, func_index as u32))
            } else {
                None
            }
        })
        .collect()
}

fn replace_system_api_functions(
    module: &mut wirm::Module<'_>,
    injected_functions: &InjectedFunctions,
    injected_counters: &InjectedCounters,
    stable_memory_index: u32,
    dirty_page_overhead: NumInstructions,
    main_memory_type: WasmMemoryType,
    max_wasm_memory_size: NumBytes,
) {
    let api_indexes = calculate_api_indexes(module);

    // Collect a single map of all the function indexes that need to be
    // replaced.
    for (api, (param, ret, body)) in replacement_functions(
        injected_functions,
        injected_counters,
        stable_memory_index,
        dirty_page_overhead,
        main_memory_type,
        max_wasm_memory_size,
    ) {
        if let Some(old_index) = api_indexes.get(&api) {
            let mut builder = FunctionBuilder::new(&param, &ret);
            builder.body = body;
            builder.replace_import_in_module(module, ImportsID(*old_index));
        }
    }
}

// Looks for the active data segments and if present, converts them to a vector of
// tuples (heap offset, bytes). It retains the passive data segments and clears the
// content of the active segments. Active data segments not followed by a passive
// segment can be entirely deleted.
fn get_data(
    data_section: &mut Vec<wirm::DataSegment>,
) -> Result<Segments, WasmInstrumentationError> {
    let res = data_section
        .iter()
        .filter_map(|segment| {
            let offset = match &segment.kind {
                wirm::ir::types::DataSegmentKind::Active {
                    memory_index: _,
                    offset_expr,
                } => match offset_expr.instructions() {
                    [InitInstr::Value(Value::I32(value))] => *value as usize,
                    [InitInstr::Value(Value::I64(value))] => *value as usize,
                    _ => return Some(Err(WasmInstrumentationError::WasmDeserializeError(WasmError::new(
                        "complex initialization expressions for data segments are not supported!".into()
                    )))),
                },
                wirm::ir::types::DataSegmentKind::Passive => return None,
            };

            Some(Ok((offset, segment.data.clone())))
        })
        .collect::<Result<_,_>>()?;

    // Clear all active data segments, but retain the indices of passive data segments:
    // * Clear the data of active data segments if (directly or indirectly) followed by a passive segment.
    // * Delete all active data segments not followed by any passive data segment.
    let mut ends_with_passive_segment = false;
    for index in (0..data_section.len()).rev() {
        let kind = &data_section[index].kind;
        match kind {
            wirm::DataSegmentKind::Passive => ends_with_passive_segment = true,
            wirm::DataSegmentKind::Active { .. } => {
                if ends_with_passive_segment {
                    data_section[index] = wirm::DataSegment {
                        kind: kind.clone(),
                        data: vec![],
                        tag: None,
                    };
                } else {
                    data_section.remove(index);
                }
            }
        }
    }

    Ok(res)
}

/// Takes a Wasm binary and inserts the instructions metering and memory grow
/// instrumentation.
///
/// Returns an [`InstrumentationOutput`] or an error if the input binary could
/// not be instrumented.
pub(super) fn instrument(
    mut module: wirm::Module<'_>,
    cost_to_compile_wasm_instruction: NumInstructions,
    metering_type: MeteringType,
    dirty_page_overhead: NumInstructions,
    max_wasm_memory_size: NumBytes,
    max_stable_memory_size: NumBytes,
) -> Result<InstrumentationOutput, WasmInstrumentationError> {
    let main_memory_type = main_memory_type(&module);
    let injected_functions = inject_helper_functions(&mut module, main_memory_type);

    module = export_table(module);
    let stable_memory_index;
    (module, stable_memory_index) =
        update_memories(module, max_wasm_memory_size, max_stable_memory_size);

    module = export_mutable_globals(module);

    let injected_counters;
    (injected_counters, module) =
        export_additional_symbols(module, &injected_functions, stable_memory_index);

    // Start has be exported as `canister_start` so we can clear it.
    module.start = None;

    // inject instructions counter decrementation
    for func_body in &mut module
        .functions
        .iter_mut()
        .filter(|f| f.is_local())
        .map(|f| f.unwrap_local_mut())
        // skip metering on injected functions
        .filter(|f| {
            *f.func_id != injected_counters.decr_instruction_counter_fn
                && *f.func_id != injected_counters.count_clean_pages_fn
        })
    {
        inject_metering(
            &mut func_body.body,
            &injected_counters,
            &injected_functions,
            metering_type,
            main_memory_type,
        );
    }

    // Inject `try_grow_wasm_memory` after `memory.grow` instructions.
    for func_body in &mut module
        .functions
        .iter_mut()
        .filter(|f| f.is_local())
        .map(Function::unwrap_local_mut)
    {
        let num_params = module.types.get(func_body.ty_id).unwrap().params().len() as u32;
        inject_try_grow_wasm_memory(
            &mut func_body.body,
            num_params,
            main_memory_type,
            &injected_functions,
        );
    }

    replace_system_api_functions(
        &mut module,
        &injected_functions,
        &injected_counters,
        stable_memory_index,
        dirty_page_overhead,
        main_memory_type,
        max_wasm_memory_size,
    );

    let exported_functions = module
        .exports
        .iter()
        .filter_map(|export| WasmMethod::try_from(export.name.to_string()).ok())
        .collect();

    let expected_memories = 3;
    let memories_count = module.memories.iter().count();
    if memories_count > expected_memories {
        return Err(WasmInstrumentationError::IncorrectNumberMemorySections {
            expected: expected_memories,
            got: memories_count,
        });
    }

    let initial_limit = if module.memories.is_empty() {
        // if Wasm does not declare any memory section (mostly tests), use this default
        0
    } else {
        module.memories.iter().next().unwrap().ty.initial
    };

    // pull out the data from the data section
    let data = get_data(&mut module.data)?;
    data.validate(NumWasmPages::from(initial_limit as usize))?;

    let mut wasm_instruction_count: u64 = 0;
    for function in module.functions.iter() {
        if let FuncKind::Local(function) = function.kind() {
            wasm_instruction_count += function.body.instructions.len() as u64;
        }
    }
    for _ in module.globals.iter() {
        // Each global has a single instruction initializer and an `End`
        // instruction will be added during encoding.
        wasm_instruction_count += 2;
    }

    let result = module.encode();

    Ok(InstrumentationOutput {
        exported_functions,
        data,
        binary: BinaryEncodedWasm::new(result),
        compilation_cost: cost_to_compile_wasm_instruction * wasm_instruction_count,
    })
}
