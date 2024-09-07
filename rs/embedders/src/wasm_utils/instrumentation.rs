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
use ic_config::flag_status::FlagStatus;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NumWasmPages;
use ic_sys::PAGE_SIZE;
use ic_types::methods::WasmMethod;
use ic_types::NumBytes;
use ic_types::NumInstructions;
use ic_wasm_types::{BinaryEncodedWasm, WasmError, WasmInstrumentationError};
use rand::rngs::ThreadRng;
use rand::Rng;

use crate::wasmtime_embedder::{
    STABLE_BYTEMAP_MEMORY_NAME, STABLE_MEMORY_NAME, WASM_HEAP_BYTEMAP_MEMORY_NAME,
    WASM_HEAP_MEMORY_NAME,
};
use ic_wasm_transform::{self, Global, Module};
use wasmparser::{
    BlockType, CompositeType, Export, ExternalKind, FuncType, GlobalType, Import, MemoryType,
    Operator, SubType, TypeRef, ValType,
};

use std::collections::BTreeMap;
use std::convert::TryFrom;

const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;

#[derive(Copy, Clone, Debug)]
pub(crate) enum WasmMemoryType {
    Wasm32,
    Wasm64,
}

pub(crate) fn main_memory_type(module: &Module<'_>) -> WasmMemoryType {
    let mut mem_type = WasmMemoryType::Wasm32;
    if let Some(mem) = module.memories.first() {
        if mem.memory64 {
            mem_type = WasmMemoryType::Wasm64;
        }
    }
    mem_type
}

// The indices of injected function imports.
pub(crate) enum InjectedImports {
    OutOfInstructions = 0,
    TryGrowWasmMemory = 1,
    TryGrowStableMemory = 2,
    InternalTrap = 3,
    StableReadFirstAccess = 4,
}

impl InjectedImports {
    fn count(wasm_native_stable_memory: FlagStatus) -> usize {
        if wasm_native_stable_memory == FlagStatus::Enabled {
            5
        } else {
            2
        }
    }
}

// Gets the cost of an instruction.
pub fn instruction_to_cost(i: &Operator) -> u64 {
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
        Operator::Call { .. } | Operator::ReturnCall { .. } => 5,
        Operator::CallIndirect { .. } | Operator::ReturnCallIndirect { .. } => 10,

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
        Operator::V128Load { .. } => 1,
        Operator::V128Load8x8S { .. } => 1,
        Operator::V128Load8x8U { .. } => 1,
        Operator::V128Load16x4S { .. } => 1,
        Operator::V128Load16x4U { .. } => 1,
        Operator::V128Load32x2S { .. } => 1,
        Operator::V128Load32x2U { .. } => 1,
        Operator::V128Load8Splat { .. } => 1,
        Operator::V128Load16Splat { .. } => 1,
        Operator::V128Load32Splat { .. } => 1,
        Operator::V128Load64Splat { .. } => 1,
        Operator::V128Load32Zero { .. } => 1,
        Operator::V128Load64Zero { .. } => 1,
        Operator::V128Store { .. } => 1,
        Operator::V128Load8Lane { .. } => 2,
        Operator::V128Load16Lane { .. } => 2,
        Operator::V128Load32Lane { .. } => 1,
        Operator::V128Load64Lane { .. } => 1,
        Operator::V128Store8Lane { .. } => 1,
        Operator::V128Store16Lane { .. } => 1,
        Operator::V128Store32Lane { .. } => 1,
        Operator::V128Store64Lane { .. } => 1,
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

fn add_func_type(module: &mut Module, ty: FuncType) -> u32 {
    for (idx, existing_subtype) in module.types.iter().enumerate() {
        if let CompositeType::Func(existing_ty) = &existing_subtype.composite_type {
            if *existing_ty == ty {
                return idx as u32;
            }
        }
    }
    module.types.push(SubType {
        is_final: true,
        supertype_idx: None,
        composite_type: CompositeType::Func(ty),
    });
    (module.types.len() - 1) as u32
}

fn mutate_function_indices(module: &mut Module, f: impl Fn(u32) -> u32) {
    fn mutate_instruction(f: &impl Fn(u32) -> u32, op: &mut Operator) {
        match op {
            Operator::Call { function_index }
            | Operator::ReturnCall { function_index }
            | Operator::RefFunc { function_index } => {
                *function_index = f(*function_index);
            }
            _ => {}
        }
    }

    for func_body in &mut module.code_sections {
        for op in &mut func_body.instructions {
            mutate_instruction(&f, op);
        }
    }

    for exp in &mut module.exports {
        if let ExternalKind::Func = exp.kind {
            exp.index = f(exp.index);
        }
    }

    for (_, elem_items) in &mut module.elements {
        match elem_items {
            ic_wasm_transform::ElementItems::Functions(fun_items) => {
                for idx in fun_items {
                    *idx = f(*idx);
                }
            }
            ic_wasm_transform::ElementItems::ConstExprs { ty: _, exprs } => {
                for op in exprs {
                    mutate_instruction(&f, op)
                }
            }
        }
    }

    for global in &mut module.globals {
        mutate_instruction(&f, &mut global.init_expr)
    }

    for data_segment in &mut module.data {
        match &mut data_segment.kind {
            ic_wasm_transform::DataSegmentKind::Passive => {}
            ic_wasm_transform::DataSegmentKind::Active {
                memory_index: _,
                offset_expr,
            } => {
                mutate_instruction(&f, offset_expr);
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
    mem_type: WasmMemoryType,
) -> Module {
    // insert types
    let ooi_type = FuncType::new([], []);
    let tgwm_type = match mem_type {
        WasmMemoryType::Wasm32 => FuncType::new([ValType::I32, ValType::I32], [ValType::I32]),
        WasmMemoryType::Wasm64 => FuncType::new([ValType::I64, ValType::I64], [ValType::I64]),
    };

    let ooi_type_idx = add_func_type(&mut module, ooi_type);
    let tgwm_type_idx = add_func_type(&mut module, tgwm_type);

    // push_front imports
    let ooi_imp = Import {
        module: INSTRUMENTED_FUN_MODULE,
        name: OUT_OF_INSTRUCTIONS_FUN_NAME,
        ty: TypeRef::Func(ooi_type_idx),
    };

    let tgwm_imp = Import {
        module: INSTRUMENTED_FUN_MODULE,
        name: TRY_GROW_WASM_MEMORY_FUN_NAME,
        ty: TypeRef::Func(tgwm_type_idx),
    };

    let mut old_imports = module.imports;
    module.imports =
        Vec::with_capacity(old_imports.len() + InjectedImports::count(wasm_native_stable_memory));
    module.imports.push(ooi_imp);
    module.imports.push(tgwm_imp);

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

    module.imports.append(&mut old_imports);

    // now increment all function references by InjectedImports::Count
    let cnt = InjectedImports::count(wasm_native_stable_memory) as u32;
    mutate_function_indices(&mut module, |i| i + cnt);

    debug_assert!(
        module.imports[InjectedImports::OutOfInstructions as usize].name == "out_of_instructions"
    );
    debug_assert!(
        module.imports[InjectedImports::TryGrowWasmMemory as usize].name == "try_grow_wasm_memory"
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

    module
}

/// Indices of functions, globals, etc that will be need in the later parts of
/// instrumentation.
#[derive(Default)]
pub(super) struct SpecialIndices {
    pub instructions_counter_ix: u32,
    pub dirty_pages_counter_ix: Option<u32>,
    pub accessed_pages_counter_ix: Option<u32>,
    pub decr_instruction_counter_fn: u32,
    pub count_clean_pages_fn: Option<u32>,
    pub start_fn_ix: Option<u32>,
    pub stable_memory_index: u32,
    pub afl_instrument_prev_location: u32,
    pub afl_instrument_mem_ptr: u32,
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
    max_wasm_memory_size: NumBytes,
    max_stable_memory_size: NumBytes,
) -> Result<InstrumentationOutput, WasmInstrumentationError> {
    let main_memory_type = main_memory_type(&module);
    let stable_memory_index;
    let mut module = inject_helper_functions(module, wasm_native_stable_memory, main_memory_type);
    module = export_table(module);
    (module, stable_memory_index) = update_memories(
        module,
        write_barrier,
        wasm_native_stable_memory,
        max_wasm_memory_size,
        max_stable_memory_size,
    );

    let mut extra_strs: Vec<String> = Vec::new();
    module = export_mutable_globals(module, &mut extra_strs);

    // Inject two new globals
    // Will record the prev_location of each branch traversal
    // prev_location => mutable: true, value: 0
    // Address of our coverage map store.
    // mem_ptr => mutable: false, value: 0

    let prev_location = Global {
        ty: GlobalType {
            content_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        init_expr: Operator::I32Const { value: 0 },
    };

    let mem_ptr = Global {
        ty: GlobalType {
            content_type: ValType::I32,
            mutable: false,
            shared: false,
        },
        init_expr: Operator::I32Const { value: 0 },
    };

    // all previous indexes are fixed
    module.globals.push(prev_location);
    module.globals.push(mem_ptr);

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

    let num_functions = (module.functions.len() + num_imported_functions) as u32;
    let num_globals = (module.globals.len() + num_imported_globals) as u32;

    let dirty_pages_counter_ix;
    let accessed_pages_counter_ix;
    let count_clean_pages_fn;
    assert!(num_globals >= 2);
    let afl_instrument_prev_location = num_globals - 2;
    let afl_instrument_mem_ptr = num_globals - 1;

    match wasm_native_stable_memory {
        FlagStatus::Enabled => {
            dirty_pages_counter_ix = Some(num_globals + 1);
            accessed_pages_counter_ix = Some(num_globals + 2);
            count_clean_pages_fn = Some(num_functions + 2);
        }
        FlagStatus::Disabled => {
            dirty_pages_counter_ix = None;
            accessed_pages_counter_ix = None;
            count_clean_pages_fn = None;
        }
    };

    let mut special_indices = SpecialIndices {
        instructions_counter_ix: num_globals,
        dirty_pages_counter_ix,
        accessed_pages_counter_ix,
        decr_instruction_counter_fn: num_functions + 1,
        count_clean_pages_fn,
        start_fn_ix: module.start,
        stable_memory_index,
        afl_instrument_prev_location,
        afl_instrument_mem_ptr,
    };

    if special_indices.start_fn_ix.is_some() {
        module.start = None;
    }

    let new_num_funcs: u32 = inject_afl_coverage(&mut module, &special_indices, num_functions);

    if new_num_funcs > num_functions {
        special_indices.decr_instruction_counter_fn = new_num_funcs + 1;
        match wasm_native_stable_memory {
            FlagStatus::Enabled => {
                special_indices.count_clean_pages_fn = Some(new_num_funcs + 2);
            }
            _ => (),
        };
    }

    // inject instructions counter decrementation
    let mut rng = rand::thread_rng();
    let mut i: usize = 0;
    for func_body in &mut module.code_sections {
        if let CompositeType::Func(func_type) =
            &module.types[module.functions[i] as usize].composite_type
        {
            let n_locals: u32 = func_body.locals.iter().map(|x| x.0).sum();
            let next_local = func_type.params().len() as u32 + n_locals;
            // We need one local variable for duplicating the global
            func_body.locals.push((1, ValType::I32));

            inject_metering(
                &mut func_body.instructions,
                &special_indices,
                metering_type,
                main_memory_type,
                next_local,
                &mut rng,
            );
        }
        i += 1;
    }

    // Collect all the function types of the locally defined functions inside the
    // module.
    //
    // The main reason to create this vector of function types is because we can't
    // mix a mutable (to inject instructions) and immutable (to look up the function
    // type) reference to the `code_section`.
    let mut func_types = Vec::new();
    for i in 0..module.code_sections.len() {
        if let CompositeType::Func(t) = &module.types[module.functions[i] as usize].composite_type {
            func_types.push((i, t.clone()));
        } else {
            return Err(WasmInstrumentationError::InvalidFunctionType(format!(
                "Function has type which is not a function type. Found type: {:?}",
                &module.types[module.functions[i] as usize].composite_type
            )));
        }
    }

    // Inject `try_grow_wasm_memory` after `memory.grow` instructions.
    if !func_types.is_empty() {
        let func_bodies = &mut module.code_sections;
        for (func_ix, func_type) in func_types.into_iter() {
            inject_try_grow_wasm_memory(&mut func_bodies[func_ix], &func_type, main_memory_type);
            if write_barrier == FlagStatus::Enabled {
                inject_mem_barrier(&mut func_bodies[func_ix], &func_type);
            }
        }
    }

    module = export_additional_symbols(module, &special_indices, wasm_native_stable_memory);

    if wasm_native_stable_memory == FlagStatus::Enabled {
        replace_system_api_functions(
            &mut module,
            special_indices,
            subnet_type,
            dirty_page_overhead,
            main_memory_type,
            max_wasm_memory_size,
        )
    }

    let exported_functions = module
        .exports
        .iter()
        .filter_map(|export| WasmMethod::try_from(export.name.to_string()).ok())
        .collect();

    let expected_memories =
        1 + match write_barrier {
            FlagStatus::Enabled => 1,
            FlagStatus::Disabled => 0,
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
    for global in &module.globals {
        // Each global has a single instruction initializer and an `End`
        // instruction will be added during encoding.
        // We statically assert this is the case to ensure this calculation is
        // adjusted if we add support for longer initialization expressions.
        let _: &Operator = &global.init_expr;
        wasm_instruction_count += 2;
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

fn inject_afl_coverage(module: &mut Module<'_>, special_indices: &SpecialIndices, idx: u32) -> u32 {
    use Operator::*;

    let mut new_func_index = idx;

    // Get the system API import indexes for the function body
    let mut ic0_msg_reply_data_append_index: usize = usize::MAX;
    let mut ic0_msg_reply_index: usize = usize::MAX;

    for (func_index, import) in module
        .imports
        .iter()
        .filter(|imp| matches!(imp.ty, TypeRef::Func(_)))
        .enumerate()
    {
        if import.module == API_VERSION_IC0 {
            match import.name {
                "msg_reply_data_append" => ic0_msg_reply_data_append_index = func_index,
                "msg_reply" => ic0_msg_reply_index = func_index,
                &_ => (),
            }
        }
    }

    if ic0_msg_reply_data_append_index == usize::MAX {
        let ty = FuncType::new(vec![ValType::I32, ValType::I32], []);
        let mrda_type_idx = add_func_type(module, ty);

        let mrda_import = Import {
            module: API_VERSION_IC0,
            name: "msg_reply_data_append",
            ty: TypeRef::Func(mrda_type_idx),
        };

        module.imports.push(mrda_import);
        ic0_msg_reply_data_append_index = module.imports.len() - 1;
        new_func_index += 1;
    }

    if ic0_msg_reply_index == usize::MAX {
        let ty = FuncType::new([], []);
        let mr_type_idx = add_func_type(module, ty);

        let mr_import = Import {
            module: API_VERSION_IC0,
            name: "msg_reply",
            ty: TypeRef::Func(mr_type_idx),
        };

        module.imports.push(mr_import);
        ic0_msg_reply_index = module.imports.len() - 1;
        new_func_index += 1;
    }

    // inject the canister export_coverage method
    let ty = FuncType::new([], []);
    let type_idx = add_func_type(module, ty);
    module.functions.push(type_idx);

    let func_body = ic_wasm_transform::Body {
        locals: vec![],
        instructions: vec![
            GlobalGet {
                global_index: special_indices.afl_instrument_mem_ptr, // 0 for now
            },
            I32Const {
                value: 65536 as i32, // 1 page
            },
            Call {
                function_index: ic0_msg_reply_data_append_index as u32,
            },
            Call {
                function_index: ic0_msg_reply_index as u32,
            },
            End,
        ],
    };
    module.code_sections.push(func_body);

    let start_export = Export {
        name: "canister_query export_coverage",
        kind: ExternalKind::Func,
        index: new_func_index,
    };

    module.exports.push(start_export);
    new_func_index
}

fn replace_system_api_functions(
    module: &mut Module<'_>,
    special_indices: SpecialIndices,
    subnet_type: SubnetType,
    dirty_page_overhead: NumInstructions,
    main_memory_type: WasmMemoryType,
    max_wasm_memory_size: NumBytes,
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
        main_memory_type,
        max_wasm_memory_size,
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

    let func_body = ic_wasm_transform::Body {
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
        let func_body = ic_wasm_transform::Body {
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

    if let Some(index) = special_indices.accessed_pages_counter_ix {
        let export = Export {
            name: ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
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

    // push the instructions counter
    module.globals.push(Global {
        ty: GlobalType {
            content_type: ValType::I64,
            mutable: true,
            shared: false,
        },
        init_expr: Operator::I64Const { value: 0 },
    });

    if wasm_native_stable_memory == FlagStatus::Enabled {
        // push the dirty page counter
        module.globals.push(Global {
            ty: GlobalType {
                content_type: ValType::I64,
                mutable: true,
                shared: false,
            },
            init_expr: Operator::I64Const { value: 0 },
        });
        // push the accessed page counter
        module.globals.push(Global {
            ty: GlobalType {
                content_type: ValType::I64,
                mutable: true,
                shared: false,
            },
            init_expr: Operator::I64Const { value: 0 },
        });
    }

    module
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
    mem_type: WasmMemoryType,
    afl_local_idx: u32,
    rng: &mut ThreadRng,
) {
    let points = match metering_type {
        MeteringType::None => Vec::new(),
        MeteringType::New => injections(code, mem_type),
    };

    // TODO figure out which points to inject?
    // for now we inject at all static blocks

    let points = points.iter().filter(|point| match point.cost_detail {
        InjectionPointCostDetail::StaticCost {
            scope: Scope::ReentrantBlockStart,
            cost: _,
        } => true,
        InjectionPointCostDetail::StaticCost { scope: _, cost } => cost > 0,
        InjectionPointCostDetail::DynamicCost { .. } => true,
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

                let curr_location: i32 = rng.gen_range(0..65536);
                let afl_inject_slice: Vec<Operator> = vec![
                    I32Const {
                        value: curr_location,
                    },
                    GlobalGet {
                        global_index: export_data_module.afl_instrument_prev_location,
                    },
                    I32Xor,
                    GlobalGet {
                        global_index: export_data_module.afl_instrument_mem_ptr,
                    },
                    I32Add,
                    LocalTee {
                        local_index: afl_local_idx,
                    },
                    LocalGet {
                        local_index: afl_local_idx,
                    },
                    I32Load8U {
                        memarg: wasmparser::MemArg {
                            align: 0,
                            max_align: 0,
                            offset: 0,
                            memory: 0,
                        },
                    },
                    I32Const { value: 1 },
                    I32Add,
                    I32Store8 {
                        memarg: wasmparser::MemArg {
                            align: 0,
                            max_align: 0,
                            offset: 0,
                            memory: 0,
                        },
                    },
                    I32Const {
                        value: curr_location >> 1,
                    },
                    GlobalSet {
                        global_index: export_data_module.afl_instrument_prev_location,
                    },
                ];
                elems.extend_from_slice(&afl_inject_slice);
            }
            InjectionPointCostDetail::DynamicCost { operand_on_stack } => {
                match operand_on_stack {
                    CostOperandOnStack::X64Bit => {
                        elems.extend_from_slice(&[Call {
                            function_index: export_data_module.decr_instruction_counter_fn,
                        }]);
                    }
                    CostOperandOnStack::X32Bit => {
                        elems.extend_from_slice(&[
                            I64ExtendI32U,
                            Call {
                                function_index: export_data_module.decr_instruction_counter_fn,
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

fn inject_mem_barrier(func_body: &mut ic_wasm_transform::Body, func_type: &FuncType) {
    use Operator::*;
    let mut val_i32_needed = false;
    let mut val_i64_needed = false;
    let mut val_f32_needed = false;
    let mut val_f64_needed = false;

    let mut injection_points: Vec<usize> = Vec::new();
    {
        for (idx, instr) in func_body.instructions.iter().enumerate() {
            match instr {
                I32Store { .. } | I32Store8 { .. } | I32Store16 { .. } => {
                    val_i32_needed = true;
                    injection_points.push(idx)
                }
                I64Store { .. } | I64Store8 { .. } | I64Store16 { .. } | I64Store32 { .. } => {
                    val_i64_needed = true;
                    injection_points.push(idx)
                }
                F32Store { .. } => {
                    val_f32_needed = true;
                    injection_points.push(idx)
                }
                F64Store { .. } => {
                    val_f64_needed = true;
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
        let arg_i32_addr_idx = next_local;
        next_local += 1;

        // conditionally add following locals
        let arg_i32_val_idx;
        let arg_i64_val_idx;
        let arg_f32_val_idx;
        let arg_f64_val_idx;

        if val_i32_needed {
            arg_i32_val_idx = next_local;
            next_local += 1;
            func_body.locals.push((2, ValType::I32)); // addr and val locals
        } else {
            arg_i32_val_idx = u32::MAX; // not used
            func_body.locals.push((1, ValType::I32)); // only addr local
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
            // next_local += 1;
            func_body.locals.push((1, ValType::F64));
        } else {
            arg_f64_val_idx = u32::MAX;
        }

        let orig_elems = &func_body.instructions;
        let mut elems: Vec<Operator> = Vec::new();
        let mut last_injection_position = 0;
        for point in injection_points {
            let mem_instr = orig_elems[point].clone();
            elems.extend_from_slice(&orig_elems[last_injection_position..point]);

            match mem_instr {
                I32Store { memarg } | I32Store8 { memarg } | I32Store16 { memarg } => {
                    elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_i32_val_idx,
                        arg_i32_addr_idx,
                    ));
                }
                I64Store { memarg }
                | I64Store8 { memarg }
                | I64Store16 { memarg }
                | I64Store32 { memarg } => {
                    elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_i64_val_idx,
                        arg_i32_addr_idx,
                    ));
                }
                F32Store { memarg } => {
                    elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_f32_val_idx,
                        arg_i32_addr_idx,
                    ));
                }
                F64Store { memarg } => {
                    elems.extend_from_slice(&write_barrier_instructions(
                        memarg.offset,
                        arg_f64_val_idx,
                        arg_i32_addr_idx,
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

// Scans through the function and adds instrumentation after each `memory.grow`
// instruction to make sure that there's enough available memory left to support
// the requested extra memory.
fn inject_try_grow_wasm_memory(
    func_body: &mut ic_wasm_transform::Body,
    func_type: &FuncType,
    mem_type: WasmMemoryType,
) {
    use Operator::*;
    let mut injection_points: Vec<usize> = Vec::new();
    {
        for (idx, instr) in func_body.instructions.iter().enumerate() {
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
        let memory_local_ix = func_type.params().len() as u32 + n_locals;
        match mem_type {
            WasmMemoryType::Wasm32 => func_body.locals.push((1, ValType::I32)),
            WasmMemoryType::Wasm64 => func_body.locals.push((1, ValType::I64)),
        };

        let orig_elems = &func_body.instructions;
        let mut elems: Vec<Operator> = Vec::new();
        let mut last_injection_position = 0;
        for point in injection_points {
            let memory_grow_instr = orig_elems[point].clone();
            elems.extend_from_slice(&orig_elems[last_injection_position..point]);
            // At this point we have a memory.grow so the argument to it will be on top of
            // the stack, which we just assign to `memory_local_ix` with a local.tee
            // instruction.
            elems.extend_from_slice(&[
                LocalTee {
                    local_index: memory_local_ix,
                },
                memory_grow_instr,
                LocalGet {
                    local_index: memory_local_ix,
                },
                Call {
                    function_index: InjectedImports::TryGrowWasmMemory as u32,
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
// it's re-entrant or not.
fn injections(code: &[Operator], mem_type: WasmMemoryType) -> Vec<InjectionPoint> {
    let mut res = Vec::new();
    use Operator::*;
    // The function itself is a re-entrant code block.
    // Start with at least one fuel being consumed because even empty
    // functions should consume at least some fuel.
    let mut curr = InjectionPoint::new_static_cost(0, Scope::ReentrantBlockStart, 1);
    for (position, i) in code.iter().enumerate() {
        curr.cost_detail.increment_cost(instruction_to_cost(i));
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

// Looks for the active data segments and if present, converts them to a vector of
// tuples (heap offset, bytes). It retains the passive data segments and clears the
// content of the active segments. Active data segments not followed by a passive
// segment can be entirely deleted.
fn get_data(
    data_section: &mut Vec<ic_wasm_transform::DataSegment>,
) -> Result<Segments, WasmInstrumentationError> {
    let res = data_section
        .iter()
        .filter_map(|segment| {
            let offset = match &segment.kind {
                ic_wasm_transform::DataSegmentKind::Active {
                    memory_index: _,
                    offset_expr,
                } => match offset_expr {
                    Operator::I32Const { value } => *value as usize,
                    Operator::I64Const { value } => *value as usize,
                    _ => return Some(Err(WasmInstrumentationError::WasmDeserializeError(WasmError::new(
                        "complex initialization expressions for data segments are not supported!".into()
                    )))),
                },
                ic_wasm_transform::DataSegmentKind::Passive => return None,
            };

            Some(Ok((offset, segment.data.to_vec())))
        })
        .collect::<Result<_,_>>()?;

    // Clear all active data segments, but retain the indices of passive data segments:
    // * Clear the data of active data segments if (directly or indirectly) followed by a passive segment.
    // * Delete all active data segments not followed by any passive data segment.
    let mut ends_with_passive_segment = false;
    for index in (0..data_section.len()).rev() {
        let kind = &data_section[index].kind;
        match kind {
            ic_wasm_transform::DataSegmentKind::Passive => ends_with_passive_segment = true,
            ic_wasm_transform::DataSegmentKind::Active { .. } => {
                if ends_with_passive_segment {
                    data_section[index] = ic_wasm_transform::DataSegment {
                        kind: kind.clone(),
                        data: &[],
                    };
                } else {
                    data_section.remove(index);
                }
            }
        }
    }

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
    max_wasm_memory_size: NumBytes,
    max_stable_memory_size: NumBytes,
) -> (Module, u32) {
    let mut stable_index = 0;

    if let Some(mem) = module.memories.first_mut() {
        if mem.memory64 {
            let max_wasm_memory_size_in_wasm_pages =
                max_memory_size_in_wasm_pages(max_wasm_memory_size);
            match mem.maximum {
                Some(max) => {
                    // In case the maximum memory size is larger than the maximum allowed, cap it.
                    if max > max_wasm_memory_size_in_wasm_pages {
                        mem.maximum = Some(max_wasm_memory_size_in_wasm_pages);
                    }
                }
                None => {
                    mem.maximum = Some(max_wasm_memory_size_in_wasm_pages);
                }
            }
        }
    }

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

    let wasm_bytemap_size_in_wasm_pages = bytemap_size_in_wasm_pages(max_wasm_memory_size);
    if write_barrier == FlagStatus::Enabled && !module.memories.is_empty() {
        module.memories.push(MemoryType {
            memory64: false,
            shared: false,
            initial: wasm_bytemap_size_in_wasm_pages,
            maximum: Some(wasm_bytemap_size_in_wasm_pages),
            page_size_log2: None,
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
            maximum: Some(max_memory_size_in_wasm_pages(max_stable_memory_size)),
            page_size_log2: None,
        });

        module.exports.push(Export {
            name: STABLE_MEMORY_NAME,
            kind: ExternalKind::Memory,
            index: stable_index,
        });

        let stable_bytemap_size_in_wasm_pages = bytemap_size_in_wasm_pages(max_stable_memory_size);
        module.memories.push(MemoryType {
            memory64: false,
            shared: false,
            initial: stable_bytemap_size_in_wasm_pages,
            maximum: Some(stable_bytemap_size_in_wasm_pages),
            page_size_log2: None,
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
