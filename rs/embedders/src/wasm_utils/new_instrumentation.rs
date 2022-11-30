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
//! In more details, first, it inserts two System API functions:
//!
//! ```wasm
//! (import "__" "out_of_instructions" (func (;0;) (func)))
//! (import "__" "update_available_memory" (func (;1;) ((param i32 i32) (result i32))))
//! ```
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

use super::{InstrumentationOutput, Segments};
use ic_config::flag_status::FlagStatus;
use ic_replicated_state::NumWasmPages;
use ic_sys::PAGE_SIZE;
use ic_types::NumInstructions;
use ic_types::{methods::WasmMethod, MAX_WASM_MEMORY_IN_BYTES};
use ic_wasm_types::{BinaryEncodedWasm, WasmError, WasmInstrumentationError};
use wasmtime_environ::WASM_PAGE_SIZE;

use crate::wasm_utils::wasm_transform::{self, Module};
use crate::wasmtime_embedder::{WASM_HEAP_BYTEMAP_MEMORY_NAME, WASM_HEAP_MEMORY_NAME};
use wasmparser::{
    BlockType, ConstExpr, Export, ExternalKind, FuncType, Global, GlobalType, Import, MemoryType,
    Operator, Type, TypeRef, ValType,
};

use std::convert::TryFrom;

// The indicies of injected function imports.
enum InjectedImports {
    OutOfInstructionsFn = 0,
    UpdateAvailableMemoryFn = 1,
    Count = 2,
}

// Gets the cost of an instruction.
fn instruction_to_cost(i: &Operator) -> u64 {
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

// Injects two system api functions:
//   * `out_of_instructions` which is called, whenever a message execution runs
//     out of instructions.
//   * `update_available_memory` which is called after a native `memory.grow` to
//     check whether the canister has enough available memory according to its
//     memory allocation.
//
// Note that these functions are injected as the first two imports, so that we
// can increment all function indices unconditionally by two. (If they would be
// added as the last two imports, we'd need to increment only non imported
// functions, since imported functions precede all others in the function index
// space, but this would be error-prone).

const INSTRUMENTED_FUN_MODULE: &str = "__";
const OUT_OF_INSTRUCTIONS_FUN_NAME: &str = "out_of_instructions";
const UPDATE_MEMORY_FUN_NAME: &str = "update_available_memory";
const TABLE_STR: &str = "table";
const CANISTER_COUNTER_INSTRUCTIONS_STR: &str = "canister counter_instructions";
const CANISTER_START_STR: &str = "canister_start";

/// There is one byte for each OS page in the wasm heap.
const BYTEMAP_SIZE_IN_WASM_PAGES: u64 =
    MAX_WASM_MEMORY_IN_BYTES / (PAGE_SIZE as u64) / (WASM_PAGE_SIZE as u64);

fn add_type(module: &mut Module, ty: Type) -> u32 {
    let Type::Func(sig) = &ty;
    for (idx, Type::Func(msig)) in module.types.iter().enumerate() {
        if *msig == *sig {
            return idx as u32;
        }
    }
    module.types.push(ty);
    (module.types.len() - 1) as u32
}

fn inject_helper_functions(mut module: Module) -> Module {
    // insert types
    let ooi_type = Type::Func(FuncType::new([], []));
    let uam_type = Type::Func(FuncType::new([ValType::I32, ValType::I32], [ValType::I32]));

    let ooi_type_idx = add_type(&mut module, ooi_type);
    let uam_type_idx = add_type(&mut module, uam_type);

    // push_front imports
    let ooi_imp = Import {
        module: INSTRUMENTED_FUN_MODULE,
        name: OUT_OF_INSTRUCTIONS_FUN_NAME,
        ty: TypeRef::Func(ooi_type_idx as u32),
    };

    let uam_imp = Import {
        module: INSTRUMENTED_FUN_MODULE,
        name: UPDATE_MEMORY_FUN_NAME,
        ty: TypeRef::Func(uam_type_idx as u32),
    };

    let mut old_imports = module.imports;
    module.imports = Vec::with_capacity(old_imports.len() + 2);
    module.imports.push(ooi_imp);
    module.imports.push(uam_imp);
    module.imports.append(&mut old_imports);

    // now increment all function references by InjectedImports::Count
    let cnt = InjectedImports::Count as u32;
    for func_body in &mut module.code_sections {
        for instr in &mut func_body.instructions {
            if let Operator::Call { function_index } = instr {
                *function_index += cnt;
            }
        }
    }
    for exp in &mut module.exports {
        if let ExternalKind::Func = exp.kind {
            exp.index += cnt;
        }
    }
    for (_, elem_items) in &mut module.elements {
        if let wasm_transform::ElementItems::Functions(fun_items) = elem_items {
            for idx in fun_items {
                *idx += cnt;
            }
        }
    }
    if let Some(start_idx) = module.start.as_mut() {
        *start_idx += cnt;
    }

    debug_assert!(
        module.imports[InjectedImports::OutOfInstructionsFn as usize].name == "out_of_instructions"
    );
    debug_assert!(
        module.imports[InjectedImports::UpdateAvailableMemoryFn as usize].name
            == "update_available_memory"
    );

    module
}

#[derive(Default)]
pub struct ExportModuleData {
    pub instructions_counter_ix: u32,
    pub decr_instruction_counter_fn: u32,
    pub start_fn_ix: Option<u32>,
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
) -> Result<InstrumentationOutput, WasmInstrumentationError> {
    let mut module = inject_helper_functions(module);
    module = export_table(module);
    module = export_memory(module, write_barrier);

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

    let num_functions = (module.functions.len() + num_imported_functions) as u32;
    let num_globals = (module.globals.len() + num_imported_globals) as u32;

    let export_module_data = ExportModuleData {
        instructions_counter_ix: num_globals,
        decr_instruction_counter_fn: num_functions,
        start_fn_ix: module.start,
    };

    if export_module_data.start_fn_ix.is_some() {
        module.start = None;
    }

    // inject instructions counter decrementation
    for func_body in &mut module.code_sections {
        inject_metering(&mut func_body.instructions, &export_module_data);
    }

    // Collect all the function types of the locally defined functions inside the
    // module.
    //
    // The main reason to create this vector of function types is because we can't
    // mix a mutable (to inject instructions) and immutable (to look up the function
    // type) reference to the `code_section`.
    let mut func_types = Vec::new();
    for i in 0..module.code_sections.len() {
        let Type::Func(t) = &module.types[module.functions[i] as usize];
        func_types.push(t.clone());
    }

    // Inject `update_available_memory` to functions with `memory.grow`
    // instructions.
    if !func_types.is_empty() {
        let func_bodies = &mut module.code_sections;
        for (func_ix, func_type) in func_types.into_iter().enumerate() {
            inject_update_available_memory(&mut func_bodies[func_ix], &func_type);
        }
    }

    let mut extra_data: Option<Vec<u8>> = None;
    module = export_additional_symbols(module, &export_module_data, &mut extra_data);

    let exported_functions = module
        .exports
        .iter()
        .filter_map(|export| WasmMethod::try_from(export.name.to_string()).ok())
        .collect();

    let expected_memories = match write_barrier {
        FlagStatus::Enabled => 2,
        FlagStatus::Disabled => 1,
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
        wasm_instruction_count += glob.init_expr.get_operators_reader().into_iter().count() as u64;
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

// Helper function used by instrumentation to export additional symbols.
//
// Returns the new module or an error if a symbol is not reserved.
#[doc(hidden)] // pub for usage in tests
pub fn export_additional_symbols<'a>(
    mut module: Module<'a>,
    export_module_data: &ExportModuleData,
    extra_data: &'a mut Option<Vec<u8>>,
) -> Module<'a> {
    // push function to decrement the instruction counter

    let func_type = Type::Func(FuncType::new([ValType::I32], [ValType::I32]));

    use Operator::*;

    let instructions = vec![
        // Subtract the parameter amount from the instruction counter
        GlobalGet {
            global_index: export_module_data.instructions_counter_ix,
        },
        LocalGet { local_index: 0 },
        I64ExtendI32U,
        I64Sub,
        GlobalSet {
            global_index: export_module_data.instructions_counter_ix,
        },
        // Call out_of_instructions() if `counter < 0`.
        GlobalGet {
            global_index: export_module_data.instructions_counter_ix,
        },
        I64Const { value: 0 },
        I64LtS,
        If {
            blockty: BlockType::Empty,
        },
        Call {
            function_index: InjectedImports::OutOfInstructionsFn as u32,
        },
        End,
        // Return the original param so this function doesn't alter the stack
        LocalGet { local_index: 0 },
        End,
    ];

    let func_body = wasm_transform::Body {
        locals: vec![],
        instructions,
    };

    let type_idx = add_type(&mut module, func_type);
    module.functions.push(type_idx);
    module.code_sections.push(func_body);

    // globals must be exported to be accessible to hypervisor or persisted
    let counter_export = Export {
        name: CANISTER_COUNTER_INSTRUCTIONS_STR,
        kind: ExternalKind::Global,
        index: export_module_data.instructions_counter_ix,
    };
    debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&counter_export.name));
    module.exports.push(counter_export);

    if let Some(index) = export_module_data.start_fn_ix {
        // push canister_start
        let start_export = Export {
            name: CANISTER_START_STR,
            kind: ExternalKind::Func,
            index,
        };
        debug_assert!(super::validation::RESERVED_SYMBOLS.contains(&start_export.name));
        module.exports.push(start_export);
    }

    let mut zero_init_data: Vec<u8> = Vec::new();
    use wasm_encoder::Encode;
    //encode() automatically adds an End instructions
    wasm_encoder::ConstExpr::i64_const(0).encode(&mut zero_init_data);
    debug_assert!(extra_data.is_none());
    *extra_data = Some(zero_init_data);

    // push the instructions counter
    module.globals.push(Global {
        ty: GlobalType {
            content_type: ValType::I64,
            mutable: true,
        },
        init_expr: ConstExpr::new(extra_data.as_ref().unwrap(), 0),
    });

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
// following basic block. `DynamicCost` injection points assume there is an i32
// on the stack which should be decremented from the instruction counter.
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
fn inject_metering(code: &mut Vec<Operator>, export_data_module: &ExportModuleData) {
    let points = injections(code);
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
                            function_index: InjectedImports::OutOfInstructionsFn as u32,
                        },
                        End,
                    ]);
                }
            }
            InjectionPointCostDetail::DynamicCost => {
                elems.extend_from_slice(&[Call {
                    function_index: export_data_module.decr_instruction_counter_fn,
                }]);
            }
        }
        last_injection_position = point.position;
    }
    elems.extend_from_slice(&orig_elems[last_injection_position..]);
    *orig_elems = elems;
}

// Scans through a function and adds instrumentation after each `memory.grow`
// instruction to make sure that there's enough available memory left to support
// the requested extra memory. If no `memory.grow` instructions are present then
// the function's code remains unchanged.
fn inject_update_available_memory(func_body: &mut wasm_transform::Body, func_type: &FuncType) {
    use Operator::*;
    let mut injection_points: Vec<usize> = Vec::new();
    {
        for (idx, instr) in func_body.instructions.iter().enumerate() {
            // TODO(EXC-222): Once `table.grow` is supported we should extend the list of
            // injections here.
            if let MemoryGrow { .. } = instr {
                injection_points.push(idx);
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
        func_body.locals.push((1, ValType::I32));

        let orig_elems = &func_body.instructions;
        let mut elems: Vec<Operator> = Vec::new();
        let mut last_injection_position = 0;
        for point in injection_points {
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
                Call {
                    function_index: InjectedImports::UpdateAvailableMemoryFn as u32,
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
fn injections(code: &[Operator]) -> Vec<InjectionPoint> {
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
            | TableInit { .. } => {
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

fn export_memory(mut module: Module, write_barrier: FlagStatus) -> Module {
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

    if write_barrier == FlagStatus::Enabled && !module.memories.is_empty() {
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

    module
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
