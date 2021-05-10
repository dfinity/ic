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
//! After the instrumentation, exported functions `canister counter_set` and
//! `canister counter_get` can be used to set/get the counter value. Any other
//! function of that module will only be able to execute as long as at every
//! reentrant basic block of its execution path, the counter is verified to be
//! above zero. Otherwise, the function will trap (via calling a special system
//! API call). If the function returns before the counter overflows, the value
//! of the counter is the initial value minus the sum of cost of all
//! executed instructions.
//!
//! In more details, first, it inserts two System API functions:
//!
//! ```wasm
//! (import "__" "out_of_instructions" (func (;0;) (func)))
//! (import "__" "update_available_memory" (func (;1;) ((param i32 i32) (result i32))))
//! ```
//!
//! It then inserts a global mutable counter:
//! ```wasm
//! (global (mut i64) (i64.const 0))
//! ```
//!
//! and two exported functions setting and reading the instructions value:
//!
//! ```wasm
//! (func (;2;) (type 1) (param i64)
//!   local.get 0
//!   global.set 1)
//! (func (;3;) (type 2) (result i64)
//!   global.get 1)
//! (export "canister counter_set" (func 2))
//! (export "canister counter_get" (func 3))
//! ```
//!
//! The function `canister counter_set` should be called before the execution of
//! the instrumented code. After the execution, the counter can be read using
//! the exported function `canister counter_get`.
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
//! Note that we omit checking for the counter overflow at the non-reentrant
//! blocks to optimize for performance. The maximal overflow in that case is
//! bound by the length of the longest execution path consisting of
//! non-reentrant basic blocks.

use crate::errors::into_parity_wasm_error;
use ic_wasm_types::{BinaryEncodedWasm, WasmInstrumentationError};
use parity_wasm::builder;
use parity_wasm::elements::{
    BlockType, ExportEntry, FuncBody, FunctionType, GlobalEntry, GlobalType, InitExpr, Instruction,
    Instructions, Internal, Local, Module, Section, Type, ValueType,
};
use std::collections::{HashMap, HashSet};

const UPDATE_AVAILABLE_MEMORY_FN: u32 = 1; // because it's the second import

// Converts a Wasm instruction to a string mnemonic.
// TODO(EXC-221): Consider optimizing this to "cache" results, so we don't have
// to extract the mnemomic each time this function is called.
fn instruction_to_mnemonic(i: &Instruction) -> String {
    let out = i.to_string();
    let mut iter = out.split_whitespace();
    iter.next()
        .expect("The string representation of a Wasm instruction is never empty.")
        .to_string()
}

/// The metering can be configured by providing a cost-per-instruction table and
/// the default cost for an instruction in case it's not present in the cost
/// table.
pub struct InstructionCostTable {
    // mapping of instruction mnemonic to its cost
    instruction_cost: HashMap<String, u64>,
    // default cost of an instruction (if not present in the cost table)
    default_cost: u64,
}

impl InstructionCostTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_cost(mut self, cost: u64) -> Self {
        self.default_cost = cost;
        self
    }

    pub fn with_instruction_cost(mut self, id: String, cost: u64) -> Self {
        self.instruction_cost.insert(id, cost);
        self
    }

    // Returns the cost of a Wasm instruction from the cost table or the default
    // cost if the instruction is not in the cost table.
    fn cost(&self, i: &Instruction) -> u64 {
        let mnemonic = instruction_to_mnemonic(i);
        *self
            .instruction_cost
            .get(&mnemonic)
            .unwrap_or(&self.default_cost)
    }
}

impl Default for InstructionCostTable {
    fn default() -> Self {
        let mut instruction_cost = HashMap::new();

        // The following instructions are mostly signaling the start/end of code blocks,
        // so we assign 0 cost to them.
        instruction_cost.insert(
            instruction_to_mnemonic(&Instruction::Block(BlockType::NoResult)),
            0,
        );
        instruction_cost.insert(instruction_to_mnemonic(&Instruction::Else), 0);
        instruction_cost.insert(instruction_to_mnemonic(&Instruction::End), 0);
        instruction_cost.insert(
            instruction_to_mnemonic(&Instruction::Loop(BlockType::NoResult)),
            0,
        );

        Self {
            default_cost: 1,
            instruction_cost,
        }
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
fn inject_helper_functions(module: Module) -> Module {
    let mut builder = builder::from_module(module);
    let import_sig = builder.push_signature(builder::signature().build_sig());

    builder.push_import(
        builder::import()
            .module("__")
            .field("out_of_instructions")
            .external()
            .func(import_sig)
            .build(),
    );

    let import_sig = builder.push_signature(
        builder::signature()
            .with_param(ValueType::I32)
            .with_param(ValueType::I32)
            .with_return_type(Some(ValueType::I32))
            .build_sig(),
    );
    builder.push_import(
        builder::import()
            .module("__")
            .field("update_available_memory")
            .external()
            .func(import_sig)
            .build(),
    );
    let mut module = builder.build();
    // We know, we have at least two imports, because we pushed them above, now
    // let's move them to the first two positions respectively, so that we can
    // increase all other function indices unconditionally.
    let entries = module.import_section_mut().unwrap().entries_mut();
    let last = entries.pop().unwrap();
    debug_assert!(last.module() == "__" && last.field() == "update_available_memory");
    entries.insert(0, last);
    let last = entries.pop().unwrap();
    debug_assert!(last.module() == "__" && last.field() == "out_of_instructions");
    entries.insert(0, last);

    // We lift all call references by 2
    for section in module.sections_mut() {
        match section {
            Section::Code(ref mut code_section) => {
                for func_body in code_section.bodies_mut() {
                    let code = func_body.code_mut();
                    code.elements_mut().iter_mut().for_each(|instr| {
                        if let Instruction::Call(ref mut call_index) = instr {
                            *call_index += 2
                        }
                    });
                }
            }
            Section::Export(ref mut export_section) => {
                for export in export_section.entries_mut() {
                    if let Internal::Function(ref mut func_index) = export.internal_mut() {
                        *func_index += 2
                    }
                }
            }
            Section::Element(ref mut elements_section) => {
                for segment in elements_section.entries_mut() {
                    for func_index in segment.members_mut() {
                        *func_index += 2
                    }
                }
            }
            Section::Start(ref mut func_index) => *func_index += 2,
            _ => {}
        }
    }
    module
}

/// Vector of heap data chunks with their offsets.
pub struct Segments(Vec<(usize, Vec<u8>)>);

impl From<Vec<(usize, Vec<u8>)>> for Segments {
    fn from(vec: Vec<(usize, Vec<u8>)>) -> Self {
        Self(vec)
    }
}

impl Segments {
    // Returns the slice of the internal data. For testing purposes only.
    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[(usize, Vec<u8>)] {
        &self.0
    }

    // Takes chunks extracted from data, and creates pages out of them, by mapping
    // them to the corresponding page, leaving uninitialized parts filled with
    // zeros.
    pub fn as_pages(&self, page_size: usize) -> Vec<(usize, Vec<u8>)> {
        self.0
            .iter()
            // We go over all chunks and split them into multiple chunks if they cross page
            // boundaries.
            .flat_map(|(offset, bytes)| {
                // First, we determine the size of the first chunk, which is equal to the chunk
                // itself, if it does not cross the page boundary.
                let first_chunk_size = std::cmp::min(bytes.len(), page_size - (offset % page_size));
                let mut split_chunks = vec![(*offset, bytes[..first_chunk_size].to_vec())];
                // If the chunk crosses the page boundary, split the rest of it into
                // page-sized chunks and compute the correct offset for them.
                split_chunks.extend_from_slice(
                    bytes[first_chunk_size..]
                        .chunks(page_size)
                        .enumerate()
                        .map(move |(chunk_num, chunk)| {
                            (
                                offset + first_chunk_size + page_size * chunk_num,
                                chunk.to_vec(),
                            )
                        })
                        .collect::<Vec<(usize, Vec<u8>)>>()
                        .as_slice(),
                );
                split_chunks
            })
            // Second, after we know, that no chunk crosses the page boundary, simply fold all of
            // them into a map page_num -> page. Whenever we map a chunk into its page,
            // we simply copy its bytes to the right place inside the page.
            .fold(HashMap::new(), |mut acc, (offset, bytes)| {
                let page_num = offset / page_size;
                let list = acc.entry(page_num).or_insert_with(|| vec![0; page_size]);
                let local_offset = offset % page_size;
                list[local_offset..local_offset + (bytes.len() as usize)].copy_from_slice(&bytes);
                acc
            })
            .into_iter()
            .collect()
    }
}

pub struct InstrumentationOutput {
    /// A set of all exports.
    pub exports: HashSet<String>,

    /// Memory limits (min, max).
    pub limits: (u32, Option<u32>),

    /// Data segements.
    pub data: Segments,

    /// Instrumented Wasm binary.
    pub binary: BinaryEncodedWasm,
}

/// Takes a Wasm binary and inserts the instructions metering and memory grow
/// instrumentation.
///
/// Returns an [`InstrumentationOutput`] or an error if the input binary could
/// not be instrumented.
pub fn instrument(
    wasm: &BinaryEncodedWasm,
    instruction_cost_table: &InstructionCostTable,
) -> Result<InstrumentationOutput, WasmInstrumentationError> {
    let module = parity_wasm::deserialize_buffer::<Module>(wasm.as_slice()).map_err(|err| {
        WasmInstrumentationError::ParityDeserializeError(into_parity_wasm_error(err))
    })?;
    let mut module = inject_helper_functions(module);
    module = export_table(module);
    module = export_memory(module);
    module = export_mutable_globals(module);
    let num_functions = module.functions_space() as u32;
    let num_globals = module.globals_space() as u32;

    let out_of_instructions_fn = 0; // because it's the first import
    let instructions_counter_ix = num_globals;
    let set_counter_fn = num_functions;
    let get_counter_fn = num_functions + 1;
    let start_fn_ix = module.start_section();
    if start_fn_ix.is_some() {
        module.clear_start_section();
    }

    // inject instructions counter decrementation
    {
        if let Some(code_section) = module.code_section_mut() {
            for func_body in code_section.bodies_mut().iter_mut() {
                let code = func_body.code_mut();
                inject_metering(
                    code,
                    instruction_cost_table,
                    instructions_counter_ix,
                    out_of_instructions_fn,
                );
            }
        }
    }

    {
        // Collect all the function types of the locally defined functions inside the
        // module.
        //
        // The main reason to create this vector of function types is because we can't
        // mix a mutable (to inject instructions) and immutable (to look up the function
        // type) reference to the `code_section`.
        let mut func_types = Vec::new();
        if let Some(code_section) = module.code_section() {
            let functions = module.function_section().unwrap().entries();
            let types = module.type_section().unwrap().types();
            for i in 0..code_section.bodies().len() {
                let Type::Function(t) = &types[functions[i].type_ref() as usize];
                func_types.push(t.clone());
            }
        }
        // Inject `update_available_memory` to functions with `memory.grow`
        // instructions.
        if !func_types.is_empty() {
            let func_bodies = module.code_section_mut().unwrap().bodies_mut();
            for (func_ix, func_type) in func_types.into_iter().enumerate() {
                inject_update_available_memory(&mut func_bodies[func_ix], &func_type);
            }
        }
    }

    // pull out the data from the data section
    let data = Segments::from(get_data(module.sections_mut()));

    let mut mbuilder = builder::from_module(module);

    // push canister counter_set
    mbuilder.push_function(
        builder::function()
            .with_signature(builder::signature().with_param(ValueType::I64).build_sig())
            .body()
            .with_instructions(Instructions::new(vec![
                Instruction::GetLocal(0),
                Instruction::SetGlobal(instructions_counter_ix),
                Instruction::End,
            ]))
            .build()
            .build(),
    );
    mbuilder.push_export(ExportEntry::new(
        "canister counter_set".to_string(),
        Internal::Function(set_counter_fn),
    ));

    // push canister counter_get
    mbuilder.push_function(
        builder::function()
            .with_signature(
                builder::signature()
                    .with_return_type(Some(ValueType::I64))
                    .build_sig(),
            )
            .body()
            .with_instructions(Instructions::new(vec![
                Instruction::GetGlobal(instructions_counter_ix),
                Instruction::End,
            ]))
            .build()
            .build(),
    );
    mbuilder.push_export(ExportEntry::new(
        "canister counter_get".to_string(),
        Internal::Function(get_counter_fn),
    ));

    // globals must be exported to be accessible to hypervisor or persisted
    mbuilder.push_export(ExportEntry::new(
        "canister counter_instructions".to_string(),
        Internal::Global(instructions_counter_ix),
    ));

    if let Some(ix) = start_fn_ix {
        // push canister_start
        mbuilder.push_export(ExportEntry::new(
            "canister_start".to_string(),
            Internal::Function(ix),
        ));
    }

    // push the instructions counter
    let module = mbuilder
        .with_global(GlobalEntry::new(
            GlobalType::new(ValueType::I64, true),
            InitExpr::new(vec![Instruction::I64Const(0), Instruction::End]),
        ))
        .build();

    let exports = module
        .export_section()
        .unwrap() // because we definitely push exports above
        .entries()
        .iter()
        .map(|elem| elem.field().to_string())
        .collect();

    let limits = match module.memory_section() {
        // if Wasm does not declare any memory section (mostly tests), use this default
        None => (0, None),
        Some(section) => {
            let entries = section.entries();
            if entries.len() != 1 {
                return Err(WasmInstrumentationError::IncorrectNumberMemorySections {
                    expected: 1,
                    got: entries.len(),
                });
            }
            let limits = entries[0].limits();
            (limits.initial(), limits.maximum())
        }
    };

    let result = parity_wasm::serialize(module).map_err(|err| {
        WasmInstrumentationError::ParitySerializeError(into_parity_wasm_error(err))
    })?;
    Ok(InstrumentationOutput {
        exports,
        limits,
        data,
        binary: BinaryEncodedWasm::new(result),
    })
}

// Represents a hint about the context of each basic code block in Wasm.
#[derive(Copy, Clone, Debug, PartialEq)]
enum Scope {
    ReentrantBlockStart,
    NonReentrantBlockStart,
    BlockEnd,
}

// Represents a instructions metering injection point.
#[derive(Copy, Clone, Debug)]
struct InjectionPoint {
    scope: Scope,
    position: usize,
    cost: u64,
}

impl InjectionPoint {
    fn new(position: usize, scope: Scope) -> Self {
        InjectionPoint {
            scope,
            position,
            cost: 0,
        }
    }
}

// This function iterates over the injection points, and inserts two different
// pieces of Wasm code:
// - we insert a simple instructions counter decrementation in a beginning of
//   every non-reentrant block
// - we insert a counter decrementation and an overflow check at the beginning
//   of every reentrant block (a loop or a function call).
fn inject_metering(
    code: &mut Instructions,
    instruction_cost_table: &InstructionCostTable,
    instructions_counter_ix: u32,
    out_of_instructions_fn: u32,
) {
    let points = injections(code.elements(), instruction_cost_table);
    let points = points.iter().filter(|point| point.cost > 0);
    let orig_elems = code.elements();
    let mut elems: Vec<Instruction> = Vec::new();
    let mut last_injection_position = 0;
    for point in points {
        elems.extend_from_slice(&orig_elems[last_injection_position..point.position]);
        elems.extend_from_slice(&[
            Instruction::GetGlobal(instructions_counter_ix),
            Instruction::I64Const(point.cost as i64),
            Instruction::I64Sub,
            Instruction::SetGlobal(instructions_counter_ix),
        ]);
        if point.scope == Scope::ReentrantBlockStart {
            elems.extend_from_slice(&[
                Instruction::GetGlobal(instructions_counter_ix),
                Instruction::I64Const(0),
                Instruction::I64LtS,
                Instruction::If(BlockType::NoResult),
                Instruction::Call(out_of_instructions_fn),
                Instruction::End,
            ]);
        }
        last_injection_position = point.position;
    }
    elems.extend_from_slice(&orig_elems[last_injection_position..]);
    *code.elements_mut() = elems;
}

// Scans through a function and adds instrumentation after each `memory.grow`
// instruction to make sure that there's enough available memory left to support
// the requested extra memory. If no `memory.grow` instructions are present then
// the function's code remains unchanged.
fn inject_update_available_memory(func_body: &mut FuncBody, func_type: &FunctionType) {
    let mut injection_points: Vec<usize> = Vec::new();
    {
        let code = func_body.code();
        for (idx, instr) in code.elements().iter().enumerate() {
            // TODO(EXC-222): Once `table.grow` is supported we should extend the list of
            // injections here.
            if let Instruction::GrowMemory(_) = instr {
                injection_points.push(idx);
            }
        }
    }

    // If we found any injection points, we need to instrument the code.
    if !injection_points.is_empty() {
        // We inject a local to cache the argument to `memory.grow`.
        let n_locals: u32 = func_body.locals().iter().map(Local::count).sum();
        let memory_local_ix = func_type.params().len() as u32 + n_locals;
        func_body.locals_mut().push(Local::new(1, ValueType::I32));
        let code = func_body.code_mut();
        let orig_elems = code.elements_mut();
        let mut elems: Vec<Instruction> = Vec::new();
        let mut last_injection_position = 0;
        for point in injection_points {
            let update_available_memory_instr = orig_elems[point].clone();
            elems.extend_from_slice(&orig_elems[last_injection_position..point]);
            // At this point we have a memory.grow so the argument to it will be on top of
            // the stack, which we just assign to `memory_local_ix` with a local.tee
            // instruction.
            elems.extend_from_slice(&[
                Instruction::TeeLocal(memory_local_ix),
                update_available_memory_instr,
                Instruction::GetLocal(memory_local_ix),
                Instruction::Call(UPDATE_AVAILABLE_MEMORY_FN),
            ]);
            last_injection_position = point + 1;
        }
        elems.extend_from_slice(&orig_elems[last_injection_position..]);
        *orig_elems = elems;
    }
}

// This function scans through the Wasm code and creates an injection point
// at the beginning of every basic block (straight-line sequence of instructions
// with no branches). An injection point contains a "hint" about the context
// of every basic block, specifically if it's re-entrant or not.
fn injections(
    code: &[Instruction],
    instruction_cost_table: &InstructionCostTable,
) -> Vec<InjectionPoint> {
    let mut res = Vec::new();
    let mut stack = Vec::new();
    use Instruction::*;
    let mut curr = InjectionPoint::new(0, Scope::ReentrantBlockStart);
    for (position, i) in code.iter().enumerate() {
        curr.cost += instruction_cost_table.cost(i);
        match i {
            // Start of a re-entrant code block.
            Loop(_) => {
                stack.push(curr);
                curr = InjectionPoint::new(position + 1, Scope::ReentrantBlockStart);
            }
            // Start of a non re-entrant code block.
            If(_) | Block(_) => {
                stack.push(curr);
                curr = InjectionPoint::new(position + 1, Scope::NonReentrantBlockStart);
            }
            // End of a code block but still more code left.
            Else | Br(_) | BrIf(_) | BrTable(_) => {
                res.push(curr);
                curr = InjectionPoint::new(position + 1, Scope::BlockEnd);
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
            // Nothing special to be done for other instructions.
            _ => (),
        }
    }
    res.sort_by_key(|k| k.position);
    res
}

// Looks for the data section and if it is present, converts it to a vector of
// tuples (heap offset, bytes) and then deletes the section.
fn get_data(sections: &mut Vec<Section>) -> Vec<(usize, Vec<u8>)> {
    let mut res = Vec::new();
    let mut data_section_idx = sections.len();
    for (i, section) in sections.iter_mut().enumerate() {
        if let Section::Data(section) = section {
            data_section_idx = i;
            res = section
                .entries_mut()
                .iter_mut()
                .map(|segment| {
                    let offset = match segment.offset() {
                        None => panic!("no offset found for the data segment"),
                        Some(exp) => {
                            match exp.code() {
                                [
                                    Instruction::I32Const(val),
                                    Instruction::End
                                ] => *val as usize,
                                _ => panic!(
                                    "complex initialization expressions for data segments are not supported!"
                                    ),
                            }
                        }
                    };
                    (offset, std::mem::replace(segment.value_mut(), Vec::new()))
                })
                .collect();
        }
    }
    if data_section_idx < sections.len() {
        sections.remove(data_section_idx);
    }
    res
}

fn rename_export(export_entry: &mut ExportEntry, name: &str) {
    *export_entry.field_mut() = name.to_string();
}

fn export_table(mut module: Module) -> Module {
    let mut table_already_exported = false;
    if let Some(export_section) = module.export_section_mut() {
        for e in export_section.entries_mut() {
            if let Internal::Table(_) = e.internal() {
                table_already_exported = true;
                rename_export(e, "table");
            }
        }
    }

    if table_already_exported || module.table_section().is_none() {
        module
    } else {
        let mut mbuilder = builder::from_module(module);
        mbuilder.push_export(ExportEntry::new("table".to_string(), Internal::Table(0)));
        mbuilder.build()
    }
}

fn export_memory(mut module: Module) -> Module {
    let mut memory_already_exported = false;
    if let Some(export_section) = module.export_section_mut() {
        for e in export_section.entries_mut() {
            if let Internal::Memory(_) = e.internal() {
                memory_already_exported = true;
                rename_export(e, "memory");
            }
        }
    }

    if memory_already_exported || module.memory_section().is_none() {
        module
    } else {
        let mut mbuilder = builder::from_module(module);
        mbuilder.push_export(ExportEntry::new("memory".to_string(), Internal::Memory(0)));
        mbuilder.build()
    }
}

// Mutable globals must be exported to be persisted.
fn export_mutable_globals(module: Module) -> Module {
    if let Some(global_section) = module.global_section() {
        let mut mutable_exported: Vec<(bool, bool)> = global_section
            .entries()
            .iter()
            .map(|g| g.global_type().is_mutable())
            .zip(std::iter::repeat(false))
            .collect();

        if let Some(export_section) = module.export_section() {
            for e in export_section.entries() {
                if let Internal::Global(ix) = e.internal() {
                    mutable_exported[*ix as usize].1 = true;
                }
            }
        }

        let mut mbuilder = builder::from_module(module);
        for (ix, (mutable, exported)) in mutable_exported.into_iter().enumerate() {
            if mutable && !exported {
                mbuilder.push_export(ExportEntry::new(
                    format!("__persistent_mutable_global_{}", ix),
                    Internal::Global(ix as u32),
                ));
            }
        }
        mbuilder.build()
    } else {
        module
    }
}
