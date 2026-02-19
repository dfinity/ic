use super::*;

// `wasm-tools` is preferred. `walrus` is used since some of the code was adapted from `ic-wasm`
// which uses `walrus`.
use walrus::ir::*;
use walrus::*;

const NUM_BYTES_ENABLED_FLAG: usize = 4;
const NUM_BYTES_NUM_ENTRIES: usize = 8;
const MAX_NUM_LOG_ENTRIES: usize = 100_000_000;
const NUM_BYTES_FUNC_ID: usize = 4;
const NUM_BYTES_INSTRUCTION_COUNTER: usize = 8;

pub(super) fn prepare_instruction_tracing(wasm: &[u8]) -> (Vec<u8>, BTreeMap<i32, String>) {
    let config = ModuleConfig::new();
    let mut module = config.parse(wasm).expect("failed to parse wasm");

    let function_names = extract_function_names(&module);
    let wasm = instrument_wasm(&mut module);

    (wasm, function_names)
}

fn instrument_wasm(module: &mut Module) -> Vec<u8> {
    let performance_counter_func = module
        .imports
        .get_func("ic0", "performance_counter")
        .unwrap();
    let prepare_func = module.funcs.by_name("__prepare_tracing").unwrap();
    let bench_funcs: Vec<_> = module
        .funcs
        .iter()
        .filter_map(|f| {
            if f.name
                .as_ref()
                .is_some_and(|name| name.starts_with("canister_query __tracing__"))
            {
                Some(f.id())
            } else {
                None
            }
        })
        .collect();

    // The start address of the tracing buffer as a global variable. The address will be set to the
    // return value of the `__prepare_tracing` function, which is called before the benchmark
    // function is run.
    // TODO(EXC-2019): use i64 for wasm64 support.
    let traces_start_address =
        module
            .globals
            .add_local(ValType::I32, true, false, ConstExpr::Value(Value::I32(0)));
    // The trace function is called at the start/end of each instrumented function, which records
    // the (function id, performance counter) to the tracing buffer.
    let trace_func = make_trace_func(module, traces_start_address, performance_counter_func);

    // Injects the tracing code to all functions except the trace function itself.
    for (id, func) in module.funcs.iter_local_mut() {
        if id != trace_func && id != prepare_func && !bench_funcs.contains(&id) {
            inject_tracing(&module.types, trace_func, id, func);
        }
    }
    // Injects the `__prepare_tracing` call to be called at the start of each instruction tracing
    // query call.
    for (id, func) in module.funcs.iter_local_mut() {
        if bench_funcs.contains(&id) {
            inject_prepare_tracing_call(&module.types, traces_start_address, prepare_func, func);
        }
    }
    module.emit_wasm()
}

/// Creates a trace function, assuming (1) the tracing is enabled and (2) the number of logs has not
/// reached the maximum, when the trace function is called with function id (i32), it calls the
/// `ic0.performance_counter(0)` and appends (function id, performance counter) to the tracing
/// buffer.
fn make_trace_func(
    module: &mut Module,
    trace_start_address: GlobalId,
    performance_counter_func: FunctionId,
) -> FunctionId {
    let mut builder = FunctionBuilder::new(&mut module.types, &[ValType::I32], &[]);
    let mut body = builder.func_body();
    let memory = module.get_memory_id().unwrap();

    let func_id = module.locals.add(ValType::I32);
    let num_logs_address = module.locals.add(ValType::I32);
    let num_logs_before = module.locals.add(ValType::I64);
    let new_log_address = module.locals.add(ValType::I32);
    let store_kind_i32 = StoreKind::I32 { atomic: false };
    let load_kind_i32 = LoadKind::I32 { atomic: false };
    let store_kind_i64 = StoreKind::I64 { atomic: false };
    let load_kind_i64 = LoadKind::I64 { atomic: false };
    let mem_arg_i32 = MemArg {
        offset: 0,
        align: 4,
    };
    let mem_arg_i64 = MemArg {
        offset: 0,
        align: 8,
    };

    // Check whether tracing is enabled, leaving the value (0 or 1 as i32) in the stack.
    let is_tracing_enabled = |body: &mut InstrSeqBuilder| {
        body.global_get(trace_start_address)
            .load(memory, load_kind_i32, mem_arg_i32)
            .i32_const(1)
            .binop(BinaryOp::I32Eq);
    };
    // Increment the number of logs by 1, while setting `num_logs_before` to the previous value,
    // and `num_logs_address` to the address of the number of logs.
    let increment_num_logs = |body: &mut InstrSeqBuilder| {
        body.global_get(trace_start_address)
            .i32_const(NUM_BYTES_ENABLED_FLAG as i32)
            .binop(BinaryOp::I32Add)
            .local_tee(num_logs_address)
            .local_get(num_logs_address)
            .load(memory, load_kind_i64, mem_arg_i64)
            .local_tee(num_logs_before)
            .i64_const(1)
            .binop(BinaryOp::I64Add)
            .store(memory, store_kind_i64, mem_arg_i64);
    };
    // Assuming the number of logs is less than 100_000_000 (therefore the number can be wrapped as
    // i32), write a log entry.
    let write_log = |body: &mut InstrSeqBuilder| {
        increment_num_logs(body);
        body.local_get(num_logs_before)
            .unop(UnaryOp::I32WrapI64)
            .i32_const((NUM_BYTES_FUNC_ID + NUM_BYTES_INSTRUCTION_COUNTER) as i32)
            .binop(BinaryOp::I32Mul)
            .i32_const((NUM_BYTES_ENABLED_FLAG + NUM_BYTES_NUM_ENTRIES) as i32)
            .binop(BinaryOp::I32Add)
            .global_get(trace_start_address)
            .binop(BinaryOp::I32Add)
            .local_tee(new_log_address)
            .local_get(func_id)
            .store(memory, store_kind_i32, mem_arg_i32)
            .local_get(new_log_address)
            .i32_const(NUM_BYTES_FUNC_ID as i32)
            .binop(BinaryOp::I32Add)
            .i32_const(0)
            .call(performance_counter_func)
            .store(memory, store_kind_i64, mem_arg_i64);
    };
    let write_log_if_not_full = |body: &mut InstrSeqBuilder| {
        body.global_get(trace_start_address)
            .i32_const(NUM_BYTES_ENABLED_FLAG as i32)
            .binop(BinaryOp::I32Add)
            .load(memory, load_kind_i64, mem_arg_i64)
            .i64_const(MAX_NUM_LOG_ENTRIES as i64)
            .binop(BinaryOp::I64LtU)
            .if_else(None, write_log, increment_num_logs);
    };

    is_tracing_enabled(&mut body);
    body.if_else(None, write_log_if_not_full, |_| {});
    builder.finish(vec![func_id], &mut module.funcs)
}

/// Injects the given start and end instructions before and after the original function body.
/// Adapted from
/// https://github.com/dfinity/ic-wasm/blob/4c52e75c12bb730e795d8a4c2862987f4a9524a3/src/instrumentation.rs#L288-L398.
fn inject_function_call(
    types: &ModuleTypes,
    start: impl for<'a> FnOnce(&'a mut InstrSeqBuilder),
    end: impl for<'a> FnOnce(&'a mut InstrSeqBuilder),
    func: &mut LocalFunction,
) {
    // Put the original function body inside a block, so that if the code
    // use br_if/br_table to exit the function, we can still output the exit signal.
    let start_id = func.entry_block();
    let original_block = func.block_mut(start_id);
    let start_instrs = original_block.instrs.split_off(0);
    let start_ty = match original_block.ty {
        InstrSeqType::MultiValue(id) => {
            let valtypes = types.results(id);
            InstrSeqType::Simple(match valtypes.len() {
                0 => None,
                1 => Some(valtypes[0]),
                _ => unreachable!("Multivalue return not supported"),
            })
        }
        // top-level block is using the function signature
        InstrSeqType::Simple(_) => unreachable!(),
    };
    let mut inner_start = func.builder_mut().dangling_instr_seq(start_ty);
    *(inner_start.instrs_mut()) = start_instrs;
    let inner_start_id = inner_start.id();

    // Apply the start and end instructions before and after the original function body.
    let mut start_builder = func.builder_mut().func_body();
    start(&mut start_builder);
    start_builder.instr(Block {
        seq: inner_start_id,
    });
    end(&mut start_builder);

    let mut stack = vec![inner_start_id];
    while let Some(seq_id) = stack.pop() {
        let mut builder = func.builder_mut().instr_seq(seq_id);
        let original = builder.instrs_mut();
        let mut instrs = vec![];
        for (instr, loc) in original.iter() {
            match instr {
                Instr::Block(Block { seq }) | Instr::Loop(Loop { seq }) => {
                    stack.push(*seq);
                    instrs.push((instr.clone(), *loc));
                }
                Instr::IfElse(IfElse {
                    consequent,
                    alternative,
                }) => {
                    stack.push(*alternative);
                    stack.push(*consequent);
                    instrs.push((instr.clone(), *loc));
                }
                Instr::Return(_) => {
                    instrs.push((
                        Instr::Br(Br {
                            block: inner_start_id,
                        }),
                        *loc,
                    ));
                }
                // redirect br,br_if,br_table to inner seq id
                Instr::Br(Br { block }) if *block == start_id => {
                    instrs.push((
                        Instr::Br(Br {
                            block: inner_start_id,
                        }),
                        *loc,
                    ));
                }
                Instr::BrIf(BrIf { block }) if *block == start_id => {
                    instrs.push((
                        Instr::BrIf(BrIf {
                            block: inner_start_id,
                        }),
                        *loc,
                    ));
                }
                Instr::BrTable(BrTable { blocks, default }) => {
                    let mut blocks = blocks.clone();
                    for i in 0..blocks.len() {
                        if let Some(id) = blocks.get_mut(i) {
                            if *id == start_id {
                                *id = inner_start_id
                            };
                        }
                    }
                    let default = if *default == start_id {
                        inner_start_id
                    } else {
                        *default
                    };
                    instrs.push((Instr::BrTable(BrTable { blocks, default }), *loc));
                }
                // TODO(EXC-2021): handle `ReturnCall`/`ReturnCallIndirect` correctly.
                _ => instrs.push((instr.clone(), *loc)),
            }
        }
        *original = instrs;
    }
}

/// Injects the `__prepare_tracing` call at the start of the function. The function sets the start
/// address of the tracing buffer to the global variable.
fn inject_prepare_tracing_call(
    types: &ModuleTypes,
    traces_start_address: GlobalId,
    prepare_func: FunctionId,
    func: &mut LocalFunction,
) {
    inject_function_call(
        types,
        |builder| {
            builder.call(prepare_func).global_set(traces_start_address);
        },
        |_| {},
        func,
    );
}

/// Injects the tracing code to the function. The function calls the trace function at the start and
/// end of the function.
fn inject_tracing(
    types: &ModuleTypes,
    trace_func: FunctionId,
    id: FunctionId,
    func: &mut LocalFunction,
) {
    inject_function_call(
        types,
        |builder| {
            builder.i32_const(id.index() as i32).call(trace_func);
        },
        |builder| {
            builder
                .i32_const(reverse_func_id(id.index() as i32))
                .call(trace_func);
        },
        func,
    );
}

/// Renders the tracing to a file. Adapted from
/// https://github.com/dfinity/ic-repl/blob/master/src/tracing.rs
pub(super) fn write_traces_to_file(
    input: Vec<(i32, i64)>,
    names: &BTreeMap<i32, String>,
    bench_fn: &str,
    filename: PathBuf,
) -> Result<(), String> {
    use inferno::flamegraph::{from_reader, Options};
    let mut stack = Vec::new();
    let mut prefix = Vec::new();
    let mut result = Vec::new();
    let mut prev = None;
    for (id, count) in input.into_iter() {
        if id >= 0 {
            stack.push((id, count, 0));
            let name = if id < i32::MAX {
                match names.get(&id) {
                    Some(name) => name.clone(),
                    None => "func_".to_string() + &id.to_string(),
                }
            } else {
                bench_fn.to_string()
            };
            prefix.push(name);
        } else {
            let end_id = reverse_func_id(id);
            match stack.pop() {
                None => return Err("pop empty stack".to_string()),
                Some((start_id, start, children)) => {
                    if start_id != end_id {
                        return Err("func id mismatch".to_string());
                    }
                    let cost = count - start;
                    let frame = prefix.join(";");
                    prefix.pop().unwrap();
                    if let Some((parent, parent_cost, children_cost)) = stack.pop() {
                        stack.push((parent, parent_cost, children_cost + cost));
                    }
                    match prev {
                        Some(prev) if prev == frame => {
                            // Add an empty spacer to avoid collapsing adjacent same-named calls
                            // See https://github.com/jonhoo/inferno/issues/185#issuecomment-671393504
                            result.push(format!("{};spacer 0", prefix.join(";")));
                        }
                        _ => (),
                    }
                    result.push(format!("{} {}", frame, cost - children));
                    prev = Some(frame);
                }
            }
        }
    }
    let is_trace_incomplete = !stack.is_empty();
    let mut opt = Options::default();
    opt.count_name = "instructions".to_string();
    let bench_fn = if is_trace_incomplete {
        bench_fn.to_string() + " (incomplete)"
    } else {
        bench_fn.to_string()
    };
    opt.title = bench_fn;
    opt.flame_chart = true;
    opt.no_sort = true;
    // Reserve result order to make flamegraph from left to right.
    // See https://github.com/jonhoo/inferno/issues/236
    result.reverse();
    let logs = result.join("\n");
    let reader = std::io::Cursor::new(logs);
    let mut writer = std::fs::File::create(&filename).map_err(|e| e.to_string())?;
    from_reader(&mut opt, reader, &mut writer).map_err(|e| e.to_string())?;
    println!("Instruction traces written to {}", filename.display());
    Ok(())
}

/// Extracts function names from the module to be a map from function id to function name.
fn extract_function_names(module: &Module) -> BTreeMap<i32, String> {
    module
        .funcs
        .iter()
        .filter_map(|f| {
            if matches!(f.kind, FunctionKind::Local(_)) {
                use rustc_demangle::demangle;
                let name = f.name.as_ref()?;
                let demangled = format!("{:#}", demangle(name));
                Some((f.id().index() as i32, demangled))
            } else {
                None
            }
        })
        .collect()
}

/// Returns the reversed function id. Since the function id can be 0, we need to map 0 to -1, 1 to
/// -2, ..., i32::MAX to i32::MIN. The given id is assumed to be non-negative.
fn reverse_func_id(id: i32) -> i32 {
    // Note that -(id + 1) can overflow for i32::MAX.
    !id
}
