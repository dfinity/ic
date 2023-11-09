use ic_replicated_state::Global;
use ic_types::methods::WasmMethod;
use std::collections::BTreeSet;
use wasm_encoder::{ExportKind, GlobalType, ValType};

pub fn transform_exports<T>(exports: Vec<(String, ExportKind, T)>) -> BTreeSet<WasmMethod> {
    let mut wasm_methods: BTreeSet<WasmMethod> = BTreeSet::new();
    let canister_funcs: Vec<_> = exports
        .iter()
        .filter(|(_, ty, _)| *ty == ExportKind::Func)
        .collect();
    for (func_name, _, _) in canister_funcs.iter() {
        if func_name.starts_with("canister_query") {
            wasm_methods.insert(WasmMethod::Query(
                func_name
                    .strip_prefix("canister_query ")
                    .unwrap()
                    .to_string(),
            ));
        }

        if func_name.starts_with("canister_update") {
            wasm_methods.insert(WasmMethod::Update(
                func_name
                    .strip_prefix("canister_update ")
                    .unwrap()
                    .to_string(),
            ));
        }

        if func_name.starts_with("canister_composite_query") {
            wasm_methods.insert(WasmMethod::CompositeQuery(
                func_name
                    .strip_prefix("canister_composite_query ")
                    .unwrap()
                    .to_string(),
            ));
        }
    }
    wasm_methods
}

#[allow(dead_code)]
pub fn transform_exported_globals<T>(exported_globals: Vec<(GlobalType, T)>) -> Vec<Global> {
    // TODO(PSEC-1574) Unable to extract value from wasm_encoder::ConstExpr since
    // it's fields are private. Passing 0 temporarily
    let mut persisted_globals: Vec<Global> = exported_globals
        .iter()
        .filter_map(|(global, _expr)| match global.val_type {
            ValType::I32 => Some(Global::I32(0_i32)),
            ValType::I64 => Some(Global::I64(0_i64)),
            ValType::F32 => Some(Global::F32(0 as f32)),
            ValType::F64 => Some(Global::F64(0 as f64)),
            _ => None,
        })
        .collect();

    // An extra global is added for instruction counter.
    // On the exporting logic, two other globals must be exported
    // but they are not persisted across ExecutionState.
    // const TO_IGNORE: &[&str] = &[
    //     DIRTY_PAGES_COUNTER_GLOBAL_NAME,
    //     ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
    // ];
    //
    // Instruction counter shouldn't be persisted as well since
    // it's overwritten with instruction limit every round.
    // However, this is currently not done in the embedders library
    // and we have to persist it to pass a validation check.
    // It can be removed once instruction counter isn't persisted
    // in our library.

    persisted_globals.push(Global::I64(i64::MAX));
    persisted_globals
}
