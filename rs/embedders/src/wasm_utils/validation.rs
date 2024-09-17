//! This module is responsible for validating the wasm binaries that are
//! installed on the Internet Computer.

use super::{Complexity, WasmImportsDetails, WasmValidationDetails};

use ic_config::embedders::Config as EmbeddersConfig;
use ic_replicated_state::canister_state::execution_state::{
    CustomSection, CustomSectionType, WasmMetadata,
};
use ic_types::{NumBytes, NumInstructions, MAX_STABLE_MEMORY_IN_BYTES};
use ic_wasm_transform::{Body, DataSegment, DataSegmentKind, Module};
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};
use std::{
    cmp,
    collections::{BTreeMap, HashMap, HashSet},
};

use crate::wasmtime_embedder::{
    STABLE_BYTEMAP_MEMORY_NAME, STABLE_MEMORY_NAME, WASM_HEAP_MEMORY_NAME,
};
use crate::{
    wasm_utils::instrumentation::{
        main_memory_type, WasmMemoryType, ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
        DIRTY_PAGES_COUNTER_GLOBAL_NAME, WASM_PAGE_SIZE,
    },
    MAX_WASM_STACK_SIZE, MIN_GUARD_REGION_SIZE,
};
use wasmparser::{CompositeInnerType, ExternalKind, FuncType, Operator, TypeRef, ValType};

/// Symbols that are reserved and cannot be exported by canisters.
#[doc(hidden)] // pub for usage in tests
pub const RESERVED_SYMBOLS: [&str; 6] = [
    "canister counter_instructions",
    "canister_start",
    DIRTY_PAGES_COUNTER_GLOBAL_NAME,
    ACCESSED_PAGES_COUNTER_GLOBAL_NAME,
    STABLE_MEMORY_NAME,
    STABLE_BYTEMAP_MEMORY_NAME,
];

const WASM_FUNCTION_COMPLEXITY_LIMIT: Complexity = Complexity(1_000_000);
pub const WASM_FUNCTION_SIZE_LIMIT: usize = 1_000_000;
pub const MAX_CODE_SECTION_SIZE_IN_BYTES: u32 = 10 * 1024 * 1024;

// Represents the expected function signature for any System APIs the Internet
// Computer provides or any special exported user functions.
struct FunctionSignature {
    pub param_types: Vec<ValType>,
    pub return_type: Vec<ValType>,
}

pub(super) const API_VERSION_IC0: &str = "ic0";

// Constructs a map of function name -> HashMap<String,
// `FunctionSignature`> (to allow the same function to be imported from
// multiple modules) based on the System API.
//
// We use a two-level hashmap to be able to differentiate between the case a
// user tries to import a function that doesn't exist in any of the expected
// modules vs the case where the function exists but is imported from the wrong
// module.
// Returns system api functions available only in wasm32 mode
fn get_valid_system_apis_32_only() -> HashMap<String, HashMap<String, FunctionSignature>> {
    let valid_system_apis = vec![
        (
            "call_cycles_add",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64],
                    return_type: vec![],
                },
            )],
        ),
        (
            "stable_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "stable_grow",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I32],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "stable_read",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I32, ValType::I32, ValType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "stable_write",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I32, ValType::I32, ValType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "canister_cycle_balance",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "msg_cycles_available",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "msg_cycles_refunded",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "msg_cycles_accept",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
    ];

    valid_system_apis
        .into_iter()
        .map(|(func_name, signatures)| {
            (
                func_name.to_string(),
                signatures
                    .into_iter()
                    .map(|(module, signature)| (module.to_string(), signature))
                    .collect(),
            )
        })
        .collect()
}

// Returns system api functions available both in wasm32 and wasm64
#[allow(non_snake_case)]
fn get_valid_system_apis_common(I: ValType) -> HashMap<String, HashMap<String, FunctionSignature>> {
    let valid_system_apis = vec![
        (
            // Public methods
            "msg_caller_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![I],
                },
            )],
        ),
        (
            "msg_caller_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_arg_data_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![I],
                },
            )],
        ),
        (
            "msg_arg_data_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_method_name_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![I],
                },
            )],
        ),
        (
            "msg_method_name_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "accept_message",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_reject_code",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "msg_reject_msg_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![I],
                },
            )],
        ),
        (
            "msg_reject_msg_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_reply_data_append",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_reply",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_reject",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "canister_self_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![I],
                },
            )],
        ),
        (
            "canister_self_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        // Inter-canister method calls
        (
            "call_new",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I, I, I, I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_data_append",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_on_cleanup",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_perform",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        // Debugging aids
        (
            "debug_print",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "stable64_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "stable64_grow",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "stable64_read",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64, ValType::I64, ValType::I64],
                    return_type: vec![],
                },
            )],
        ),
        (
            "stable64_write",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64, ValType::I64, ValType::I64],
                    return_type: vec![],
                },
            )],
        ),
        (
            "time",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "global_timer_set",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "performance_counter",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I32],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "canister_version",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "trap",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "certified_data_set",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "data_certificate_present",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "data_certificate_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![I],
                },
            )],
        ),
        (
            "data_certificate_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "canister_status",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "mint_cycles",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
        (
            "call_cycles_add128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64, ValType::I64],
                    return_type: vec![],
                },
            )],
        ),
        (
            "canister_cycle_balance128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_cycles_available128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_cycles_refunded128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_cycles_accept128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64, ValType::I64, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "is_controller",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![I, I],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "in_replicated_execution",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I32],
                },
            )],
        ),
        (
            "cycles_burn128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I64, ValType::I64, I],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_with_best_effort_response",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_deadline",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValType::I64],
                },
            )],
        ),
    ];

    valid_system_apis
        .into_iter()
        .map(|(func_name, signatures)| {
            (
                func_name.to_string(),
                signatures
                    .into_iter()
                    .map(|(module, signature)| (module.to_string(), signature))
                    .collect(),
            )
        })
        .collect()
}

// Constructs a map of function name -> `FunctionSignature` based on the
// special user exported functions allowed in the interface spec.
fn get_valid_exported_functions() -> HashMap<String, FunctionSignature> {
    let valid_exported_functions = vec![
        (
            "canister_init",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_update",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_query",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_composite_query",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_pre_upgrade",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_post_upgrade",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_inspect_message",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_heartbeat",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
        (
            "canister_global_timer",
            FunctionSignature {
                param_types: vec![],
                return_type: vec![],
            },
        ),
    ];

    valid_exported_functions
        .into_iter()
        .map(|(func_name, signature)| (func_name.to_string(), signature))
        .collect()
}

// Validates an input function signature by comparing against the provided
// expected function signature.
fn validate_function_signature(
    expected_signature: &FunctionSignature,
    field: &str,
    function_type: &FuncType,
) -> Result<(), WasmValidationError> {
    if function_type.params() != expected_signature.param_types.as_slice() {
        return Err(WasmValidationError::InvalidFunctionSignature(format!(
            "Expected input params {:?} for '{}', got {:?}.",
            expected_signature.param_types,
            field,
            function_type.params()
        )));
    }

    if function_type.results() != expected_signature.return_type {
        return Err(WasmValidationError::InvalidFunctionSignature(format!(
            "Expected return type {:?} for '{}', got {:?}.",
            expected_signature.return_type,
            field,
            function_type.results()
        )));
    }
    Ok(())
}

fn set_imports_details(import_details: &mut WasmImportsDetails, import_module: &str, field: &str) {
    if import_module != API_VERSION_IC0 {
        return;
    }
    match field {
        "call_cycles_add" => import_details.imports_call_cycles_add = true,
        "canister_cycle_balance" => import_details.imports_canister_cycle_balance = true,
        "msg_cycles_available" => import_details.imports_msg_cycles_available = true,
        "msg_cycles_refunded" => import_details.imports_msg_cycles_refunded = true,
        "msg_cycles_accept" => import_details.imports_msg_cycles_accept = true,
        "mint_cycles" => import_details.imports_mint_cycles = true,
        _ => {}
    }
}

// Performs the following checks for the import section:
// * If we import memory or table, we can only import from “env”.
// * Any imported functions that appear in `valid_system_apis` have the correct
//   signatures.
//
// Returns information about what IC0 methods are imported via
// `WasmImportsDetails`.
fn validate_import_section(module: &Module) -> Result<WasmImportsDetails, WasmValidationError> {
    let mut imports_details = WasmImportsDetails::default();

    if !module.imports.is_empty() {
        let valid_system_apis = match main_memory_type(module) {
            WasmMemoryType::Wasm32 => {
                let mut all = get_valid_system_apis_common(ValType::I32);
                all.extend(get_valid_system_apis_32_only());
                all
            }
            WasmMemoryType::Wasm64 => get_valid_system_apis_common(ValType::I64),
        };
        for entry in &module.imports {
            let import_module = entry.module;
            let field = entry.name;
            match &entry.ty {
                TypeRef::Func(index) => {
                    let func_ty = if let CompositeInnerType::Func(func_ty) =
                        &module.types[*index as usize].composite_type.inner
                    {
                        func_ty
                    } else {
                        return Err(WasmValidationError::InvalidImportSection(format!(
                            "Function import doesn't have a function type. Type found: {:?}",
                            &module.types[*index as usize]
                        )));
                    };
                    set_imports_details(&mut imports_details, import_module, field);
                    match valid_system_apis.get(field) {
                        Some(signatures) => {
                            match signatures.get(import_module) {
                                Some(signature) => {
                                    validate_function_signature(
                                        signature,
                                        field,
                                        func_ty,
                                    )?;
                                },
                                None => {return Err(WasmValidationError::InvalidImportSection(format!(
                                    "Module imports function {:?} from {:?}, expected to be imported from one of {:?} instead.",
                                    field, import_module, signatures.keys(),
                                )))}

                            }
                        },
                        None => {
                            return Err(WasmValidationError::InvalidImportSection(format!(
                                "Module imports function '{}' from '{}' that is not exported by the runtime.",
                                field, import_module,
                            )))
                        }
                    }
                }
                TypeRef::Table(_) => {
                    if field == "table" && import_module != "env" {
                        return Err(WasmValidationError::InvalidImportSection(
                            "Only tables imported from env.table are allowed.".to_string(),
                        ));
                    }
                }
                TypeRef::Memory(_) => {
                    if field == WASM_HEAP_MEMORY_NAME && import_module != "env" {
                        return Err(WasmValidationError::InvalidImportSection(
                            "Only memory imported from env.memory is allowed.".to_string(),
                        ));
                    };
                }
                TypeRef::Global(_) => {
                    return Err(WasmValidationError::InvalidImportSection(
                        "Importing globals is not allowed.".to_string(),
                    ))
                }
                TypeRef::Tag(_) => {
                    return Err(WasmValidationError::InvalidImportSection(
                        "Importing tags is not allowed.".to_string(),
                    ))
                }
            }
        }
    }
    Ok(imports_details)
}

// Performs the following checks:
// * Validates signatures of exported canister_update and canister_query
//   methods.
// * Validates the signatures of other allowed exported functions (like
//   `canister_init` or `canister_pre_upgrade`) if present.
// * Validates that the canister doesn't export any reserved symbols
// * Validates that all exported functions whose names start
//   with the reserved "canister_" prefix are in the list of allowed exports.
fn validate_export_section(
    module: &Module,
    max_number_exported_functions: usize,
    max_sum_exported_function_name_lengths: usize,
) -> Result<(), WasmValidationError> {
    if !module.exports.is_empty() {
        let imported_function_types: Vec<_> = module
            .imports
            .iter()
            .filter_map(|i| match i.ty {
                TypeRef::Func(type_index) => Some(&module.types[type_index as usize]),
                _ => None,
            })
            .collect();

        let mut seen_funcs: HashSet<&str> = HashSet::new();
        let valid_exported_functions = get_valid_exported_functions();
        let valid_system_functions = [
            "canister_init",
            "canister_pre_upgrade",
            "canister_post_upgrade",
            "canister_inspect_message",
            "canister_heartbeat",
            "canister_global_timer",
        ];
        let mut number_exported_functions = 0;
        let mut sum_exported_function_name_lengths = 0;
        for export in &module.exports {
            // Verify that the exported symbol's name isn't reserved.
            if RESERVED_SYMBOLS.contains(&export.name) {
                return Err(WasmValidationError::InvalidExportSection(format!(
                    "Exporting reserved symbol {} not allowed.",
                    export.name
                )));
            }
            if ExternalKind::Func == export.kind {
                let fn_index = export.index;
                let mut func_name = export.name;
                // func_name holds either:
                // - the entire exported non-IC function names, or
                // - canister_query or canister_update part in case of the IC functions.
                if func_name.starts_with("canister_query ")
                    || func_name.starts_with("canister_composite_query ")
                    || func_name.starts_with("canister_update ")
                {
                    let parts: Vec<&str> = func_name.splitn(2, ' ').collect();
                    func_name = parts[0];
                    let unmangled_func_name = parts[1];
                    if seen_funcs.contains(unmangled_func_name) {
                        return Err(WasmValidationError::DuplicateExport {
                            name: unmangled_func_name.to_string(),
                        });
                    }
                    seen_funcs.insert(unmangled_func_name);
                    number_exported_functions += 1;
                    sum_exported_function_name_lengths += unmangled_func_name.len();
                } else if func_name.starts_with("canister_") {
                    // The "canister_" prefix is reserved and only functions allowed by the spec
                    // can be exported.
                    if !valid_system_functions.contains(&func_name) {
                        return Err(WasmValidationError::InvalidExportSection(format!(
                            "Exporting reserved function '{}' with \"canister_\" prefix",
                            func_name
                        )));
                    }
                }
                if let Some(valid_signature) = valid_exported_functions.get(func_name) {
                    // The function section contains only the functions defined locally in the
                    // module, so we need to subtract the number of imported functions to get the
                    // correct index from the general function space.
                    let fn_index = fn_index as usize;
                    let import_count = imported_function_types.len();
                    let composite_type = if fn_index < import_count {
                        &imported_function_types[fn_index].composite_type
                    } else {
                        let actual_fn_index = fn_index - import_count;
                        let type_index = module.functions[actual_fn_index] as usize;
                        &module.types[type_index].composite_type
                    };
                    let CompositeInnerType::Func(func_ty) = &composite_type.inner else {
                        return Err(WasmValidationError::InvalidExportSection(format!(
                            "Function export doesn't have a function type. Type found: {:?}",
                            composite_type
                        )));
                    };
                    validate_function_signature(valid_signature, export.name, func_ty)?;
                }
            }
        }

        if number_exported_functions > max_number_exported_functions {
            return Err(WasmValidationError::TooManyExports {
                defined: number_exported_functions,
                allowed: max_number_exported_functions,
            });
        }

        if sum_exported_function_name_lengths > max_sum_exported_function_name_lengths {
            return Err(WasmValidationError::ExportedNamesTooLong {
                total_length: sum_exported_function_name_lengths,
                allowed: max_sum_exported_function_name_lengths,
            });
        }
    }
    Ok(())
}

// Checks that offset-expressions in active data segments consist of only one constant
// expression. Required because of OP. See also:
// instrumentation.rs
fn validate_data_section(module: &Module) -> Result<(), WasmValidationError> {
    fn validate_segment(
        s: &DataSegment,
        mem_type: WasmMemoryType,
    ) -> Result<(), WasmValidationError> {
        match (&s.kind, mem_type) {
            (DataSegmentKind::Passive, _) => Ok(()),
            (
                DataSegmentKind::Active {
                    memory_index: _,
                    offset_expr,
                },
                WasmMemoryType::Wasm32,
            ) => match offset_expr {
                Operator::I32Const { .. } => Ok(()),
                _ => Err(WasmValidationError::InvalidDataSection(format!(
                    "Invalid offset expression in data segment for 32bit memory: {:?}",
                    offset_expr
                ))),
            },
            (
                DataSegmentKind::Active {
                    memory_index: _,
                    offset_expr,
                },
                WasmMemoryType::Wasm64,
            ) => match offset_expr {
                Operator::I64Const { .. } => Ok(()),
                _ => Err(WasmValidationError::InvalidDataSection(format!(
                    "Invalid offset expression in data segment for 64bit memory: {:?}",
                    offset_expr
                ))),
            },
        }
    }

    let mem_type = main_memory_type(module);

    for d in &module.data {
        validate_segment(d, mem_type)?;
    }
    Ok(())
}

fn validate_wasm_memory_size(
    module: &Module,
    max_wasm_memory_size: NumBytes,
) -> Result<(), WasmValidationError> {
    if let Some(mem) = module.memories.first() {
        if mem.memory64 {
            // This check is only needed by Wasm64 modules, for Wasm32 the check is done by Wasmtime.
            if let Some(declared_size_in_wasm_pages) = mem.maximum {
                let allowed_size_in_wasm_pages = max_wasm_memory_size.get() / WASM_PAGE_SIZE as u64;
                if declared_size_in_wasm_pages > allowed_size_in_wasm_pages {
                    return Err(WasmValidationError::WasmMemoryTooLarge {
                        defined_size: declared_size_in_wasm_pages,
                        allowed_size: allowed_size_in_wasm_pages,
                    });
                }
            }
        }
    }
    Ok(())
}

// Checks that no more than `max_globals` are defined in the module
// and all globals have supported type.
fn validate_global_section(module: &Module, max_globals: usize) -> Result<(), WasmValidationError> {
    if module.globals.len() > max_globals {
        return Err(WasmValidationError::TooManyGlobals {
            defined: module.globals.len(),
            allowed: max_globals,
        });
    }
    for global in &module.globals {
        match global.ty.content_type {
            ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64 | ValType::V128 => (),
            _ => {
                return Err(WasmValidationError::InvalidGlobalSection(format!(
                    "Unsupported global type: {:?}",
                    global.ty.content_type
                )))
            }
        }
    }
    Ok(())
}

// Checks that no more than `max_functions` are defined in the
// module.
fn validate_function_section(
    module: &Module,
    max_functions: usize,
) -> Result<(), WasmValidationError> {
    if module.functions.len() > max_functions {
        return Err(WasmValidationError::TooManyFunctions {
            defined: module.functions.len(),
            allowed: max_functions,
        });
    }
    Ok(())
}

// Extracts the name of the custom section.
// Possible options:
//      * icp:public <name>
//      * icp:private <name>
// Where <name> is an arbitrary string (empty names are allowed).
// If the name starts with the prefix `icp:` but does not define
// the visibility `private` or `public` then this custom name is invalid.
#[doc(hidden)] // pub for usage in tests
pub fn extract_custom_section_name(
    section_name: &str,
) -> Result<Option<(&str, CustomSectionType)>, WasmValidationError> {
    if !section_name.starts_with("icp:") {
        // Ignore custom section name which does not start with `icp:`.
        return Ok(None);
    }

    if let Some(name) = section_name.strip_prefix("icp:public ") {
        return Ok(Some((name, CustomSectionType::Public)));
    }

    if let Some(name) = section_name.strip_prefix("icp:private ") {
        return Ok(Some((name, CustomSectionType::Private)));
    }

    if section_name == "icp:public" || section_name == "icp:private" {
        return Err(WasmValidationError::InvalidCustomSection(
            "'icp:' section names must have a space after the public/private scope".to_string(),
        ));
    }

    Err(WasmValidationError::InvalidCustomSection(format!(
        "Invalid custom section: Custom section '{}' has no public/private scope defined.",
        section_name
    )))
}

#[test]
fn test_extract_section_name() {
    assert_eq!(
        extract_custom_section_name("icp:public "),
        Ok(Some(("", CustomSectionType::Public))),
    );
    assert_eq!(
        extract_custom_section_name("icp:private "),
        Ok(Some(("", CustomSectionType::Private))),
    );
    assert_eq!(
        extract_custom_section_name("icp:public name"),
        Ok(Some(("name", CustomSectionType::Public))),
    );
    assert_eq!(
        extract_custom_section_name("icp:private name"),
        Ok(Some(("name", CustomSectionType::Private))),
    );
    assert_eq!(
        extract_custom_section_name("icp:public   name"),
        Ok(Some(("  name", CustomSectionType::Public))),
    );
    assert_eq!(
        extract_custom_section_name("icp:private   name"),
        Ok(Some(("  name", CustomSectionType::Private))),
    );
    assert_eq!(
        extract_custom_section_name("icp:public static void main"),
        Ok(Some(("static void main", CustomSectionType::Public))),
    );
    assert_eq!(
        extract_custom_section_name("icp:private static void main"),
        Ok(Some(("static void main", CustomSectionType::Private))),
    );

    extract_custom_section_name("icp:protected name").unwrap_err();
    extract_custom_section_name("icp:public").unwrap_err();
    extract_custom_section_name("icp:private").unwrap_err();

    assert_eq!(extract_custom_section_name("eth:private name"), Ok(None));
    assert_eq!(extract_custom_section_name(" icp:private name"), Ok(None));
    assert_eq!(extract_custom_section_name(" icp:private name"), Ok(None));
    assert_eq!(extract_custom_section_name("eth:private"), Ok(None));
}

/// Performs the following checks to validate the custom sections:
/// * Ensures that the names of the custom sections are unique
/// * Check that visibility level is provided to a custom section
///      * `icp:public`
///      * `icp:private`
/// * Checks that no more than `max_custom_sections` are defined in the
///   module.
/// * Checks that the size of a custom section does not exceed
///   `max_custom_section_size`.
///
/// Returns the validated custom sections.
fn validate_custom_section(
    module: &Module,
    config: &EmbeddersConfig,
) -> Result<WasmMetadata, WasmValidationError> {
    let mut validated_custom_sections: BTreeMap<String, CustomSection> = BTreeMap::new();
    let mut total_custom_sections_size = NumBytes::from(0);

    for custom_section in &module.custom_sections {
        let payload = custom_section.1;
        let section_name = custom_section.0;

        // Extract the name.
        if let Some((name, visibility)) = extract_custom_section_name(section_name)? {
            if validated_custom_sections.contains_key(name) {
                return Err(WasmValidationError::InvalidCustomSection(format!(
                    "Invalid custom section: name {} already exists",
                    name
                )));
            }

            // Check the total accumulated size of the custom sections.
            let size_custom_section = NumBytes::new((payload.len() + name.len()) as u64);
            total_custom_sections_size += size_custom_section;
            if total_custom_sections_size > config.max_custom_sections_size {
                return Err(WasmValidationError::InvalidCustomSection(format!(
                        "Invalid custom sections: total size of the custom sections exceeds the maximum allowed: size {} bytes, allowed {} bytes",
                        total_custom_sections_size, config.max_custom_sections_size
                    )));
            }

            validated_custom_sections.insert(
                name.to_string(),
                CustomSection::new(visibility, payload.to_vec()),
            );

            // Check that adding a new custom section does not exceed `max_custom_sections`
            // allowed.
            if validated_custom_sections.len() > config.max_custom_sections {
                return Err(WasmValidationError::TooManyCustomSections {
                    defined: validated_custom_sections.len(),
                    allowed: config.max_custom_sections,
                });
            }
        }
    }

    Ok(WasmMetadata::new(validated_custom_sections))
}

fn wasm_function_complexity(
    index: usize,
    body: &Body<'_>,
) -> Result<Complexity, WasmValidationError> {
    use Operator::*;

    let mut complexity: u64 = 0;
    for instruction in &body.instructions {
        complexity = complexity.saturating_add(match instruction {
            Block { .. }
            | Loop { .. }
            | If { .. }
            | Br { .. }
            | BrIf { .. }
            | BrTable { .. }
            | Call { .. }
            | CallIndirect { .. }
            | MemoryGrow { .. } => 50,
            TableGrow { .. } => {
                return Err(WasmValidationError::UnsupportedWasmInstruction {
                    index,
                    instruction: "table.grow".into(),
                });
            }
            TableGet { .. } => 14,
            RefFunc { .. } => 8,
            TableSet { .. } => {
                return Err(WasmValidationError::UnsupportedWasmInstruction {
                    index,
                    instruction: "table.set".into(),
                });
            }
            RefIsNull => 6,
            TableFill { .. } => {
                return Err(WasmValidationError::UnsupportedWasmInstruction {
                    index,
                    instruction: "table.fill".into(),
                });
            }
            I32TruncF32S | I32TruncF32U | I32TruncF64S | I32TruncF64U | I64ExtendI32S
            | I64ExtendI32U | I64TruncF32S | I64TruncF32U | I64TruncF64S | I64TruncF64U
            | F32ConvertI32S | F32ConvertI32U | F32ConvertI64S | F32ConvertI64U | F32DemoteF64
            | F64ConvertI32S | F64ConvertI32U | F64ConvertI64S | F64ConvertI64U => 5,
            F32Neg | F32Abs | F64Neg | F64Abs | MemoryCopy { .. } => 4,
            TableCopy { .. } => {
                return Err(WasmValidationError::UnsupportedWasmInstruction {
                    index,
                    instruction: "table.copy".into(),
                });
            }
            TableInit { .. } => {
                return Err(WasmValidationError::UnsupportedWasmInstruction {
                    index,
                    instruction: "table.init".into(),
                });
            }
            F32Copysign
            | F64Copysign
            | F64Eq
            | I32RemU
            | I32RemS
            | I64RemU
            | I64RemS
            | I32DivU
            | I32DivS
            | I64DivU
            | I64DivS
            | MemoryFill { .. }
            | I32Load { .. }
            | I64Load { .. }
            | F32Load { .. }
            | F64Load { .. }
            | I32Load8S { .. }
            | I32Load8U { .. }
            | I32Load16S { .. }
            | I32Load16U { .. }
            | I64Load8S { .. }
            | I64Load8U { .. }
            | I64Load16S { .. }
            | I64Load16U { .. }
            | I64Load32S { .. }
            | I64Load32U { .. }
            | I32TruncSatF32S
            | I32TruncSatF32U
            | I32TruncSatF64S
            | I32TruncSatF64U
            | I64TruncSatF32S
            | I64TruncSatF32U
            | I64TruncSatF64S
            | I64TruncSatF64U => 3,
            GlobalGet { .. }
            | I32Popcnt
            | I64Popcnt
            | Select
            | MemorySize { .. }
            | I32Store { .. }
            | I32Store16 { .. }
            | I32Store8 { .. }
            | I64Store { .. }
            | I64Store32 { .. }
            | I64Store16 { .. }
            | I64Store8 { .. }
            | F64Store { .. }
            | F32Store { .. }
            | I32Eqz
            | I32Eq
            | I32Ne
            | I32LtS
            | I32LtU
            | I32GtS
            | I32GtU
            | I32LeS
            | I32LeU
            | I32GeS
            | I32GeU
            | I64Eqz
            | I64Eq
            | I64Ne
            | I64LtS
            | I64LtU
            | I64GtS
            | I64GtU
            | I64LeS
            | I64LeU
            | I64GeS
            | I64GeU
            | F32Eq
            | F32Ne
            | F32Lt
            | F32Gt
            | F32Le
            | F32Ge
            | F64Ne
            | F64Lt
            | F64Gt
            | F64Le
            | F64Ge
            | F32Ceil
            | F64Ceil
            | F32Floor
            | F64Floor
            | F32Sqrt
            | F64Sqrt
            | F32Trunc
            | F64Trunc
            | I32ReinterpretF32
            | I64ReinterpretF64
            | F32ReinterpretI32
            | F64ReinterpretI64
            | I32WrapI64
            | I32Extend8S
            | I32Extend16S
            | I64Extend8S
            | I64Extend16S
            | I64Extend32S
            | F64PromoteF32 => 2,
            _ => 1,
        });
    }
    Ok(Complexity(complexity))
}

fn validate_code_section(
    module: &Module,
) -> Result<(NumInstructions, Complexity), WasmValidationError> {
    let mut max_function_size = NumInstructions::new(0);
    let mut max_complexity = Complexity(0);

    for (index, func_body) in module.code_sections.iter().enumerate() {
        let size = func_body.instructions.len();
        let complexity = wasm_function_complexity(index, func_body)?;
        if complexity > WASM_FUNCTION_COMPLEXITY_LIMIT {
            return Err(WasmValidationError::FunctionComplexityTooHigh {
                index,
                complexity: complexity.0 as usize,
                allowed: WASM_FUNCTION_COMPLEXITY_LIMIT.0 as usize,
            });
        } else {
            max_complexity = cmp::max(max_complexity, complexity);
        }

        if size > WASM_FUNCTION_SIZE_LIMIT {
            return Err(WasmValidationError::FunctionTooLarge {
                index,
                size,
                allowed: WASM_FUNCTION_SIZE_LIMIT,
            });
        } else {
            max_function_size = cmp::max(max_function_size, NumInstructions::new(size as u64));
        }
    }
    Ok((max_function_size, max_complexity))
}

/// Returns a Wasmtime config that is used for Wasm validation.
pub fn wasmtime_validation_config(embedders_config: &EmbeddersConfig) -> wasmtime::Config {
    let mut config = wasmtime::Config::default();

    // Keep this in the alphabetical order to simplify comparison with new
    // `wasmtime::Config` methods in a new version of wasmtime.

    // NaN canonicalization is needed for determinism.
    config.cranelift_nan_canonicalization(true);
    // Disable optimizations to keep compilation simple and fast.
    // The assumption is that Wasm binaries have already been optimized.
    config.cranelift_opt_level(wasmtime::OptLevel::None);
    // Disabling the address map saves about 20% of compile code size.
    config.generate_address_map(false);
    // The signal handler uses Posix signals, not Mach ports on MacOS.
    config.macos_use_mach_ports(false);
    config.wasm_backtrace(false);
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
    config.wasm_bulk_memory(true);
    config.wasm_function_references(false);
    config.wasm_gc(false);
    if embedders_config.feature_flags.wasm64 == ic_config::flag_status::FlagStatus::Enabled {
        config.wasm_memory64(true);
    } else {
        config.wasm_memory64(false);
    }
    // Wasm multi-memory feature is disabled during validation,
    // but enabled during execution for the Wasm-native stable memory
    // implementation.
    config.wasm_multi_memory(false);
    config.wasm_reference_types(true);
    // The relaxed SIMD instructions are disable for determinism.
    config.wasm_relaxed_simd(false);
    // Tail calls may be enabled in the future.
    config.wasm_tail_call(false);

    config
        // The maximum size in bytes where a linear memory is considered
        // static. Setting this to maximum Wasm memory size will guarantee
        // the memory is always static.
        //
        // If there is a change in the size of the largest memories we
        // expect to see then the changes will likely need to be coordinated
        // with a change in how we create the memories in the implementation
        // of `wasmtime::MemoryCreator`.
        .static_memory_maximum_size(MAX_STABLE_MEMORY_IN_BYTES)
        .guard_before_linear_memory(true)
        .static_memory_guard_size(MIN_GUARD_REGION_SIZE as u64)
        .max_wasm_stack(MAX_WASM_STACK_SIZE);
    config
}

#[test]
fn can_create_engine_from_validation_config() {
    let config = wasmtime_validation_config(&EmbeddersConfig::default());
    wasmtime::Engine::new(&config).expect("Cannot create engine from validation config");
}

fn can_compile(
    wasm: &BinaryEncodedWasm,
    embedders_config: &EmbeddersConfig,
) -> Result<(), WasmValidationError> {
    let config = wasmtime_validation_config(embedders_config);
    let engine = wasmtime::Engine::new(&config).expect("Failed to create wasmtime::Engine");
    wasmtime::Module::validate(&engine, wasm.as_slice()).map_err(|err| {
        WasmValidationError::WasmtimeValidation(format!(
            "wasmtime::Module::validate() failed with {}",
            err
        ))
    })
}

fn check_code_section_size(wasm: &BinaryEncodedWasm) -> Result<(), WasmValidationError> {
    let parser = wasmparser::Parser::new(0);
    let payloads = parser.parse_all(wasm.as_slice());
    for payload in payloads {
        if let wasmparser::Payload::CodeSectionStart {
            count: _,
            range: _,
            size,
        } = payload.map_err(|e| {
            WasmValidationError::DecodingError(format!("Error finding code section: {}", e))
        })? {
            if size > MAX_CODE_SECTION_SIZE_IN_BYTES {
                return Err(WasmValidationError::CodeSectionTooLarge {
                    size,
                    allowed: MAX_CODE_SECTION_SIZE_IN_BYTES,
                });
            } else {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Validates a Wasm binary against the requirements of the interface spec
/// defined in https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-module.
///
/// It constructs a module by parsing the input Wasm binary and then calls into
/// more specific methods that validate different sections of the Wasm binary.
/// Currently, the sections we verify are:
/// * Import
/// * Export
/// * Code
/// * Data
/// * Global
/// * Function
/// * CustomSections
///
/// Additionally, it ensures that the wasm binary can actually compile.
pub(super) fn validate_wasm_binary<'a>(
    wasm: &'a BinaryEncodedWasm,
    config: &EmbeddersConfig,
) -> Result<(WasmValidationDetails, Module<'a>), WasmValidationError> {
    check_code_section_size(wasm)?;
    can_compile(wasm, config)?;
    let module = Module::parse(wasm.as_slice(), false)
        .map_err(|err| WasmValidationError::DecodingError(format!("{}", err)))?;
    let imports_details = validate_import_section(&module)?;
    validate_export_section(
        &module,
        config.max_number_exported_functions,
        config.max_sum_exported_function_name_lengths,
    )?;
    validate_data_section(&module)?;
    validate_global_section(&module, config.max_globals)?;
    validate_function_section(&module, config.max_functions)?;
    validate_wasm_memory_size(&module, config.max_wasm_memory_size)?;
    let (largest_function_instruction_count, max_complexity) = validate_code_section(&module)?;
    let wasm_metadata = validate_custom_section(&module, config)?;
    Ok((
        WasmValidationDetails {
            imports_details,
            wasm_metadata,
            largest_function_instruction_count,
            max_complexity,
        },
        module,
    ))
}
