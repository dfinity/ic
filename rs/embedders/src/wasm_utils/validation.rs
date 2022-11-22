//! This module is responsible for validating the wasm binaries that are
//! installed on the Internet Computer.

use super::{errors::into_wasm_error, WasmImportsDetails, WasmValidationDetails};

use ic_config::embedders::Config as EmbeddersConfig;
use ic_replicated_state::canister_state::execution_state::{
    CustomSection, CustomSectionType, WasmMetadata,
};
use ic_types::{NumBytes, NumInstructions};
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};
use parity_wasm::elements::{
    DataSegment, External, ImportCountType,
    Instruction::{self},
    Internal, Module, Section, Type, ValueType,
};
use std::{
    cmp,
    collections::{BTreeMap, HashMap, HashSet},
};
use wasmtime::Config;

/// Symbols that are reserved and cannot be exported by canisters.
#[doc(hidden)] // pub for usage in tests
pub const RESERVED_SYMBOLS: [&str; 2] = ["canister counter_instructions", "canister_start"];

const WASM_FUNCTION_COMPLEXITY_LIMIT: usize = 15_000;
const WASM_FUNCTION_SIZE_LIMIT: usize = 1_000_000;

// Represents the expected function signature for any System APIs the Internet
// Computer provides or any special exported user functions.
struct FunctionSignature {
    pub param_types: Vec<ValueType>,
    pub return_type: Vec<ValueType>,
}

const METHOD_MODULE: &str = "method";
const API_VERSION_IC0: &str = "ic0";

// Constructs a map of function name -> HashMap<String,
// `FunctionSignature`> (to allow the same function to be imported from
// multiple modules) based on the System API.
//
// We use a two-level hashmap to be able to differentiate between the case a
// user tries to import a function that doesn't exist in any of the expected
// modules vs the case where the function exists but is imported from the wrong
// module.
fn get_valid_system_apis() -> HashMap<String, HashMap<String, FunctionSignature>> {
    let valid_system_apis = vec![
        (
            // Public methods
            "msg_caller_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "msg_caller_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "msg_arg_data_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "msg_method_name_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "msg_reject_msg_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "msg_reject_msg_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_reply_data_append",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32],
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
                    param_types: vec![ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "canister_self_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "controller_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "controller_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        // Inter-canister method calls
        (
            "public",
            vec![(
                METHOD_MODULE,
                FunctionSignature {
                    param_types: vec![ValueType::I64, ValueType::I32, ValueType::I32],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "call_simple",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                    ],
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "call_new",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                        ValueType::I32,
                    ],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_data_append",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_on_cleanup",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "call_cycles_add",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        // Debugging aids
        (
            "debug_print",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "stable_grow",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32],
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "stable_read",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "stable_write",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "stable64_grow",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "stable64_read",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64, ValueType::I64, ValueType::I64],
                    return_type: vec![],
                },
            )],
        ),
        (
            "stable64_write",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64, ValueType::I64, ValueType::I64],
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
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "global_timer_set",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "performance_counter",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "canister_version",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "trap",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "msg_cycles_available",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "msg_cycles_refunded",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "msg_cycles_accept",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "certified_data_set",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "data_certificate_size",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![],
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "data_certificate_copy",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32, ValueType::I32, ValueType::I32],
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
                    return_type: vec![ValueType::I32],
                },
            )],
        ),
        (
            "mint_cycles",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64],
                    return_type: vec![ValueType::I64],
                },
            )],
        ),
        (
            "call_cycles_add128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64, ValueType::I64],
                    return_type: vec![],
                },
            )],
        ),
        (
            "canister_cycle_balance128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_cycles_available128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_cycles_refunded128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I32],
                    return_type: vec![],
                },
            )],
        ),
        (
            "msg_cycles_accept128",
            vec![(
                API_VERSION_IC0,
                FunctionSignature {
                    param_types: vec![ValueType::I64, ValueType::I64, ValueType::I32],
                    return_type: vec![],
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
    function_type: &Type,
) -> Result<(), WasmValidationError> {
    let Type::Function(function_type) = function_type;
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
        "call_simple" => import_details.imports_call_simple = true,
        "controller_size" => import_details.imports_controller_size = true,
        "controller_copy" => import_details.imports_controller_copy = true,
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

    if let Some(section) = module.import_section() {
        let valid_system_apis = get_valid_system_apis();
        for entry in section.entries() {
            let import_module = entry.module();
            let field = entry.field();
            match entry.external() {
                External::Function(index) => {
                    set_imports_details(&mut imports_details, import_module, field);
                    match valid_system_apis.get(field) {
                        Some(signatures) => {
                            match signatures.get(import_module) {
                                Some(signature) => {
                                    validate_function_signature(
                                        signature,
                                        field,
                                        &module.type_section().unwrap().types()[*index as usize],
                                    )?;
                                },
                                None => {return Err(WasmValidationError::InvalidImportSection(format!(
                                    "Module imports function {:?} from {:?}, expected to be imported from one of {:?} instead.",
                                    field, import_module, signatures.keys(),
                                )))}

                            }
                        }
                        None => {
                            return Err(WasmValidationError::InvalidImportSection(format!(
                                "Module imports function '{}' from '{}' that is not exported by the runtime.",
                                field, import_module,
                            )))
                        }
                    }
                }
                External::Table(_) => {
                    if field == "table" && import_module != "env" {
                        return Err(WasmValidationError::InvalidImportSection(
                            "Only tables imported from env.table are allowed.".to_string(),
                        ));
                    }
                }
                External::Memory(_) => {
                    if field == "memory" && import_module != "env" {
                        return Err(WasmValidationError::InvalidImportSection(
                            "Only memory imported from env.memory is allowed.".to_string(),
                        ));
                    };
                }
                External::Global(_) => {
                    return Err(WasmValidationError::InvalidImportSection(
                        "Importing globals is not allowed.".to_string(),
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
//
// Returns the number of exported functions that are not in the list of
// allowed exports and whose name starts with the reserved "canister_" prefix.
fn validate_export_section(module: &Module) -> Result<usize, WasmValidationError> {
    let mut reserved_exports: usize = 0;
    if let Some(section) = module.export_section() {
        let mut seen_funcs: HashSet<&str> = HashSet::new();
        let valid_exported_functions = get_valid_exported_functions();
        for export in section.entries().iter() {
            // Verify that the exported symbol's name isn't reserved.
            if RESERVED_SYMBOLS.contains(&export.field()) {
                return Err(WasmValidationError::InvalidExportSection(format!(
                    "Exporting reserved symbol {} not allowed.",
                    export.field()
                )));
            }
            if let Internal::Function(fn_index) = export.internal() {
                let mut func_name = export.field();
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
                        return Err(WasmValidationError::InvalidExportSection(format!(
                            "Duplicate function '{}' exported multiple times \
                             with different call types: update, query, or composite_query.",
                            unmangled_func_name
                        )));
                    }
                    seen_funcs.insert(unmangled_func_name);
                } else if func_name.starts_with("canister_") {
                    // The "canister_" prefix is reserved and only functions allowed by the spec
                    // can be exported.
                    // TODO(EXC-350): Turn this into an actual error once we confirm that no
                    // reserved functions are exported.
                    if !valid_exported_functions.contains_key(func_name) {
                        reserved_exports += 1;
                    }
                }
                if let Some(valid_signature) = valid_exported_functions.get(func_name) {
                    // The function section contains only the functions defined locally in the
                    // module, so we need to subtract the number of imported functions to get the
                    // correct index from the general function space.
                    let fn_index = *fn_index as usize;
                    let import_count = module.import_count(ImportCountType::Function);
                    if fn_index < import_count {
                        return Err(WasmValidationError::InvalidFunctionIndex {
                            index: fn_index,
                            import_count,
                        });
                    }
                    let actual_fn_index = fn_index - import_count;
                    let type_index =
                        module.function_section().unwrap().entries()[actual_fn_index].type_ref();
                    validate_function_signature(
                        valid_signature,
                        export.field(),
                        &module.type_section().unwrap().types()[type_index as usize],
                    )?;
                }
            }
        }
    }
    Ok(reserved_exports)
}

// Checks that offset-expressions in data sections consist of only one constant
// expression. Required because of OP. See also:
// src/hypervisor/metering_injector/mod.rs
fn validate_data_section(module: &Module) -> Result<(), WasmValidationError> {
    fn validate_segment(s: &DataSegment) -> Result<(), WasmValidationError> {
        match s.offset() {
            None => Err(WasmValidationError::InvalidDataSection(
                "Empty offset in data segment.".to_string(),
            )),
            Some(expr) => match expr.code() {
                [Instruction::I32Const(_), Instruction::End] => Ok(()),
                _ => Err(WasmValidationError::InvalidDataSection(
                    "Invalid offset expression in data segment.".to_string(),
                )),
            },
        }
    }

    module
        .sections()
        .iter()
        .filter_map(|s| match s {
            Section::Data(s) => Some(s),
            _ => None,
        })
        .flat_map(|s| s.entries().iter())
        .try_for_each(validate_segment)
}

// Checks that no more than `max_globals` are defined in the module.
fn validate_global_section(module: &Module, max_globals: usize) -> Result<(), WasmValidationError> {
    if let Some(section) = module.global_section() {
        let globals_defined = section.entries().len();
        if globals_defined > max_globals {
            return Err(WasmValidationError::TooManyGlobals {
                defined: globals_defined,
                allowed: max_globals,
            });
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
    if let Some(section) = module.function_section() {
        let functions_defined = section.entries().len();
        if functions_defined > max_functions {
            return Err(WasmValidationError::TooManyFunctions {
                defined: functions_defined,
                allowed: max_functions,
            });
        }
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

// Performs the following checks to validate the custom sections:
// * Ensures that the names of the custom sections are unique
// * Check that visibility level is provided to a custom section
//      * `icp:public`
//      * `icp:private`
// * Checks that no more than `max_custom_sections` are defined in the
// module.
// * Checks that the size of a custom section does not exceed
// `max_custom_section_size`.
//
// Returns the validated custom sections.

// Public for usage in tests.
// TODO(EXC-787): Use validate `validate_wam_binary` once wabt fully supports
// custom sections.
#[doc(hidden)]
pub fn validate_custom_section(
    module: &Module,
    config: &EmbeddersConfig,
) -> Result<WasmMetadata, WasmValidationError> {
    let mut validated_custom_sections: BTreeMap<String, CustomSection> = BTreeMap::new();
    let custom_sections = module.custom_sections();
    let mut total_custom_sections_size = NumBytes::from(0);

    for custom_section in custom_sections {
        let payload = custom_section.payload();

        // Extract the name.
        if let Some((name, visibility)) = extract_custom_section_name(custom_section.name())? {
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

fn validate_code_section(module: &Module) -> Result<NumInstructions, WasmValidationError> {
    let mut max_function_size = NumInstructions::new(0);
    if let Some(code_section) = module.code_section() {
        for (index, func_body) in code_section.bodies().iter().enumerate() {
            let instructions = func_body.code().elements();
            let size = instructions.len();
            let complexity = instructions
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction,
                        Instruction::Block(_)
                            | Instruction::Loop(_)
                            | Instruction::If(_)
                            | Instruction::Br(_)
                            | Instruction::BrIf(_)
                            | Instruction::BrTable(_)
                            | Instruction::Call(_)
                            | Instruction::CallIndirect(_, _)
                    )
                })
                .count();

            if complexity > WASM_FUNCTION_COMPLEXITY_LIMIT {
                return Err(WasmValidationError::FunctionComplexityTooHigh {
                    index,
                    complexity,
                    allowed: WASM_FUNCTION_COMPLEXITY_LIMIT,
                });
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
    }
    Ok(max_function_size)
}

/// Sets Wasmtime flags to ensure deterministic execution.
pub fn ensure_determinism(config: &mut Config) {
    config
        .wasm_threads(false)
        .wasm_simd(false)
        .cranelift_nan_canonicalization(true);
}

fn can_compile(wasm: &BinaryEncodedWasm) -> Result<(), WasmValidationError> {
    let mut config = wasmtime::Config::default();
    ensure_determinism(&mut config);
    let engine = wasmtime::Engine::new(&config).map_err(|_| {
        WasmValidationError::WasmtimeValidation(String::from("Failed to initialize Wasm engine"))
    })?;
    wasmtime::Module::validate(&engine, wasm.as_slice()).map_err(|err| {
        WasmValidationError::WasmtimeValidation(format!(
            "wasmtime::Module::validate() failed with {}",
            err
        ))
    })
}

/// Validates a Wasm binary against the requirements of the interface spec
/// defined in https://sdk.dfinity.org/docs/interface-spec/index.html.
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
pub(super) fn validate_wasm_binary(
    wasm: &BinaryEncodedWasm,
    config: &EmbeddersConfig,
) -> Result<WasmValidationDetails, WasmValidationError> {
    can_compile(wasm)?;
    let module = parity_wasm::deserialize_buffer::<Module>(wasm.as_slice())
        .map_err(|err| WasmValidationError::WasmDeserializeError(into_wasm_error(err)))?;
    let imports_details = validate_import_section(&module)?;
    let reserved_exports = validate_export_section(&module)?;
    validate_data_section(&module)?;
    validate_global_section(&module, config.max_globals)?;
    validate_function_section(&module, config.max_functions)?;
    let largest_function_instruction_count = validate_code_section(&module)?;
    let wasm_metadata = validate_custom_section(&module, config)?;
    Ok(WasmValidationDetails {
        reserved_exports,
        imports_details,
        wasm_metadata,
        largest_function_instruction_count,
    })
}
