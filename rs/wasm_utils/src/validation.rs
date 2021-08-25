//! This module is responsible for validating the wasm binaries that are
//! installed on the Internet Computer.

use crate::{ensure_determinism, errors::into_parity_wasm_error};
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};
use parity_wasm::elements::{
    DataSegment, External, ImportCountType,
    Instruction::{self},
    Internal, Module, Section, Type, ValueType,
};
use std::collections::{HashMap, HashSet};

/// Symbols that are reserved and cannot be exported by canisters.
#[doc(hidden)] // pub for usage in tests
pub const RESERVED_SYMBOLS: [&str; 4] = [
    "canister counter_instructions",
    "canister counter_get",
    "canister counter_set",
    "canister_start",
];

// Represents the expected function signature for any System APIs the Internet
// Computer provides or any special exported user functions.
struct FunctionSignature {
    pub param_types: Vec<ValueType>,
    pub return_type: Vec<ValueType>,
}

/// Controls how many globals and functions are allowed in a Wasm module on the
/// Internet Computer.
//
// Note that we define a struct with the two limits instead of just passing them
// to `validate_wasm_binary` to make it easier and safer to use as a caller
// without worrying about mixing the two up (since they're both of type
// `usize`).
pub struct WasmValidationLimits {
    /// Maximum number of globals allowed in a module.
    pub max_globals: usize,
    /// Maximum number of functions allowed in a module.
    pub max_functions: usize,
}

impl Default for WasmValidationLimits {
    fn default() -> Self {
        Self {
            max_globals: 200,
            max_functions: 6000,
        }
    }
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
                    || func_name.starts_with("canister_update ")
                {
                    let parts: Vec<&str> = func_name.splitn(2, ' ').collect();
                    let unmangled_func_name = parts[1];
                    if seen_funcs.contains(unmangled_func_name) {
                        return Err(WasmValidationError::InvalidExportSection(format!(
                            "Duplicate function '{}' exported for both update calls and queries.",
                            unmangled_func_name
                        )));
                    }
                    seen_funcs.insert(unmangled_func_name);
                    func_name = parts[0];
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
                    // Note: parity-wasm provides a well defined order of the sections in the
                    // module. Due to this, indices of exported functions will
                    // always be greater or equal than the number of imports.
                    let actual_fn_index =
                        *fn_index as usize - module.import_count(ImportCountType::Function);
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

#[derive(Debug, PartialEq, Eq, Default)]
pub struct WasmImportsDetails {
    // True if the module imports these IC0 methods.
    pub imports_call_simple: bool,
    pub imports_call_cycles_add: bool,
    pub imports_canister_cycle_balance: bool,
    pub imports_msg_cycles_available: bool,
    pub imports_msg_cycles_refunded: bool,
    pub imports_msg_cycles_accept: bool,
    pub imports_mint_cycles: bool,
}

/// Returned as a result of `validate_wasm_binary` and provides
/// additional information about the validation.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct WasmValidationDetails {
    // The number of exported functions that are not in the list of
    // allowed exports and whose name starts with the reserved
    // "canister_" prefix.
    pub reserved_exports: usize,
    pub imports_details: WasmImportsDetails,
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
///
/// Additionally, it ensures that the wasm binary can actually compile.
pub fn validate_wasm_binary(
    wasm: &BinaryEncodedWasm,
    config: WasmValidationLimits,
) -> Result<WasmValidationDetails, WasmValidationError> {
    can_compile(&wasm)?;
    let module = parity_wasm::deserialize_buffer::<Module>(wasm.as_slice())
        .map_err(|err| WasmValidationError::ParityDeserializeError(into_parity_wasm_error(err)))?;
    let imports_details = validate_import_section(&module)?;
    let reserved_exports = validate_export_section(&module)?;
    validate_data_section(&module)?;
    validate_global_section(&module, config.max_globals)?;
    validate_function_section(&module, config.max_functions)?;
    Ok(WasmValidationDetails {
        reserved_exports,
        imports_details,
    })
}
