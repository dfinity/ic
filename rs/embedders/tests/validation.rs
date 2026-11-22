use std::borrow::Cow;
use std::time::Duration;

use assert_matches::assert_matches;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::{
        Complexity, WasmImportsDetails, WasmValidationDetails, validate_and_instrument_for_testing,
        validation::{
            MAX_RAW_CUSTOM_SECTIONS, MAX_WASM_FUNCTION_NAME_LENGTH, MAX_WASM_FUNCTION_NUM_LOCALS,
            RESERVED_SYMBOLS, extract_custom_section_name,
        },
    },
};
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};

use ic_replicated_state::canister_state::execution_state::{
    CustomSection, CustomSectionType, WasmMetadata,
};
use ic_types::{NumBytes, NumInstructions};
use maplit::btreemap;

use ic_embedders::WASM_PAGE_SIZE;
const KB: u32 = 1024;

fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wat::Error> {
    wat::parse_str(wat).map(BinaryEncodedWasm::new)
}

fn validate_wasm_binary(
    wasm: &BinaryEncodedWasm,
    config: &EmbeddersConfig,
) -> Result<WasmValidationDetails, WasmValidationError> {
    let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());
    match validate_and_instrument_for_testing(&embedder, wasm) {
        Ok((validation_details, _)) => Ok(validation_details),
        Err(HypervisorError::InvalidWasm(err)) => Err(err),
        Err(other_error) => panic!("unexpected error {other_error}"),
    }
}

#[test]
fn can_validate_valid_import_section() {
    let wasm = wat2wasm(
        r#"(module
                (import "env" "memory" (memory (;0;) 529))
                (import "env" "table" (table (;0;) 33 33 funcref))
                (import "ic0" "msg_reply" (func $reply)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
fn can_validate_import_section_with_invalid_memory_import() {
    let wasm = wat2wasm(r#"(module (import "foo" "memory" (memory (;0;) 529)))"#).unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn can_validate_import_section_with_invalid_table_import() {
    let wasm = wat2wasm(r#"(module (import "foo" "table" (table (;0;) 33 33 funcref)))"#).unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn can_validate_import_section_with_invalid_imported_function() {
    let wasm =
        wat2wasm(r#"(module (import "ic0" "msg_reply" (func $reply (param i64 i32))))"#).unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_valid_export_section() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x)
                  (export "some_function_is_ok" (func $x))
                  (export "canister_init" (func $x))
                  (export "canister_heartbeat" (func $x))
                  (export "canister_global_timer" (func $x))
                  (export "canister_on_low_wasm_memory" (func $x))
                  (export "canister_pre_upgrade" (func $x))
                  (export "canister_post_upgrade" (func $x))
                  (export "canister_query read" (func $x))
                  (export "canister_composite_query query" (func $x)))"#,
    )
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            largest_function_instruction_count: NumInstructions::new(1),
            max_complexity: Complexity(1),
            code_section_size: NumBytes::from(3),
            ..Default::default()
        })
    );
}

#[test]
fn can_validate_valid_export_section_with_no_space_after_canister_query() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x)
                  (export "canister_init" (func $x))
                  (export "canister_heartbeat" (func $x))
                  (export "canister_global_timer" (func $x))
                  (export "canister_on_low_wasm_memory" (func $x))
                  (export "canister_pre_upgrade" (func $x))
                  (export "canister_post_upgrade" (func $x))
                  (export "canister_query read" (func $x))
                  (export "some_function_is_ok" (func $x))
                  (export "canister_query" (func $x)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidExportSection(
            "Exporting reserved function 'canister_query' with \"canister_\" prefix".to_string()
        ))
    );
}

#[test]
fn can_validate_valid_export_section_with_reserved_functions() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x)
                  (export "canister_init" (func $x))
                  (export "canister_heartbeat" (func $x))
                  (export "canister_global_timer" (func $x))
                  (export "canister_on_low_wasm_memory" (func $x))
                  (export "canister_pre_upgrade" (func $x))
                  (export "canister_post_upgrade" (func $x))
                  (export "canister_query read" (func $x))
                  (export "some_function_is_ok" (func $x))
                  (export "canister_bar_is_reserved" (func $x)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidExportSection(
            "Exporting reserved function 'canister_bar_is_reserved' with \"canister_\" prefix"
                .to_string()
        ))
    );
}

#[test]
fn can_validate_canister_init_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_init" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_init_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_init" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_inspect_message_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_inspect_message" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_inspect_message_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_inspect_message" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_heartbeat_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_heartbeat" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_global_timer_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_global_timer" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_on_low_wasm_memory_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_on_low_wasm_memory" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_heartbeat_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_heartbeat" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_global_timer_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_global_timer" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_on_low_wasm_memory_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_on_low_wasm_memory" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_pre_upgrade_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_pre_upgrade" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_pre_upgrade_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_pre_upgrade" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_post_upgrade_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (result i32) (i32.const 0))
                  (export "canister_post_upgrade" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_post_upgrade_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x (param $y i32))
                  (export "canister_post_upgrade" (func $x)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_query_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param $y i32))
                    (export "canister_query read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_query_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (result i32) (i32.const 0))
                    (export "canister_query read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_composite_query_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param $y i32))
                    (export "canister_composite_query read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_composite_query_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (result i32) (i32.const 0))
                    (export "canister_composite_query read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_update_with_invalid_params() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param $y i32))
                    (export "canister_update read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_update_with_invalid_return() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (result i32) (i32.const 0))
                    (export "canister_update read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_update_with_no_space() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read)
                    (export "canister_update" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidExportSection(_))
    );
}

#[test]
fn can_validate_canister_update_with_empty_name() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read)
                    (export "canister_update " (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(_)
    );
}

#[test]
fn can_validate_canister_update_with_spaces() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read)
                    (export "canister_update name with spaces" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(_)
    );
}

#[test]
fn can_validate_duplicate_update_and_query_methods() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read)
                    (export "canister_query read" (func $read))
                    (export "canister_update read" (func $read)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::DuplicateExport {
            name: "read".to_string()
        })
    );
}

#[test]
fn can_validate_duplicate_update_and_composite_query_methods() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read)
                    (export "canister_composite_query read" (func $read))
                    (export "canister_update read" (func $read)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::DuplicateExport {
            name: "read".to_string()
        })
    );
}

#[test]
fn can_validate_duplicate_query_and_composite_query_methods() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read)
                    (export "canister_composite_query read" (func $read))
                    (export "canister_query read" (func $read)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::DuplicateExport {
            name: "read".to_string()
        })
    );
}

#[test]
fn can_validate_invalid_export_with_canister_prefix() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param $y i32))
                    (export "canister_callback" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidExportSection(_))
    );
}

fn many_exported_functions(n: usize) -> String {
    use std::fmt::Write;
    let mut ret: String = "(module\n  (func $read)\n".to_string();
    for i in 0..n {
        let typ = if i % 3 == 0 {
            "update"
        } else if i % 3 == 1 {
            "query"
        } else {
            "composite_query"
        };
        writeln!(ret, "  (export \"canister_{typ} xxx{i}\" (func $read))").unwrap();
    }
    ret.push_str("\n)");
    ret
}

#[test]
fn can_validate_many_exported_functions() {
    let wasm = wat2wasm(&many_exported_functions(1000)).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            largest_function_instruction_count: NumInstructions::new(1),
            max_complexity: Complexity(1),
            code_section_size: NumBytes::from(3),
            ..Default::default()
        })
    );
}

#[test]
fn can_validate_too_many_exported_functions() {
    let wasm = wat2wasm(&many_exported_functions(1001)).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::TooManyExports {
            defined: 1001,
            allowed: 1000
        })
    );
}

#[test]
fn can_validate_too_many_total_exports() {
    // One global exported three times: a single global, but three exports. This
    // is the shape that evades the function-export limit, so the total number of
    // exports is bounded on its own.
    let wasm = wat2wasm(
        r#"(module
                (global i32 (i32.const 0))
                (export "a" (global 0))
                (export "b" (global 0))
                (export "c" (global 0)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_number_exports: 2,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::TooManyTotalExports {
            defined: 3,
            allowed: 2
        })
    );
}

#[test]
fn validating_many_exports_is_fast() {
    const NUM_EXPORTS: usize = 499_999;
    const BUDGET: Duration = Duration::from_secs(10);

    let wasm = wat2wasm(&many_exported_functions(NUM_EXPORTS)).unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(validate_wasm_binary(&wasm, &EmbeddersConfig::default()));
    });

    let result = rx
        .recv_timeout(BUDGET)
        .unwrap_or_else(|_| panic!("validation did not finish within {BUDGET:?}"));

    assert_eq!(
        result,
        Err(WasmValidationError::TooManyExports {
            defined: NUM_EXPORTS,
            allowed: 1000
        })
    );
}

#[test]
fn can_validate_large_sum_exported_function_name_lengths() {
    let func_a = String::from_utf8(vec![b'a'; 6666]).unwrap();
    let func_b = String::from_utf8(vec![b'b'; 6667]).unwrap();
    let func_c = String::from_utf8(vec![b'c'; 6667]).unwrap();
    let wasm = wat2wasm(&format!(
        r#"(module
                    (func $read)
                    (export "canister_update {func_a}" (func $read))
                    (export "canister_composite_query {func_b}" (func $read))
                    (export "canister_query {func_c}" (func $read)))"#
    ))
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            largest_function_instruction_count: NumInstructions::new(1),
            max_complexity: Complexity(1),
            code_section_size: NumBytes::from(3),
            ..Default::default()
        })
    );
}

#[test]
fn can_validate_too_large_sum_exported_function_name_lengths() {
    let func_a = String::from_utf8(vec![b'a'; 6667]).unwrap();
    let func_b = String::from_utf8(vec![b'b'; 6667]).unwrap();
    let func_c = String::from_utf8(vec![b'c'; 6667]).unwrap();
    let wasm = wat2wasm(&format!(
        r#"(module
                    (func $read)
                    (export "canister_update {func_a}" (func $read))
                    (export "canister_composite_query {func_b}" (func $read))
                    (export "canister_query {func_c}" (func $read)))"#
    ))
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::ExportedNamesTooLong {
            total_length: 20001,
            allowed: 20000
        })
    );
}

#[test]
fn can_validate_canister_query_update_method_name_with_whitespace() {
    let wasm = wat2wasm(
        r#"(module
                    (func $x)
                    (export "canister_query my_func x" (func $x))
                    (export "canister_composite_query my_func y" (func $x))
                    (export "canister_update my_func z" (func $x)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            largest_function_instruction_count: NumInstructions::new(1),
            max_complexity: Complexity(1),
            code_section_size: NumBytes::from(3),
            ..Default::default()
        })
    );
}

#[test]
fn can_validate_valid_data_section() {
    let wasm = wat2wasm(
        r#"
                (module
                    (memory (;0;) 1)
                    (data (i32.const 0) "abcd")
                )
            "#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
// this test passes currently not because of a correct validation that we're not
// using a global in data offset expression, but because we terminate the
// validation on rejecting an imported global.
fn can_validate_invalid_offset_expression_in_data_section() {
    let wasm = wat2wasm(
        r#"
                (module
                    (global (;0;) (import "test" "test") i32)
                    (memory (;0;) 1)
                    (data (global.get 0) "abcd")
                )
            "#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn can_validate_module_with_import_func() {
    // Accepts `msg_reply` from ic0 module.
    let wasm = wat2wasm(r#"(module (import "ic0" "msg_reply" (func $msg_reply)))"#).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
fn can_validate_module_with_not_allowed_import_func() {
    let wasm = wat2wasm(
        r#"(module
                    (import "msg" "my_func" (func $reply (param i32))))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn can_validate_module_with_not_allowed_ic0_import_func() {
    let wasm = wat2wasm(
        r#"(module
                    (import "ic0" "my_call_perform" (func $ic0_call_perform (result i32))))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn can_validate_module_with_wrong_import_module_for_func() {
    let wasm = wat2wasm(r#"(module (import "foo" "msg_reply" (func $reply)))"#).unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn reject_wasm_that_imports_global() {
    let wasm = wat2wasm(
        r#"
                (module
                  (import "test" "adf" (global i64))
                )
            "#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidImportSection(_))
    );
}

#[test]
fn can_reject_module_with_too_many_globals() {
    let wasm = wat2wasm(
        r#"
                (module
                  (global (mut i32) (i32.const 0))
                  (global (mut i64) (i64.const 1))
                  (global i64 (i64.const 2))
                )
            "#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_globals: 2,
                max_functions: 1024,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::TooManyGlobals {
            defined: 3,
            allowed: 2
        })
    );
}

#[test]
fn can_reject_module_with_too_many_functions() {
    let wasm = wat2wasm(
        r#"
                (module
                  (func $x1)
                  (func $x2)
                  (func $x3)
                  (func $x4)
                  (func $x5)
                  (func $x6)
                )
            "#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_globals: 256,
                max_functions: 5,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::TooManyFunctions {
            defined: 6,
            allowed: 5
        })
    );
}

#[test]
fn can_validate_module_with_custom_sections() {
    let mut module = wasm_encoder::Module::new();
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:private name1"),
        data: Cow::Borrowed(&[0, 1]),
    });
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:public name2"),
        data: Cow::Borrowed(&[0, 2]),
    });
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("name3"),
        data: Cow::Borrowed(&[0, 2]),
    });
    let wasm = BinaryEncodedWasm::new(module.finish());

    // Extracts the custom sections that provide the visibility `public/private`.
    let validation_details = validate_wasm_binary(
        &wasm,
        &EmbeddersConfig {
            max_custom_sections: 4,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        validation_details.wasm_metadata,
        WasmMetadata::new(btreemap! {
            "name1".to_string() => CustomSection::new(CustomSectionType::Private, vec![0, 1]),
            "name2".to_string() => CustomSection::new(CustomSectionType::Public, vec![0, 2]),
        })
    );
}

#[test]
fn can_validate_module_with_empty_custom_section_name() {
    for (visibility, custom_section_type) in [
        ("private", CustomSectionType::Private),
        ("public", CustomSectionType::Public),
    ] {
        let mut module = wasm_encoder::Module::new();
        module.section(&wasm_encoder::CustomSection {
            name: Cow::Borrowed(&format!("icp:{visibility} ")),
            data: Cow::Borrowed(&[0, 1]),
        });
        let wasm = BinaryEncodedWasm::new(module.finish());

        // Extracts the custom sections that provide the visibility `public/private`.
        let validation_details = validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_custom_sections: 4,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            validation_details.wasm_metadata,
            WasmMetadata::new(btreemap! {
                "".to_string() => CustomSection::new(custom_section_type, vec![0, 1]),
            })
        );
    }
}

#[test]
fn can_validate_module_with_custom_section_name_with_spaces() {
    let mut module = wasm_encoder::Module::new();
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:public name with spaces"),
        data: Cow::Borrowed(&[0, 1]),
    });
    let wasm = BinaryEncodedWasm::new(module.finish());

    // Extracts the custom sections that provide the visibility `public/private`.
    let validation_details = validate_wasm_binary(
        &wasm,
        &EmbeddersConfig {
            max_custom_sections: 4,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        validation_details.wasm_metadata,
        WasmMetadata::new(btreemap! {
            "name with spaces".to_string() => CustomSection::new(CustomSectionType::Public, vec![0, 1]),
        })
    );
}

#[test]
fn can_reject_module_with_too_many_custom_sections() {
    let mut module = wasm_encoder::Module::new();
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:private name1"),
        data: Cow::Borrowed(&[0, 1]),
    });
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:public name2"),
        data: Cow::Borrowed(&[0, 2]),
    });
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("name3"),
        data: Cow::Borrowed(&[0, 2]),
    });
    let wasm = BinaryEncodedWasm::new(module.finish());

    assert_matches!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_custom_sections: 1,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::TooManyCustomSections {
            defined: 2,
            allowed: 1
        })
    );
}

/// Wasm magic + version, followed by `count` custom sections encoded as
/// `00 01 00` (section id 0, size 1, empty name, empty payload).
fn wasm_with_empty_custom_sections(count: usize) -> BinaryEncodedWasm {
    let mut bytes = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for _ in 0..count {
        bytes.extend_from_slice(&[0x00, 0x01, 0x00]);
    }
    BinaryEncodedWasm::new(bytes)
}

// Empty-name sections are not `icp:` metadata, so `max_custom_sections` does
// not apply to them. The streaming pre-check still rejects a module once the
// raw custom-section count exceeds `MAX_RAW_CUSTOM_SECTIONS`, before Wasmtime
// or Wirm materialize the sections.
#[test]
fn can_reject_module_with_too_many_raw_custom_sections() {
    let defined = MAX_RAW_CUSTOM_SECTIONS + 1;
    let wasm = wasm_with_empty_custom_sections(defined);

    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::TooManyCustomSections {
            defined,
            allowed: MAX_RAW_CUSTOM_SECTIONS,
        })
    );
}

#[test]
fn can_validate_module_with_max_raw_custom_sections() {
    let wasm = wasm_with_empty_custom_sections(MAX_RAW_CUSTOM_SECTIONS);
    let validation_details = validate_wasm_binary(&wasm, &EmbeddersConfig::default()).unwrap();
    assert_eq!(validation_details.wasm_metadata, WasmMetadata::default());
}

// Wasmtime does not check the indices in the `name` section. A function name
// whose index is past the last function is dropped during instrumentation.
#[test]
fn can_validate_module_with_out_of_range_function_name() {
    use wasm_encoder::Section;

    let mut wasm = wat::parse_str("(module (func) (func))").unwrap();
    let mut function_names = wasm_encoder::NameMap::new();
    function_names.append(0, "f0");
    // The module defines functions 0 and 1 only.
    function_names.append(2, "f2");
    let mut name_section = wasm_encoder::NameSection::new();
    name_section.functions(&function_names);
    name_section.append_to(&mut wasm);

    let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
    let (_, output) =
        validate_and_instrument_for_testing(&embedder, &BinaryEncodedWasm::new(wasm)).unwrap();

    let mut names = vec![];
    for payload in wasmparser::Parser::new(0).parse_all(output.binary.as_slice()) {
        if let wasmparser::Payload::CustomSection(reader) = payload.unwrap()
            && let wasmparser::KnownCustom::Name(subsections) = reader.as_known()
        {
            for subsection in subsections {
                if let wasmparser::Name::Function(map) = subsection.unwrap() {
                    for naming in map {
                        names.push(naming.unwrap().name.to_string());
                    }
                }
            }
        }
    }
    assert_eq!(names, vec!["f0"]);
}

/// The module `(module (func (param i32 i64)) (func))` followed by a `name`
/// section made of the given subsections, each given as its id and payload.
fn module_with_name_subsections(subsections: &[(u8, &[u8])]) -> BinaryEncodedWasm {
    use wasm_encoder::{Encode, Section};

    let mut wasm = wat::parse_str("(module (func (param i32 i64)) (func))").unwrap();
    let mut data = vec![];
    for (id, payload) in subsections {
        data.push(*id);
        payload.encode(&mut data);
    }
    wasm_encoder::CustomSection {
        name: Cow::Borrowed("name"),
        data: Cow::Owned(data),
    }
    .append_to(&mut wasm);
    BinaryEncodedWasm::new(wasm)
}

/// The payloads of a function-name subsection (id 1) naming both functions of
/// `module_with_name_subsections` and of a local-name subsection (id 2) naming
/// the parameters of function 0.
fn function_and_local_names() -> (Vec<u8>, Vec<u8>) {
    use wasm_encoder::Encode;

    let mut function_names = wasm_encoder::NameMap::new();
    function_names.append(0, "f0");
    function_names.append(1, "f1");
    let mut locals = wasm_encoder::NameMap::new();
    locals.append(0, "x");
    locals.append(1, "y");
    let mut local_names = wasm_encoder::IndirectNameMap::new();
    local_names.append(0, &locals);
    let (mut function_payload, mut local_payload) = (vec![], vec![]);
    function_names.encode(&mut function_payload);
    local_names.encode(&mut local_payload);
    (function_payload, local_payload)
}

fn assert_same_validation_and_instrumentation(
    wasm: &BinaryEncodedWasm,
    expected: &BinaryEncodedWasm,
) {
    let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
    let (details, output) = validate_and_instrument_for_testing(&embedder, wasm).unwrap();
    let (expected_details, expected_output) =
        validate_and_instrument_for_testing(&embedder, expected).unwrap();
    assert_eq!(details, expected_details);
    assert_eq!(
        output.exported_functions,
        expected_output.exported_functions
    );
    assert_eq!(output.data, expected_output.data);
    assert_eq!(output.binary.as_slice(), expected_output.binary.as_slice());
    assert_eq!(output.compilation_cost, expected_output.compilation_cost);
}

// Validation and instrumentation ignore the `name` subsections 12 (parameter
// names of function types) and 13 (parameter names of tag types), even if a
// name in them is not valid UTF-8.
#[test]
fn can_validate_module_with_non_utf8_parameter_name() {
    let (function_names, local_names) = function_and_local_names();
    // Names parameter 0 of type 0 with the byte 0xff, which is not UTF-8.
    let parameter_names = [1, 0, 1, 0, 1, 0xff];
    let expected = module_with_name_subsections(&[(1, &function_names), (2, &local_names)]);
    for id in [12, 13] {
        assert_same_validation_and_instrumentation(
            &module_with_name_subsections(&[
                (1, &function_names),
                (2, &local_names),
                (id, &parameter_names),
            ]),
            &expected,
        );
    }
}

#[test]
fn parameter_names_do_not_change_validation_and_instrumentation() {
    use wasm_encoder::Encode;

    let (function_names, local_names) = function_and_local_names();
    let mut names = wasm_encoder::NameMap::new();
    names.append(0, "a");
    names.append(1, "b");
    let mut parameter_names = wasm_encoder::IndirectNameMap::new();
    // Names the two parameters of type 0.
    parameter_names.append(0, &names);
    let mut payload = vec![];
    parameter_names.encode(&mut payload);

    let expected = module_with_name_subsections(&[(1, &function_names), (2, &local_names)]);
    for ids in [vec![12], vec![13], vec![12, 13]] {
        let mut subsections = vec![(1, &function_names[..]), (2, &local_names[..])];
        subsections.extend(ids.into_iter().map(|id| (id, &payload[..])));
        assert_same_validation_and_instrumentation(
            &module_with_name_subsections(&subsections),
            &expected,
        );
    }
}

/// Encodes the given indices and names as a name map.
fn encoded_name_map(names: &[(u32, &str)]) -> Vec<u8> {
    use wasm_encoder::Encode;

    let mut map = wasm_encoder::NameMap::new();
    for (index, name) in names {
        map.append(*index, name);
    }
    let mut payload = vec![];
    map.encode(&mut payload);
    payload
}

/// Encodes the given indices and name maps as an indirect name map.
fn encoded_indirect_name_map(maps: &[(u32, &[(u32, &str)])]) -> Vec<u8> {
    use wasm_encoder::Encode;

    let mut map = wasm_encoder::IndirectNameMap::new();
    for (index, names) in maps {
        let mut name_map = wasm_encoder::NameMap::new();
        for (index, name) in *names {
            name_map.append(*index, name);
        }
        map.append(*index, &name_map);
    }
    let mut payload = vec![];
    map.encode(&mut payload);
    payload
}

/// Asserts that the module with the `name` subsections `with` validates and
/// instruments like the module with the subsections `without`.
fn assert_name_subsections_ignored(with: &[(u8, &[u8])], without: &[(u8, &[u8])]) {
    assert_same_validation_and_instrumentation(
        &module_with_name_subsections(with),
        &module_with_name_subsections(without),
    );
}

// Validation and instrumentation ignore a `name` subsection whose id is not
// greater than the id of the last subsection before it that they do not
// ignore.
#[test]
fn can_validate_module_with_name_subsections_out_of_order() {
    let (function_names, local_names) = function_and_local_names();
    let other_function_names = encoded_name_map(&[(0, "g0")]);
    let module_name = [1, b'm'];
    let other_module_name = [1, b'n'];
    // A repeated id, and a smaller id after a greater one.
    assert_name_subsections_ignored(
        &[(1, &function_names), (1, &other_function_names)],
        &[(1, &function_names)],
    );
    assert_name_subsections_ignored(
        &[(2, &local_names), (1, &function_names)],
        &[(2, &local_names)],
    );
    // A second module name, and the module name after the function names.
    assert_name_subsections_ignored(
        &[
            (0, &module_name),
            (0, &other_module_name),
            (1, &function_names),
        ],
        &[(0, &module_name), (1, &function_names)],
    );
    assert_name_subsections_ignored(
        &[(1, &function_names), (0, &module_name), (2, &local_names)],
        &[(1, &function_names), (2, &local_names)],
    );
    // Subsections with unknown ids.
    assert_name_subsections_ignored(
        &[(1, &function_names), (15, &[1, 2]), (14, &[3]), (15, &[4])],
        &[(1, &function_names), (15, &[1, 2])],
    );
}

// Validation and instrumentation ignore a `name` subsection with a name map
// whose indices are not strictly increasing.
#[test]
fn can_validate_module_with_name_maps_out_of_order() {
    let (function_names, local_names) = function_and_local_names();
    // Function names out of order, and with a repeated index.
    for names in [
        encoded_name_map(&[(1, "f1"), (0, "f0")]),
        encoded_name_map(&[(0, "f0"), (0, "g0")]),
    ] {
        assert_name_subsections_ignored(&[(1, &names), (2, &local_names)], &[(2, &local_names)]);
    }
    // Local names whose map of functions is out of order, and local names
    // whose map of the locals of function 0 is out of order.
    for names in [
        encoded_indirect_name_map(&[(1, &[]), (0, &[(0, "x")])]),
        encoded_indirect_name_map(&[(0, &[(1, "y"), (0, "x")])]),
    ] {
        assert_name_subsections_ignored(
            &[(1, &function_names), (2, &names)],
            &[(1, &function_names)],
        );
    }
    // Label names whose map of functions is out of order, and type names out
    // of order.
    for (id, names) in [
        (3, encoded_indirect_name_map(&[(1, &[]), (0, &[])])),
        (4, encoded_name_map(&[(1, "t1"), (0, "t0")])),
    ] {
        assert_name_subsections_ignored(
            &[(1, &function_names), (2, &local_names), (id, &names)],
            &[(1, &function_names), (2, &local_names)],
        );
    }
}

// A `name` subsection that cannot be parsed is not ignored, even if its id or
// its name map is out of order.
#[test]
fn can_reject_module_with_malformed_name_subsection_out_of_order() {
    let (function_names, _) = function_and_local_names();
    // Function names out of order, the second of which is not UTF-8.
    let malformed_names: &[u8] = &[2, 1, 1, b'b', 0, 1, 0xff];
    for subsections in [
        vec![(1, &function_names[..]), (1, malformed_names)],
        vec![(1, malformed_names)],
    ] {
        assert_matches!(
            validate_wasm_binary(
                &module_with_name_subsections(&subsections),
                &EmbeddersConfig::default()
            ),
            Err(WasmValidationError::DecodingError(_))
        );
    }
}

#[test]
fn can_reject_module_with_custom_sections_too_big() {
    let content = vec![0, 1, 6, 5, 6, 7, 4, 6];
    let size = 2 * content.len() + "name".len() + "custom_section".len();
    let mut module = wasm_encoder::Module::new();
    // Size of this custom section is 12 bytes.
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:public name"),
        data: Cow::Borrowed(&content),
    });
    // Adding the size of this custom section will exceed the `max_custom_sections_size`.
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:private custom_section"),
        data: Cow::Borrowed(&content),
    });
    let wasm = BinaryEncodedWasm::new(module.finish());

    let max_custom_sections_size = NumBytes::new(14);
    assert_eq!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_custom_sections: 3,
                max_custom_sections_size,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::InvalidCustomSection(format!(
            "Invalid custom sections: total size of the custom sections exceeds the maximum allowed: size {size} bytes, allowed {max_custom_sections_size} bytes"
        )))
    );
}

#[test]
fn can_reject_module_with_duplicate_custom_sections() {
    for visibility_1 in ["public", "private"] {
        for visibility_2 in ["public", "private"] {
            let mut module = wasm_encoder::Module::new();
            module.section(&wasm_encoder::CustomSection {
                name: Cow::Borrowed(&format!("icp:{visibility_1} custom1")),
                data: Cow::Borrowed(&[0, 1]),
            });
            module.section(&wasm_encoder::CustomSection {
                name: Cow::Borrowed("icp:public custom2"),
                data: Cow::Borrowed(&[0, 2]),
            });
            module.section(&wasm_encoder::CustomSection {
                name: Cow::Borrowed(&format!("icp:{visibility_2} custom1")),
                data: Cow::Borrowed(&[0, 3]),
            });
            let wasm = BinaryEncodedWasm::new(module.finish());

            // Rejects the module because of duplicate custom section names.
            assert_eq!(
                validate_wasm_binary(&wasm, &EmbeddersConfig::default(),),
                Err(WasmValidationError::InvalidCustomSection(
                    "Invalid custom section: name custom1 already exists".to_string()
                ))
            );
        }
    }
}

#[test]
fn can_reject_module_with_invalid_custom_sections() {
    let mut module = wasm_encoder::Module::new();
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:private custom1"),
        data: Cow::Borrowed(&[0, 1]),
    });
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:public custom2"),
        data: Cow::Borrowed(&[0, 2]),
    });
    module.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed("icp:dummy custom3"),
        data: Cow::Borrowed(&[0, 3]),
    });
    let wasm = BinaryEncodedWasm::new(module.finish());

    // Only `private` or `public` is allowed if `icp:` prefix is defined.
    assert_eq!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_custom_sections: 5,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::InvalidCustomSection(
            "Invalid custom section: Custom section 'icp:dummy custom3' has no public/private scope defined.".to_string()
        ))
    );
}

#[test]
fn can_extract_custom_section_name() {
    // Valid public section.
    let name = "icp:public public_name";
    let (name, visibility) = extract_custom_section_name(name).unwrap().unwrap();
    assert_eq!(name, "public_name");
    assert_eq!(visibility, CustomSectionType::Public);

    // Valid private section.
    let name = "icp:private    private_name";
    let (name, visibility) = extract_custom_section_name(name).unwrap().unwrap();
    assert_eq!(name, "   private_name");
    assert_eq!(visibility, CustomSectionType::Private);

    // No space after public/private.
    let name = "icp:private";
    assert!(matches!(
        extract_custom_section_name(name),
        Err(WasmValidationError::InvalidCustomSection(_))
    ));
    let name = "icp:public";
    assert!(matches!(
        extract_custom_section_name(name),
        Err(WasmValidationError::InvalidCustomSection(_))
    ));

    // No public/private visibility defined.
    let name = "icp:x invalid_custom";
    assert_eq!(extract_custom_section_name(name),  Err(WasmValidationError::InvalidCustomSection(
            "Invalid custom section: Custom section 'icp:x invalid_custom' has no public/private scope defined.".to_string()
        )));

    // Ignore custom section. The name does not start with `icp:`.
    let name = "ignore_custom";
    assert_eq!(extract_custom_section_name(name), Ok(None));
}

#[test]
fn can_validate_module_with_reserved_symbols() {
    for reserved_symbol in RESERVED_SYMBOLS.iter() {
        // A wasm that exports a global with a reserved name. Should fail validation.
        let wasm_global = BinaryEncodedWasm::new(
            wat::parse_str(format!(
                r#"
                (module
                    (global (;0;) (mut i32) (i32.const 0))
                    (export "{reserved_symbol}" (global 0))
                )"#
            ))
            .unwrap(),
        );
        assert_matches!(
            validate_wasm_binary(&wasm_global, &EmbeddersConfig::default()),
            Err(WasmValidationError::InvalidExportSection(_))
        );

        // A wasm that exports a func with a reserved name. Should fail validation.
        let wasm_func = BinaryEncodedWasm::new(
            wat::parse_str(format!(
                r#"
                (module
                    (func $x)
                    (export "{reserved_symbol}" (func $x))
                )"#
            ))
            .unwrap(),
        );
        assert_matches!(
            validate_wasm_binary(&wasm_func, &EmbeddersConfig::default()),
            Err(WasmValidationError::InvalidExportSection(_))
        );
    }
}

#[test]
fn can_reject_wasm_with_invalid_global_access() {
    // This wasm module defines one global but attempts to access global at index 1
    // (which would be the instruction counter after
    // instrumentation). This should
    // fail validation.
    let wasm = BinaryEncodedWasm::new(
        include_bytes!("instrumentation-test-data/invalid_global_access.wasm").to_vec(),
    );
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::WasmtimeValidation(_))
    );
}

#[test]
fn can_validate_module_cycles_related_imports() {
    // Instruments imports from `ic0`.
    let wasm = wat2wasm(
        r#"(module
        (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
        (import "ic0" "canister_cycle_balance" (func $ic0_canister_cycle_balance (result i64)))
        (import "ic0" "msg_cycles_accept" (func $ic0_msg_cycles_accept (param $amount i64) (result i64)))
    )"#,
    )
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            imports_details: WasmImportsDetails {
                imports_call_cycles_add: true,
                imports_canister_cycle_balance: true,
                imports_msg_cycles_accept: true,
                ..Default::default()
            },
            ..Default::default()
        })
    );
}

#[test]
fn can_validate_export_section_exporting_import() {
    let wasm = wat2wasm(
        r#"
        (module
            (type (;0;) (func))
            (import "env" "memory" (memory (;0;) 529))
            (import "env" "table" (table (;0;) 33 33 funcref))
            (import "ic0" "msg_reply" (func (;0;) (type 0)))
            (func (;1;) (type 0))
            (func (;2;) (type 0))
            (func (;3;) (type 0))
            (export "canister_heartbeat" (func 1))
            (export "canister_pre_upgrade" (func 2))
            (export "canister_post_upgrade" (func 0)))
        "#,
    )
    .unwrap();
    validate_wasm_binary(&wasm, &EmbeddersConfig::default()).unwrap();
}

#[test]
fn can_validate_module_cycles_u128_related_imports() {
    // Instruments imports from `ic0`.
    let wasm = wat2wasm(
        r#"(module
        (import "ic0" "call_cycles_add128" (func $ic0_call_cycles_add128 (param i64 i64)))
        (import "ic0" "canister_cycle_balance128" (func $ic0_canister_cycle_balance128 (param i32)))
        (import "ic0" "msg_cycles_available128" (func $ic0_msg_cycles_available128 (param i32)))
        (import "ic0" "msg_cycles_refunded128" (func $ic0_msg_cycles_refunded128 (param i32)))
        (import "ic0" "msg_cycles_accept128" (func $ic0_msg_cycles_accept128 (param i64 i64 i32)))
    )"#,
    )
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
fn can_validate_performance_counter_import() {
    let wasm = wat2wasm(
        r#"(module
        (import "ic0" "performance_counter" (func $ic0_performance_counter (param i32) (result i64)))
    )"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

/// The spec doesn't allow exported functions to have results.
#[test]
fn function_with_result_is_invalid() {
    let wasm = wat2wasm(
        r#"
          (module
            (func $f (export "canister_update f") (result i64)
              (i64.const 1)
            )
          )"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(
            "Expected return type [] for 'canister_update f', got [I64].".to_string()
        ))
    );
}

#[test]
fn complex_function_rejected() {
    let mut wat = "(module (func) (func".to_string();
    for _ in 0..20_001 {
        wat.push_str("(loop)");
    }
    wat.push_str("))");
    let wasm = wat2wasm(&wat).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::FunctionComplexityTooHigh {
            index: 1,
            complexity: 1_020_052,
            allowed: 1_000_000
        })
    )
}

/// Creates a was with roughly the given sizes for the code and data sections
/// (may be off by a few bytes).
fn wasm_with_fixed_sizes(code_section_size: u32, data_section_size: u32) -> BinaryEncodedWasm {
    // Initial memory needs to be large enough to fit the data
    let memory_size = data_section_size / WASM_PAGE_SIZE + 1;
    let mut wat = "(module (func".to_string();
    // Each (block) is 3 bytes: 2 bytes for "block" and 1 for "end"
    for _ in 0..code_section_size / 3 {
        wat.push_str("(block)");
    }
    wat.push(')');
    wat.push_str(&format!("(memory {memory_size})"));
    wat.push_str(&format!(
        "(data (i32.const 0) \"{}\")",
        "a".repeat(data_section_size as usize),
    ));
    wat.push(')');
    wat2wasm(&wat).unwrap()
}

#[test]
fn large_code_section_rejected() {
    let wasm = wasm_with_fixed_sizes(12 * KB * KB + 10, 0);
    let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
    let result = validate_and_instrument_for_testing(&embedder, &wasm);
    assert_matches!(
        result,
        Err(HypervisorError::InvalidWasm(
            WasmValidationError::CodeSectionTooLarge { .. },
        ))
    )
}

#[test]
fn large_wasm_with_small_code_accepted() {
    let wasm = wasm_with_fixed_sizes(KB, 20 * KB * KB);
    let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
    let result = validate_and_instrument_for_testing(&embedder, &wasm);
    assert_matches!(result, Ok(_))
}

/// We are trusting the code section size reported in the header when
/// determining if the code section is too long.  A Wasm which has been
/// manipulated to report an incorrectly small size in the header should be
/// rejected should later be rejected when we try to validate it with Wasmtime.
#[test]
fn incorrect_wasm_code_size_is_invalid() {
    use wasmparser::{Parser, Payload};

    let wasm = wasm_with_fixed_sizes(10 * KB * KB + 10, 0);

    let parser = Parser::new(0);
    let payloads = parser.parse_all(wasm.as_slice());
    let mut manipulated_wasm = vec![];
    for payload in payloads {
        if let Payload::CodeSectionStart { range, .. } = payload.unwrap() {
            // The section header contains the byte 10 as the section id
            // followed by a variable length encoded u32 for the size.
            //
            // Note that the `size` field doesn't include the encoding of the
            // function count (which is 1), so it differs from the length of the
            // `range` (which does include the count encoding).
            //
            // The code section should have size 0xa0000f, which is 0x8f808005
            // as a variable-length u32.
            assert_eq!(range.end - range.start, 0xa0000f);
            assert_eq!(
                wasm.as_slice()[range.start - 5..range.start],
                [0xa /*Code section id*/, 0x8f, 0x80, 0x80, 0x05]
            );
            // Copy everything up to and including the code section id.
            manipulated_wasm.extend_from_slice(&wasm.as_slice()[..range.start - 4]);
            // Push 0x7f = 127 for the code section size.
            manipulated_wasm.push(0x7f);
            // Copy everything after the code section size unchanged.
            manipulated_wasm.extend_from_slice(&wasm.as_slice()[range.start..]);
            break;
        }
    }

    let manipulated_wasm = BinaryEncodedWasm::new(manipulated_wasm);
    let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
    let result = validate_and_instrument_for_testing(&embedder, &manipulated_wasm);
    assert_matches!(
        result,
        Err(HypervisorError::InvalidWasm(
            WasmValidationError::WasmtimeValidation(_),
        ))
    )
}

/// We're assuming there is at most one code section in the Wasm. The spec
/// doesn't allow multiple code sections, so if there are multiple code sections
/// the module should fail validation.
#[test]
fn wasm_with_multiple_code_sections_is_invalid() {
    use wasmparser::{Parser, Payload};

    let wasm = wasm_with_fixed_sizes(10, 0);

    let parser = Parser::new(0);
    let payloads = parser.parse_all(wasm.as_slice());
    let mut manipulated_wasm = vec![];
    for payload in payloads {
        if let Payload::CodeSectionStart { range, .. } = payload.unwrap() {
            // The section header contains the byte 10 as the section id
            // followed by a variable length encoded u32 for the size.
            //
            // Note that the `size` field doesn't include the encoding of the
            // function count (which is 1), so it differs from the length of the
            // `range` (which does include the count encoding).
            //
            // The code section should have size 0xa, which is unchanged as a
            // variable-length u32.
            assert_eq!(range.end - range.start, 0xd);
            assert_eq!(
                wasm.as_slice()[range.start - 2..range.start],
                [0xa /*Code section id*/, 0x0d]
            );
            // Copy everything before the code section
            manipulated_wasm.extend_from_slice(&wasm.as_slice()[..range.start - 2]);
            // Copy the code section twice
            manipulated_wasm.extend_from_slice(&wasm.as_slice()[range.start - 2..range.end]);
            manipulated_wasm.extend_from_slice(&wasm.as_slice()[range.start - 2..range.end]);
            // Copy everything after the code section size unchanged.
            manipulated_wasm.extend_from_slice(&wasm.as_slice()[range.start..]);
            break;
        }
    }

    let manipulated_wasm = BinaryEncodedWasm::new(manipulated_wasm);
    let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
    let result = validate_and_instrument_for_testing(&embedder, &manipulated_wasm);
    assert_matches!(
        result,
        Err(HypervisorError::InvalidWasm(
            WasmValidationError::WasmtimeValidation(_),
        ))
    )
}

#[test]
fn test_wasm64_initial_wasm_memory_size_validation() {
    use crate::WasmValidationError::InitialWasm64MemoryTooLarge;

    let embedders_config = EmbeddersConfig::default();
    let allowed_wasm_memory_size_in_pages =
        embedders_config.max_wasm64_memory_size.get() / WASM_PAGE_SIZE as u64;
    let declared_wasm_memory_size_in_pages = allowed_wasm_memory_size_in_pages + 10;
    let wasm = wat2wasm(&format!(
        r#"(module
            (memory i64 {declared_wasm_memory_size_in_pages} {declared_wasm_memory_size_in_pages})
        )"#
    ))
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &embedders_config),
        Err(InitialWasm64MemoryTooLarge {
            declared_size: declared_wasm_memory_size_in_pages,
            allowed_size: allowed_wasm_memory_size_in_pages
        })
    );
}

#[test]
fn test_validate_table64() {
    let embedders_config = EmbeddersConfig::default();

    let wasm = wat2wasm(
        r#"(module
            (table i64 1 funcref)
            (memory i64 1 1)
        )"#,
    )
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &embedders_config),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
fn wasm_with_funcref_table_section_is_valid() {
    let wasm = wat2wasm(r#"(module (table 1 funcref))"#).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
fn wasm_with_externref_table_section_is_invalid() {
    let wasm = wat2wasm(r#"(module (table 1 externref))"#).unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidTableSection(_))
    );
}

#[test]
fn can_validate_table_section_with_mixed_tables() {
    let wasm = wat2wasm(
        r#"(module
            (table 1 funcref)
            (table 1 externref)
        )"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidTableSection(_))
    );
}

#[test]
fn wasm_with_long_func_name_is_invalid() {
    let wat = format!(
        r#"
        (module
            (type (;0;) (func))
            (func ${} (type 0))
        )"#,
        "A".repeat(MAX_WASM_FUNCTION_NAME_LENGTH + 10)
    );

    let wasm = wat2wasm(&wat).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::FunctionNameTooLarge {
            index: 0,
            size: MAX_WASM_FUNCTION_NAME_LENGTH + 10,
            allowed: MAX_WASM_FUNCTION_NAME_LENGTH,
            name: format!("{}...", "A".repeat(100)),
        })
    );
}

#[test]
fn wasm_with_many_locals_is_invalid() {
    let wat = format!(
        r#"
          (module
            (func $f (export "canister_update f")
              (local {})
            )
          )"#,
        "i32 ".repeat(MAX_WASM_FUNCTION_NUM_LOCALS + 1)
    );

    let wasm = wat2wasm(&wat).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::TooManyLocals {
            index: 0,
            defined: MAX_WASM_FUNCTION_NUM_LOCALS + 1,
            allowed: MAX_WASM_FUNCTION_NUM_LOCALS,
        })
    );
}
