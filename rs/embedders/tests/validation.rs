use std::borrow::Cow;

use assert_matches::assert_matches;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    wasm_utils::{
        validate_and_instrument_for_testing, validate_and_return_module,
        validation::{extract_custom_section_name, RESERVED_SYMBOLS},
        Complexity, WasmImportsDetails, WasmValidationDetails,
    },
    WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};

use ic_replicated_state::canister_state::execution_state::{
    CustomSection, CustomSectionType, WasmMetadata,
};
use ic_types::{NumBytes, NumInstructions};
use maplit::btreemap;

const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;
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
        Err(other_error) => panic!("unexpected error {}", other_error),
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
fn can_validate_invalid_canister_query() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param i64 i32) (result i32) (local.get 1))
                    (export "canister_query read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_invalid_canister_composite_query() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param i64 i32) (result i32) (local.get 1))
                    (export "canister_composite_query read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
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

fn many_exported_functions(n: usize) -> String {
    let mut ret: String = "(module\n  (func $read)\n".to_string();
    for i in 0..n {
        let typ = if i % 3 == 0 {
            "update"
        } else if i % 3 == 1 {
            "query"
        } else {
            "composite_query"
        };
        ret = format!(
            "{}  (export \"canister_{} xxx{}\" (func $read))\n",
            ret, typ, i
        );
    }
    format!("{}\n)", ret)
}

#[test]
fn can_validate_many_exported_functions() {
    let wasm = wat2wasm(&many_exported_functions(1000)).unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            largest_function_instruction_count: NumInstructions::new(1),
            max_complexity: Complexity(1),
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
fn can_validate_large_sum_exported_function_name_lengths() {
    let func_a = String::from_utf8(vec![b'a'; 6666]).unwrap();
    let func_b = String::from_utf8(vec![b'b'; 6667]).unwrap();
    let func_c = String::from_utf8(vec![b'c'; 6667]).unwrap();
    let wasm = wat2wasm(&format!(
        r#"(module
                    (func $read)
                    (export "canister_update {}" (func $read))
                    (export "canister_composite_query {}" (func $read))
                    (export "canister_query {}" (func $read)))"#,
        func_a, func_b, func_c
    ))
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            largest_function_instruction_count: NumInstructions::new(1),
            max_complexity: Complexity(1),
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
                    (export "canister_update {}" (func $read))
                    (export "canister_composite_query {}" (func $read))
                    (export "canister_query {}" (func $read)))"#,
        func_a, func_b, func_c
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
            &wasm, &EmbeddersConfig {
                max_custom_sections: 3,
                max_custom_sections_size,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::InvalidCustomSection(format!(
            "Invalid custom sections: total size of the custom sections exceeds the maximum allowed: size {} bytes, allowed {} bytes",
            size, max_custom_sections_size
        )
        ))
    );
}

#[test]
fn can_reject_module_with_duplicate_custom_sections() {
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
        name: Cow::Borrowed("icp:public custom1"),
        data: Cow::Borrowed(&[0, 3]),
    });
    let wasm = BinaryEncodedWasm::new(module.finish());

    // Rejects the module because of duplicate custom section names.
    assert_eq!(
        validate_wasm_binary(
            &wasm,
            &EmbeddersConfig {
                max_custom_sections: 5,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::InvalidCustomSection(
            "Invalid custom section: name custom1 already exists".to_string()
        ))
    );
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
                    (export "{}" (global 0))
                )"#,
                reserved_symbol
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
                    (export "{}" (func $x))
                )"#,
                reserved_symbol
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
    wat.push_str(&format!("(memory {})", memory_size));
    wat.push_str(&format!(
        "(data (i32.const 0) \"{}\")",
        "a".repeat(data_section_size as usize),
    ));
    wat.push(')');
    wat2wasm(&wat).unwrap()
}

#[test]
fn large_code_section_rejected() {
    let wasm = wasm_with_fixed_sizes(10 * KB * KB + 10, 0);
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
fn validate_wasm64_memory_size() {
    use ic_config::embedders::FeatureFlags;
    use ic_config::flag_status::FlagStatus;
    let embedders_config = EmbeddersConfig {
        feature_flags: FeatureFlags {
            wasm64: FlagStatus::Enabled,
            ..Default::default()
        },
        ..Default::default()
    };
    // Define a size larger than the maximum allowed size.
    let declared_mem_in_wasm_pages =
        embedders_config.max_wasm_memory_size.get() / WASM_PAGE_SIZE as u64 + 5;
    let allowed_mem_in_wasm_pages =
        embedders_config.max_wasm_memory_size.get() / WASM_PAGE_SIZE as u64;

    let mut module = wasm_encoder::Module::new();
    let memory_type = wasm_encoder::MemoryType {
        minimum: 1,
        maximum: Some(declared_mem_in_wasm_pages),
        memory64: true,
        shared: false,
        page_size_log2: None,
    };
    let mut memory_section = wasm_encoder::MemorySection::new();
    memory_section.memory(memory_type);
    module.section(&memory_section);

    let wasm = BinaryEncodedWasm::new(module.finish());

    let result = validate_and_return_module(&wasm, &embedders_config);
    match result {
        Err(e) => panic!("{}", e.to_string()),
        Ok(module) => {
            let memory64_size = module.memories.first().unwrap().maximum.unwrap();
            assert_eq!(memory64_size, allowed_mem_in_wasm_pages);
        }
    }
}
