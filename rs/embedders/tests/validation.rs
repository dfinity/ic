use assert_matches::assert_matches;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::wasm_utils::validation::{
    extract_custom_section_name, validate_custom_section, validate_wasm_binary, WasmImportsDetails,
    WasmValidationDetails, RESERVED_SYMBOLS,
};
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};

fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wabt::Error> {
    let mut features = wabt::Features::new();
    features.enable_multi_value();
    wabt::wat2wasm_with_features(wat, features).map(BinaryEncodedWasm::new)
}
use ic_replicated_state::canister_state::execution_state::{
    CustomSection, CustomSectionType, WasmMetadata,
};
use ic_types::NumBytes;
use maplit::btreemap;
use parity_wasm::elements::{CustomSection as WasmCustomSection, Module, Section};

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
                  (export "canister_init" (func $x))
                  (export "canister_heartbeat" (func $x))
                  (export "canister_pre_upgrade" (func $x))
                  (export "canister_post_upgrade" (func $x))
                  (export "canister_query read" (func $x)))"#,
    )
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
    );
}

#[test]
fn can_validate_valid_export_section_with_reserved_functions() {
    let wasm = wat2wasm(
        r#"(module
                  (func $x)
                  (export "canister_init" (func $x))
                  (export "canister_heartbeat" (func $x))
                  (export "canister_pre_upgrade" (func $x))
                  (export "canister_post_upgrade" (func $x))
                  (export "canister_query read" (func $x))
                  (export "some_function_is_ok" (func $x))
                  (export "canister_bar_is_reserved" (func $x))
                  (export "canister_foo_is_reserved" (func $x)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            reserved_exports: 2,
            ..Default::default()
        })
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
fn can_validate_duplicate_method_for_canister_query_and_canister_update() {
    let wasm = wat2wasm(
        r#"(module
                    (func $read (param i64) (drop (i32.const 0)))
                    (export "canister_query read" (func $read))
                    (export "canister_update read" (func $read)))"#,
    )
    .unwrap();
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionSignature(_))
    );
}

#[test]
fn can_validate_canister_query_update_method_name_with_whitespace() {
    let wasm = wat2wasm(
        r#"(module
                    (func $x)
                    (export "canister_query my_func x" (func $x))
                    (export "canister_update my_func y" (func $x)))"#,
    )
    .unwrap();
    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails::default())
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
    let custom_section =
        |name: String, content: Vec<u8>| Section::Custom(WasmCustomSection::new(name, content));
    let custom_sections: Vec<Section> = vec![
        custom_section("icp:private name1".to_string(), vec![0, 1]),
        custom_section("icp:public name2".to_string(), vec![0, 2]),
        custom_section("name3".to_string(), vec![0, 2]),
    ];
    let module = Module::new(custom_sections);

    // Extracts the custom sections that provide the visibility `public/private`.
    assert_eq!(
        validate_custom_section(
            &module,
            &EmbeddersConfig {
                max_custom_sections: 4,
                ..Default::default()
            }
        ),
        Ok(WasmMetadata::new(btreemap! {
            "name1".to_string() => CustomSection {content: vec![0, 1] , visibility: CustomSectionType::Private},
            "name2".to_string() => CustomSection {content: vec![0, 2] , visibility: CustomSectionType::Public}
        }))
    );
}

#[test]
fn can_reject_module_with_too_many_custom_sections() {
    let custom_section =
        |name: String, content: Vec<u8>| Section::Custom(WasmCustomSection::new(name, content));
    let custom_sections: Vec<Section> = vec![
        custom_section("icp:private name1".to_string(), vec![0, 1]),
        custom_section("icp:public name2".to_string(), vec![0, 2]),
        custom_section("name3".to_string(), vec![0, 2]),
    ];
    let module = Module::new(custom_sections);

    assert_matches!(
        validate_custom_section(
            &module,
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
    let module = Module::new(vec![
        // Size of this custom section is 12 bytes.
        Section::Custom(WasmCustomSection::new(
            "icp:public name".to_string(),
            content.clone(),
        )),
        // Adding the size of this custom section will exceed the `max_custom_sections_size`.
        Section::Custom(WasmCustomSection::new(
            "icp:private custom_section".to_string(),
            content,
        )),
    ]);

    let max_custom_sections_size = NumBytes::new(14);
    assert_eq!(
        validate_custom_section(
            &module, &EmbeddersConfig {
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
    let custom_section =
        |name: String, content: Vec<u8>| Section::Custom(WasmCustomSection::new(name, content));
    let custom_sections: Vec<Section> = vec![
        custom_section("icp:private custom1".to_string(), vec![0, 1]),
        custom_section("icp:public custom2".to_string(), vec![0, 2]),
        custom_section("icp:public custom1".to_string(), vec![0, 3]),
    ];
    let module = Module::new(custom_sections);

    // Rejects the module because of duplicate custom section names.
    assert_eq!(
        validate_custom_section(
            &module,
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
    let custom_section =
        |name: String, content: Vec<u8>| Section::Custom(WasmCustomSection::new(name, content));
    let custom_sections: Vec<Section> = vec![
        custom_section("icp:private custom1".to_string(), vec![0, 1]),
        custom_section("icp:public custom2".to_string(), vec![0, 2]),
        custom_section("icp:dummy custom3".to_string(), vec![0, 3]),
    ];
    let module = Module::new(custom_sections);

    // Only `private` or `public` is allowed if `icp:` prefix is defined.
    assert_eq!(
        validate_custom_section(
            &module,
            &EmbeddersConfig {
                max_custom_sections: 5,
                ..Default::default()
            }
        ),
        Err(WasmValidationError::InvalidCustomSection(
            "Invalid custom section: Custom section named custom3 has no public/private scope defined.".to_string()
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
    assert_eq!(name, "private_name");
    assert_eq!(visibility, CustomSectionType::Private);

    // No public/private visibility defined.
    let name = "icp:x invalid_custom";
    assert_eq!(extract_custom_section_name(name),  Err(WasmValidationError::InvalidCustomSection(
            "Invalid custom section: Custom section named invalid_custom has no public/private scope defined.".to_string()
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
            wabt::wat2wasm(format!(
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
            wabt::wat2wasm(format!(
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
fn can_validate_module_with_call_simple_import() {
    // Instruments import of `call_simple` from `ic0`.
    let wasm = wat2wasm(
        r#"(module 
        (import "ic0" "call_simple" 
          (func $ic0_call_simple
            (param i32 i32)
            (param $method_name_src i32)    (param $method_name_len i32)
            (param $reply_fun i32)          (param $reply_env i32)
            (param $reject_fun i32)         (param $reject_env i32)
            (param $data_src i32)           (param $data_len i32)
            (result i32))
    ))"#,
    )
    .unwrap();

    assert_eq!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Ok(WasmValidationDetails {
            imports_details: WasmImportsDetails {
                imports_call_simple: true,
                ..Default::default()
            },
            ..Default::default()
        })
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
fn can_validate_valid_export_section_with_invalid_function_index() {
    let wasm = BinaryEncodedWasm::new(
        include_bytes!("instrumentation-test-data/export_section_invalid_function_index.wasm")
            .to_vec(),
    );
    assert_matches!(
        validate_wasm_binary(&wasm, &EmbeddersConfig::default()),
        Err(WasmValidationError::InvalidFunctionIndex {
            index: 0,
            import_count: 1
        })
    );
}

#[test]
fn can_validate_module_cycles_u128_related_imports() {
    // Instruments imports from `ic0`.
    let wasm = wat2wasm(
        r#"(module
        (import "ic0" "call_cycles_add128" (func $ic0_call_cycles_add128 (param i64 i64)))
        (import "ic0" "canister_cycle_balance128" (func $ic0_canister_cycles_balance128 (param i32)))
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
