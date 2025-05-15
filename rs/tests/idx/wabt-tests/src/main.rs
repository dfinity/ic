use std::path::PathBuf;

use wabt_tests::{
    add_exports, add_functions, add_globals, add_long_exported_function_names, export,
    large_custom_sections, many_custom_sections, with_custom_sections, write, write_base_end,
    write_bytes, write_end,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out: PathBuf = args[1].clone().into();
    let root = out.parent().unwrap();

    write(
        root,
        "valid_import.wasm",
        r#"(module
    (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
)"#,
    );

    write(
        root,
        "invalid_import.wasm",
        r#"(module
    (import "ic0" "my_call_perform" (func $ic0_call_perform (result i32)))
)"#,
    );

    write_base_end(
        root,
        "start.wasm",
        vec![
            "    (start $inc)\n".to_string(),
            export("canister_query read", "read"),
        ],
    );

    write_base_end(
        root,
        "no_start.wasm",
        vec![export("canister_query read", "read")],
    );

    for fun in &["reta", "retb"] {
        for method in &[
            "canister_init",
            "canister_inspect_message",
            "canister_heartbeat",
            "canister_global_timer",
            "canister_on_low_wasm_memory",
            "canister_update upd",
            "canister_query que",
            "canister_composite_query cq",
            "canister_pre_upgrade",
            "canister_post_upgrade",
        ] {
            write_base_end(
                root,
                &format!("invalid_{}_{}.wasm", str::replace(method, " ", "_"), fun),
                vec![export(method, fun)],
            );
        }
    }

    write_base_end(
        root,
        "name_clash_update_query.wasm",
        vec![
            export("canister_update read", "read"),
            export("canister_query read", "read"),
        ],
    );

    write_base_end(
        root,
        "name_clash_update_composite_query.wasm",
        vec![
            export("canister_update read", "read"),
            export("canister_composite_query read", "read"),
        ],
    );

    write_base_end(
        root,
        "name_clash_query_composite_query.wasm",
        vec![
            export("canister_query read", "read"),
            export("canister_composite_query read", "read"),
        ],
    );

    write_base_end(
        root,
        "invalid_canister_export.wasm",
        vec![export("canister_callback read", "read")],
    );

    write_bytes(
        root,
        "duplicate_custom_section.wasm",
        with_custom_sections(
            [
                (b"icp:public x".to_vec(), b"a".to_vec()),
                (b"icp:private x".to_vec(), b"b".to_vec()),
            ]
            .to_vec(),
        ),
    );

    write_bytes(
        root,
        "invalid_custom_section.wasm",
        with_custom_sections([(b"icp:mine x".to_vec(), b"y".to_vec())].to_vec()),
    );

    write_base_end(
        root,
        "many_functions.wasm",
        add_functions(50000 - 4), // there are already 4 functions declared in base (excl. imported)
    );

    write_base_end(
        root,
        "too_many_functions.wasm",
        add_functions((50000 - 4) + 1), // there are already 4 functions declared in base (excl. imported)
    );

    write_end(root, "many_globals.wasm", add_globals(1000));

    write_end(root, "too_many_globals.wasm", add_globals(1001));

    write_bytes(
        root,
        "many_custom_sections.wasm",
        with_custom_sections(many_custom_sections(16)),
    );

    write_bytes(
        root,
        "too_many_custom_sections.wasm",
        with_custom_sections(many_custom_sections(17)),
    );

    write_base_end(root, "many_exports.wasm", add_exports(1000));

    write_base_end(root, "too_many_exports.wasm", add_exports(1001));

    write_base_end(
        root,
        "long_exported_function_names.wasm",
        add_long_exported_function_names(20000),
    );

    write_base_end(
        root,
        "too_long_exported_function_names.wasm",
        add_long_exported_function_names(20001),
    );

    write_bytes(
        root,
        "large_custom_sections.wasm",
        with_custom_sections(large_custom_sections(1 << 20)),
    );

    write_bytes(
        root,
        "too_large_custom_sections.wasm",
        with_custom_sections(large_custom_sections((1 << 20) + 1)),
    );

    // Corner cases

    write_base_end(
        root,
        "invalid_empty_query_name.wasm",
        vec![export("canister_query", "read")],
    );

    write_base_end(
        root,
        "empty_query_name.wasm",
        vec![export("canister_query ", "read")],
    );

    write_base_end(
        root,
        "query_name_with_spaces.wasm",
        vec![export("canister_query name with spaces", "read")],
    );

    write_bytes(
        root,
        "invalid_empty_custom_section_name.wasm",
        with_custom_sections([(b"icp:public".to_vec(), b"a".to_vec())].to_vec()),
    );

    write_bytes(
        root,
        "empty_custom_section_name.wasm",
        with_custom_sections([(b"icp:public ".to_vec(), b"a".to_vec())].to_vec()),
    );

    write_bytes(
        root,
        "custom_section_name_with_spaces.wasm",
        with_custom_sections([(b"icp:public name with spaces".to_vec(), b"a".to_vec())].to_vec()),
    );
}
