use std::fs;

use wabt::Features;

use ic_embedders::wasm_utils::wasm_transform::Module;

fn round_trip(testname: &str, folder: &str) {
    let filename = format!(
        "{}/tests/{}/{}.wat",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        folder,
        testname
    );
    let content = fs::read_to_string(filename).expect("couldn't read the input file");
    let mut features = Features::new();
    features.enable_bulk_memory();
    let buff = wabt::wat2wasm_with_features(content, features.clone())
        .expect("couldn't convert the input wat to Wasm");

    let module = Module::parse(&buff, false).unwrap();
    let result = module.encode().unwrap();
    let out = wabt::wasm2wat_with_features(result, features.clone())
        .expect("couldn't translated Wasm to wat");
    let original = wabt::wasm2wat_with_features(buff, features)
        .expect("couldn't convert original Wasm to wat");
    assert_eq!(out, original);
}

macro_rules! make_round_trip_tests {
    ($folder:literal, $($name:ident),*) => {
        $(
            #[test]
            fn $name() {
                crate::round_trip(stringify!($name), $folder)
            }
        )*
    };
}

mod round_trip {
    make_round_trip_tests!(
        "round-trip-test-data",
        import_func,
        data_section,
        func,
        func_locals,
        table,
        table_init,
        globals,
        exports,
        start
    );
}

/// Might as well run the round trip test on the files we use to test
/// instrumentation.
mod instrument_round_trip {
    make_round_trip_tests!(
        "instrumentation-test-data",
        app,
        app2,
        basic_import_call,
        basic_import,
        basic,
        control_flow,
        element,
        export_mutable_globals,
        fac,
        fizzbuzz,
        memory_fill,
        memory_grow,
        nested_ifs,
        recursive,
        simple_loop,
        start,
        zero_cost_ops
    );
}
