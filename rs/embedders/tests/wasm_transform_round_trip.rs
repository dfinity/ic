use wirm::Module;

fn round_trip(testname: &str, folder: &str) {
    let filename = format!(
        "{}/tests/{}/{}.wat",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        folder,
        testname
    );
    let buff = wat::parse_file(filename).expect("couldn't convert the input wat to Wasm");

    let mut module = Module::parse(&buff, false).unwrap();
    let result = module.encode();
    let out = wasmprinter::print_bytes(result).expect("couldn't translated Wasm to wat");
    let original = wasmprinter::print_bytes(buff).expect("couldn't convert original Wasm to wat");
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
