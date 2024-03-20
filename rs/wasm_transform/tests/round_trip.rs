use ic_wasm_transform::Module;

fn round_trip(testname: &str, folder: &str) {
    let filename = format!(
        "{}/tests/{}/{}.wat",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        folder,
        testname
    );
    let buff = wat::parse_file(filename).expect("couldn't convert the input wat to Wasm");

    let module = Module::parse(&buff, false).unwrap();
    let result = module.encode().unwrap();
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
        start,
        const_expr
    );
}
