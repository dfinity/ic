fn main() {
    // Tell cargo to tell rustc to link the system sigsegv shared library.
    println!("cargo:rustc-link-lib=v8_wasm");

    // The bindgen::Builder is the main entry point to bindgen, and lets you
    // build up options for the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header_contents("wrapper.h", "#include <wasm.h>")
        // Derive Default trait implementations for C/C++ structures and types.
        .derive_default(true)
        // Derive Debug trait implementations for C/C++ structures and types.
        .derive_debug(true)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("wasm_api.rs"))
        .expect("Couldn't write bindings!");
}
