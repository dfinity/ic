// This build script checks if the compiler is nightly and sets
// the print_hooks feature if it is. This is because only nightly
// compilers currently support print hooks
#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=nightly_compiler");
}

#[rustversion::not(nightly)]
fn main() {}
