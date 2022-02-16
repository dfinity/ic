fn main() {
    if std::env::var("TARGET").unwrap() == "x86_64-unknown-linux-gnu" {
        cc::Build::new()
            .file("../src/backtrace.c")
            .debug(false)
            .compile("backtrace");
        println!("cargo:rerun-if-changed=../src/backtrace.c");
        println!("cargo:rustc-link-lib=dylib=unwind");
    }
}
