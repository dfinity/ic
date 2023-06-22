fn main() {
    if std::env::var("TARGET").unwrap() == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-lib=static=unwind");
        println!("cargo:rustc-link-lib=static=unwind-ptrace");
        println!("cargo:rustc-link-lib=static=unwind-x86_64");
        println!("cargo:rustc-link-lib=dylib=lzma");
    }
}
