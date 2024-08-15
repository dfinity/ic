fn main() {
    if std::env::var("TARGET").unwrap() == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-lib=dylib=lzma");
    }
}
