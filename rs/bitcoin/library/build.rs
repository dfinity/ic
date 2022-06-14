use std::env;

fn main() {
    if env::var("DFX_NETWORK").unwrap_or_else(|_| "".to_string()) != "ic" {
        println!("cargo:rustc-cfg=locally");
    }
}
