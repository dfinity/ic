use std::fs::File;
use std::path::PathBuf;

fn main() {
    // The environment variable `MAINNET_ROUTING_TABLE` pointing to a file (storing the mainnet routing table) is needed
    // for golden state tests to compile. There are two flows to support:
    // - code validation using `cargo`: we create a dummy file and point `MAINNET_ROUTING_TABLE` to that file for code validation to succeed;
    // - running golden state tests using `bazel`: `bazel` always sets `MAINNET_ROUTING_TABLE` to an actual file storing the mainnet routing table
    //   and thus we don't override `MAINNET_ROUTING_TABLE` if already set.
    let mainnet_routing_table_var_name = "MAINNET_ROUTING_TABLE".to_string();
    if std::env::var(&mainnet_routing_table_var_name).is_err() {
        let mainnet_routing_table_file_name = "mainnet_routing_table.json";
        let mainnet_routing_table_file_path =
            PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(mainnet_routing_table_file_name);
        File::create(&mainnet_routing_table_file_path).unwrap();
        println!(
            "cargo:rustc-env={}={}",
            mainnet_routing_table_var_name,
            mainnet_routing_table_file_path.display()
        );
    }
}
