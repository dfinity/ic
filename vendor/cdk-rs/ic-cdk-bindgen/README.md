# ic-cdk-bindgen

Bindings generator from Candid to Rust for `ic-cdk`.

`ic-cdk-bindgen` is designed to be used for build-time code generation as part of a Cargo build-script.

## Example

The goal is to conveniently make inter-canister calls to the canister `callee`.

First, add `ic-cdk-bindgen` as a build dependency to `Cargo.toml`.

```bash
cargo add --build ic-cdk-bindgen
```

Next, add the Candid interface file of the `callee` canister (e.g., at `candid/callee.did`).

To generate Rust code from `callee.did`, we use `ic-cdk-bindgen` in the crate's `build.rs` build-script :

```rust,no_run
// build.rs
fn main() {
    let CALLEE_CANISTER_ID : candid::Principal = todo!();
    ic_cdk_bindgen::Config::new("callee", "candid/callee.did")
        .static_callee(CALLEE_CANISTER_ID)
        .generate();
}
```

Finally, in the canister source code (e.g. `lib.rs`, `main.rs`), include the generated code:

```rust,ignore
#[allow(dead_code, unused_imports)]
mod callee {
    include!(concat!(env!("OUT_DIR"), "/callee.rs"));
}

#[ic_cdk::update]
async fn invoke_callee() {
    // In modern IDE/editors like VSCode, you can often use "Go to Definition" or similar features
    // to quickly navigate to the generated bindings.
    let _result = callee::some_method().await;
}
```

## Dynamic Callee Mode

The example above demonstrates the "Static callee" mode, where the canister ID is known at compile time.
In this mode, the generated code includes the hardcoded canister ID, making it suitable for deployments
where the canister ID is fixed and known ahead of time.

The ICP Environment Variables feature enables a workflow where the canister ID can be set via
environment variables, allowing for more flexible deployments. The "Dynamic callee" mode is designed for this workflow.

For example, the `icp-cli` CLI tool sets an Env Var if there is a canister named `callee` in the project:
- name: `ICP_CANISTER_ID:callee`
- value: The text representation of the Principal

Just apply a one line change in the `build.rs` script:

```rust,no_run
// build.rs
fn main() {
    ic_cdk_bindgen::Config::new("callee", "candid/callee.did")
        .dynamic_callee("ICP_CANISTER_ID:callee") // <--- Change made here
        .generate();
}
```

Then the generated code will use the canister ID from the environment variable at runtime.

## Type Selector Config

The `candid` project specifies a "Type Selector" configuration language that controls the details of Rust code generation.
You can use type selectors to customize how Candid types are translated to Rust types.

First, create a TOML file for your canister (e.g., `callee.toml`) with a `rust` table at the top level. For example:

```toml
# callee.toml
[rust]
visibility = "pub(crate)"
attributes = "#[derive(CandidType, Deserialize, Clone, Debug)]"
blob.use_type = "Vec<u8>"
change_details.variant.creation.name = "CreationRecord"
```

Then, add the type selector configuration to your build script using `set_type_selector_config`:

```rust,no_run
// build.rs
fn main() {
    ic_cdk_bindgen::Config::new("callee", "candid/callee.did")
        .set_type_selector_config("path/to/callee.toml")
        .dynamic_callee("ICP_CANISTER_ID:callee")
        .generate();
}
```

The updated bindings can be seen by using the "Go to definition" or similar features from your IDE/editors.

For more details on type selector syntax and capabilities, refer to the [specification](https://github.com/dfinity/candid/blob/master/spec/Type-selector.md#rust-binding-configuration).


## Use with `dfx`

The previous version of `ic-cdk-bindgen` was designed to only work with `dfx` CLI tool.
It relied on the `dfx` to set up some environment variables (note: this is the general UNIX environment variable),
so that bindgen could learn the path to the Candid file and the canister ID at build time.
Such `dfx` specific handling is removed in the updated version of `ic-cdk-bindgen`.

To use the updated `ic-cdk-bindgen` with `dfx`, it is recommended to handle the `dfx` environment variables manually in your `build.rs` script.

```rust,no_run
// build.rs
fn main() {
    let name = "callee";
    let normalized_name = name.replace('-', "_").to_uppercase();
    let canister_id_var_name = format!("CANISTER_ID_{}", normalized_name);
    let canister_id_str = std::env::var(&canister_id_var_name).unwrap();
    let canister_id = candid::Principal::from_text(&canister_id_str).unwrap();
    let candid_path_var_name = format!("CANISTER_CANDID_PATH_{}", normalized_name);
    let candid_path = std::env::var(&candid_path_var_name).unwrap();
    ic_cdk_bindgen::Config::new(name, candid_path)
        .static_callee(canister_id)
        .generate();
}
```
