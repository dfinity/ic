= Introducing a new System API or changing an existing one:

1. Specify the new API or make the required changes to an existing one in the (https://github.com/dfinity/portal)[portal] repository. Typically, you would want to make changes in the (docs/references/ic-interface-spec.md)[following file]. Make sure to provide motivation for the new API or changes you're making and how it would benefit the ICP protocol.
2. The Rust CDK would need to be updated: https://github.com/dfinity/cdk-rs[Rust Canister Development Kit]. Inform *@eng-sdk* of the work required.
3. Motoko would need to be updated: https://github.com/dfinity/motoko[Motoko]. Inform *@eng-motoko* of the work required.
4. Implement the new API in `embedders` crate. Main parts that need to be updated: the wasm validation, the linker of the system API against the Wasm module and the implementation of the system api itself.
5. Add an entry for the new System API (or update an existing entry) in `system_api_complexity.rs` to capture the overhead of calling this API. See the doc comment in the file for more details.
6. Tests: functionality and wasm validation code tests. System API availability tests should also be extended for the new/updated API. Additionally, add some execution level tests that exercise the API. These can be typically added in `execution_environment/tests/hypervisor.rs`.
7. Update the implementation of the universal canister and replace `universal-canister.wasm.gz` with the newly generated one.
8. Once the *Interface Spec* PR is marked as final, https://github.com/dfinity/motoko[Motoko] and https://github.com/dfinity/cdk-rs[Rust CDK] can be updated to use the new API. Coordinate with *@eng-sdk* and *@eng-motoko* as needed.
9. Once the implementation is rolled out fully on mainnet, the Interface Spec PR can be merged to master.