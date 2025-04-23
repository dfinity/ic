= Introducing a new System API or changing an existing one:

1. Specify the new API or make the required changes to an existing one in the [portal](https://github.com/dfinity/portal) repository. Typically, you would want to make changes in the [following file](https://github.com/dfinity/portal/blob/master/docs/references/ic-interface-spec.md). Make sure to provide motivation for the new API or changes you're making and how it would benefit the ICP protocol.
2. The Rust CDK needs to be updated: [Rust Canister Development Kit](https://github.com/dfinity/cdk-rs). Inform *@eng-sdk* of the work required.
3. Motoko needs to be updated: [Motoko](https://github.com/dfinity/motoko). Inform *@eng-motoko* of the work required.
4. Implement the new API in `embedders` crate. Main parts that need to be updated: the wasm validation, the linker of the system API against the Wasm module and the implementation of the system api itself.
5. Add an entry for the new System API (or update an existing entry) in `system_api_complexity.rs` to capture the overhead of calling this API. See the doc comment in the file for more details.
6. Tests: functionality and wasm validation code tests. System API availability tests should also be extended for the new/updated API. Additionally, add some execution level tests that exercise the API. These can be typically added in `execution_environment/tests/hypervisor.rs`.
7. Update the implementation of the universal canister.
8. Once the *Interface Spec* PR has been agreed on, [Motoko](https://github.com/dfinity/motoko) and [Rust CDK](https://github.com/dfinity/cdk-rs) can be updated to use the new API on a feature branch. Coordinate with *@eng-sdk* and *@eng-motoko* as needed.
9. Once the implementation is rolled out fully on mainnet, the Interface Spec PR, Rust CDK, and Motoko changes can be merged to master.