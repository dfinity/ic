Management Canister API Contribution Guideline
====

The following steps outline the recommended approach to introduce a new Management Canister API or change an existing one:

1. Specify the new API or make the required changes to an existing one in the *Interface Specification* in the [portal](https://github.com/dfinity/portal) repository:
   - typically, you would want to make changes in the [following file](https://github.com/dfinity/portal/blob/master/docs/references/ic-interface-spec.md);
   - additionally, make sure you update the [Candid interface](https://github.com/dfinity/portal/blob/master/docs/references/_attachments/ic.did) of the Management Canister accordingly;
   - furthermore, make sure to provide motivation for the new API or changes you're making and how it would benefit the ICP protocol.

2. The public Management Canister [types](https://crates.io/crates/ic-management-canister-types) need to be updated. Inform *@eng-sdk* of the work required. 

---

**NOTE**
The public API of the Management Canister is defined in Candid. Candid is designed to allow services to evolve and has rules to make that possible. Here are some tips to help you not paint yourself into a corner and accidently create a non-evolvable API: 
- If you have an enum (Candid: variant) in the response of any API method, and one of its variants (Candid: tags) is the unit type, this variant cannot evolve. The reason is that by default, the Rust definition `enum { A } ` is interpreted as Candid `variant { A }` which implicitly means `variant { A : null; }`. `null` cannot be specialized into any `T`, so you cannot attach more data later (Why is this counterintuitive? Because Candid records can evolve to have more data, but `null` cannot.). If you want to create non-evolvable variants, this is fine. Otherwise, you can be more explicit in your definitions: `variant { A : reserved; }` _is_ evolvable as a response, because `reserved` can be specialized to any `T`. In order to achieve this explicitly in Rust, use `enum { A(candid::Reserved) }`. 

---

3. The [Rust CDK](https://github.com/dfinity/cdk-rs) needs to be updated. Inform *@eng-sdk* of the work required.

4. [Motoko](https://github.com/dfinity/motoko) needs to be updated. Inform *@eng-motoko* of the work required.

5. Add any new types or update existing ones in `types/management_canister_types`. If possible, stick to existing naming conventions. E.g., error variants tend to have a domain specific prefix and a clear suffix describing the error, e.g., `ErrorCode::CanisterNotFound`.

6. Update the candid declarations in `types/management_canister_types/tests/ic.did`. If a new management canister API is introduced, add a placeholder for it in `types/management_canister_types/tests/candid_equality.rs`.

7. Implement the new API in the `execution_environment` crate. Main parts that need to be updated are:
   - the core implementation in the `canister_manager` module;
   - wiring up the new API in `ExecutionEnvironment` to expose it externally.

   Make sure to implement robust input validation and think of various (security-relevant) edge cases.

   Note: Some management methods (e.g., `install_code` and `install_chunked_code`) include dedicated logic to handle rollback after failures. However, for the majority of methods, there should be a clearly defined point during execution at which changes become permanent and rollback is no longer possible. Specifically:
   - no changes are performed before that point (only `&self` access to the state);
   - no failure can happen after that point (the execution is guaranteed to succeed and return a reply).

   If a feature cannot be implemented on one PR or the API should be experimental for a time, define a feature flag in `rs/config/src/execution_environment.rs` and gate the API behind the flag. This way, the feature can be rolled out to a few select subnets via a feature release. Typically, there are tests that set the flags either way and ensure the proper behaviour in each case. 

8. Write tests to cover the new or updated functionality:
   - Use the `ExecutionTest` framework by default.
   - Use the `StateMachine` framework if the feature involves inter-canister calls, canister HTTPS outcalls, threshold signatures, or checkpointing. These require mocked Consensus layer outputs or a full state manager.

9. Once the *Interface Specification* change has been agreed on, the public Management Canister [types](https://crates.io/crates/ic-management-canister-types), [Motoko](https://github.com/dfinity/motoko), and [Rust CDK](https://github.com/dfinity/cdk-rs) can be updated to use the new API on a feature branch. Coordinate with *@eng-sdk* and *@eng-motoko* as needed. The new functionality is enabled for testing in PocketIC (on a PocketIC instance created with `enable_beta_features` set) by enabling the corresponding feature flags in `rs/pocket_ic_server/src/beta_features.rs`.

10. To do a feature release on a set of subnets, prepare an unmerged commit which toggles the flag and contact *@eng-release*. After it is rolled out and tested, a feature release can be made to all subnets. When all is fine, the commit that enables the flag by default can be merged to master (and the tests relying on the flag's default have to be adjusted). Finally, the flag and associated setters can be removed. 

11. Once the implementation is rolled out fully on mainnet, the Interface Specification, public Management Canister types, Rust CDK, and Motoko changes can be merged to master.
