use arbitrary::Arbitrary;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use std::borrow::Cow;
use wasm_smith::Config;

#[derive(Arbitrary, Debug, Default, Copy, Clone)]
/// Can be used to configure wasm_smith to generate IC valid wasms.
pub struct ICWasmConfig;

impl Config for ICWasmConfig {
    // Trait definition - https://github.com/bytecodealliance/wasm-tools/blob/main/crates/wasm-smith/src/config.rs#L20
    // Adapted from https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api
    // and rs/embedders/src/wasm_utils/validation.rs
    //
    // TODO (PSEC-1204): The individual config options below come with several caveats which are current restrictions in wasm_smith.
    // PSEC-1204 intends to address these to further improve the generation of IC valid wasms.
    //
    // Ensuring determinism for WASM
    // - Wasm threads defaults to false
    // - SIMD defaults to false
    // - Canonicalize NaNs defaults to false
    //
    // General caveats :
    // - No accessors for generated values like globals, funcs - struct Module fields are private

    // It may have a (start) function.
    fn allow_start_export(&self) -> bool {
        true
    }

    // Collects only System API imports from the Universal Canister WASM.
    // Other aspects of the canister are ignored.
    // Caveats
    // - No additional setup for importing env.table & env.memory
    // - globals and tags are not imported
    fn available_imports(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(UNIVERSAL_CANISTER_WASM))
    }

    // Importing globals is not allowed in IC
    // Can't export more than 300 globals
    // const MAX_GLOBALS: usize = 300;
    // Caveats
    // - wasm_smith currently does not allow to segregate between exported and imported globals
    // TODO (PSEC-1204) - update max_globals once ExecutionState can be provided with created globals
    fn max_globals(&self) -> usize {
        0
    }

    // Can declare upto 50000 functions
    // const MAX_FUNCTIONS: usize = 50000
    // Caveats
    // - Custom function handling is not possible
    // - If it exports a function called canister_init, the function must have type () -> ().
    // - If it exports a function called canister_inspect_message, the function must have type () -> ().
    // - If it exports a function called canister_heartbeat, the function must have type () -> ().
    // - If it exports a function called canister_global_timer, the function must have type +() -> ()+.
    // - If it exports any functions called canister_update <name> or canister_query <name> for some name, the functions must have type () -> ().
    // - It may not export both canister_update <name> and canister_query <name> with the same name.
    // - It may not export other methods the names of which start with the prefix canister_ besides the methods allowed above.
    fn max_funcs(&self) -> usize {
        50_000
    }

    // Allowed instruction per function
    // const WASM_FUNCTION_SIZE_LIMIT: usize = 1_000_000;
    // Caveats
    // - Couldn't restrict function complexity
    fn max_instructions(&self) -> usize {
        1_000_000
    }

    // Total maximum allowed exports
    // Caveats
    // - Unable to restrict RESERVED_SYMBOLS from exporting
    fn max_exports(&self) -> usize {
        6_200
    }

    // Changing from default of 100
    // Caveats
    // - Restrict that offset-expressions in data sections consist of only one constant expression.
    fn max_data_segments(&self) -> usize {
        500
    }

    // Allows generations of custom sections
    // Caveats
    // - It may not have both icp:public <name> and icp:private <name> with the same name as the custom section name.
    // - It may not have other custom sections the names of which start with the prefix icp: besides the `icp:public ` and `icp:private
    // - declare <= 16 exported custom sections
    // - the total size of the exported custom sections doesn't exceeds 1MiB
    fn generate_custom_sections(&self) -> bool {
        true
    }

    // Bulk memory proposal is enabled for IC
    fn bulk_memory_enabled(&self) -> bool {
        true
    }

    // Reference types proposal is enabled for IC
    fn reference_types_enabled(&self) -> bool {
        true
    }
}
