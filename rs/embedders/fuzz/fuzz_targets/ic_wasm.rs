use arbitrary::Arbitrary;
use ic_embedders::wasm_utils::validation::RESERVED_SYMBOLS;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use std::borrow::Cow;
use wasm_encoder::ValType;
use wasm_smith::Config;

#[derive(Arbitrary, Debug, Default, Copy, Clone)]
/// Can be used to configure wasm_smith to generate IC valid wasms.
pub struct ICWasmConfig;

impl Config for ICWasmConfig {
    // Trait definition - https://github.com/bytecodealliance/wasm-tools/blob/main/crates/wasm-smith/src/config.rs#L20
    // Spec adapted from
    // 1. https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api
    // 2. rs/embedders/src/wasm_utils/validation.rs
    // 3. https://github.com/bytecodealliance/wasm-tools/compare/main...venkkatesh-sekar:wasm-tools:make_globals_public

    // Can't export more than 1000 globals
    // const MAX_GLOBALS: usize = 1000;
    fn max_globals(&self) -> usize {
        1000
    }

    // min_funcs is set since total functions include imported functions
    // and wasm-smith tries to export an imported function.
    // From spec, only local functions can be exported
    fn min_funcs(&self) -> usize {
        10
    }

    // Can declare upto 50000 functions
    // const MAX_FUNCTIONS: usize = 50000
    fn max_funcs(&self) -> usize {
        50_000
    }

    // Allowed instructions per function
    // const WASM_FUNCTION_SIZE_LIMIT: usize = 1_000_000;
    // Caveats
    // - TODO(PSEC-1574) Couldn't restrict function complexity
    // - TODO(PSEC-1574) Instructions arbitrary logic can be improved in wasm-smith
    fn max_instructions(&self) -> usize {
        1_000_000
    }

    // Arbitrary value
    fn min_exports(&self) -> usize {
        10
    }

    // It may have a (start) function.
    // If there is a start function, instrumentation will export it as canister_start
    fn allow_start_export(&self) -> bool {
        true
    }

    // Exporting everything makes modding wasm-smith easier
    fn export_everything(&self) -> bool {
        true
    }

    // Arbitrary value
    fn min_data_segments(&self) -> usize {
        5
    }

    // Changing from default of 100
    fn max_data_segments(&self) -> usize {
        500
    }

    // Collects only System API imports from the Universal Canister WASM.
    // Other aspects of the canister are ignored.
    // Caveats
    // - TODO(PSEC-1574) No additional setup for importing env.table & env.memory
    fn available_imports(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(UNIVERSAL_CANISTER_WASM))
    }

    // Allows generations of custom sections
    // Caveats
    // - TODO(PSEC-1574) this flag is currently a no-op on wasm-smith side
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

    // Disable 64bit memory
    fn memory64_enabled(&self) -> bool {
        false
    }

    // Ensuring determinism for WASM
    // Defaults are reset here to ensure they are disabled
    // Wasm threads is disabled
    fn threads_enabled(&self) -> bool {
        false
    }

    // SIMD is disabled
    fn simd_enabled(&self) -> bool {
        false
    }

    // Canonicalize NaNs is disabled
    fn canonicalize_nans(&self) -> bool {
        false
    }

    // Modded wasm-smith config
    fn disallow_import_tags(&self) -> bool {
        true
    }

    fn disallow_import_globals(&self) -> bool {
        true
    }

    fn disallow_export_of_import_funcs(&self) -> bool {
        true
    }

    fn disallow_export_names(&self) -> Option<Cow<'_, [String]>> {
        let disallow_exports: Vec<String> = RESERVED_SYMBOLS
            .iter()
            .map(|name| name.to_string())
            .collect();
        Some(Cow::from(disallow_exports))
    }

    fn disallow_export_name_prefix(&self) -> Option<Cow<'_, [String]>> {
        Some(Cow::from(vec!["canister_".to_string()]))
    }

    fn export_func_name(&self) -> Option<Cow<'_, [String]>> {
        Some(Cow::from(vec![
            "canister_init".to_string(),
            "canister_inspect_message".to_string(),
            "canister_pre_upgrade".to_string(),
            "canister_post_upgrade".to_string(),
            "canister_heartbeat".to_string(),
            "canister_global_timer".to_string(),
        ]))
    }

    fn export_func_name_prefix(&self) -> Option<Cow<'_, [String]>> {
        Some(Cow::from(vec![
            "canister_query".to_string(),
            "canister_update".to_string(),
            "canister_composite_query".to_string(),
        ]))
    }

    fn func_types(&self) -> Option<Cow<'_, [(Vec<ValType>, Vec<ValType>)]>> {
        Some(Cow::from(vec![(vec![], vec![])]))
    }
}
