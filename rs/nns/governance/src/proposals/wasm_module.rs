use crate::pb::v1::{WasmModule, wasm_module};
use ic_crypto_sha2::Sha256;
use ic_nns_governance_api as api;

impl WasmModule {
    /// Validates that the WASM module has non-empty content.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let Self {
            content,

            // Currently not checked, because this field is populated by us,
            // derived from content, at least for now.
            hash: _,
        } = self;

        let mut defects = vec![];

        // Content must be non-empty. We could strengthen this by looking
        // for magic bytes to see if it is actually WASM or gzipped WASM.
        let Some(content) = &content else {
            return Err(vec!["wasm_module is required".to_string()]);
        };
        let wasm_module::Content::Inlined(content) = content;
        if content.is_empty() {
            defects.push("wasm_module must be non-empty".to_string());
        }

        if !defects.is_empty() {
            return Err(defects);
        }

        Ok(())
    }

    /// Returns a copy with potentially large fields (content) elided.
    pub fn abridge(&self) -> Self {
        let Self {
            hash,

            // Elided.
            content: _,
        } = self;

        Self {
            hash: hash.clone(),
            content: None,
        }
    }
}

impl From<api::WasmModule> for WasmModule {
    fn from(original: api::WasmModule) -> Self {
        let api::WasmModule::Inlined(content) = original;

        Self {
            hash: Some(Sha256::hash(&content).to_vec()),
            content: Some(wasm_module::Content::Inlined(content)),
        }
    }
}
