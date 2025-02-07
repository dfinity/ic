use crate::validation::{
    augment_candid_service, encode_upgrade_args, CandidServiceArgValidationError,
};
use ic_wasm::{metadata, utils::parse_wasm};
use std::io::Read;
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use thiserror::Error;

const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];

#[derive(Debug, Error)]
pub enum CandidError {
    #[error("agent interaction failed: {0}")]
    WasmParseError(String),
    #[error("Wasm metadata has no Candid service declaration.")]
    NoCandidService,
    #[error("Candid service args are invalid: {0}.")]
    CandidServiceArgValidationError(CandidServiceArgValidationError),
}

pub trait Wasm {
    fn bytes(&self) -> &[u8];

    fn module_hash(&self) -> [u8; 32];

    fn list_metadata_sections(&self) -> Result<Vec<String>, CandidError> {
        let module = parse_wasm(self.bytes(), false)
            .map_err(|err| CandidError::WasmParseError(format!("{err:?}")))?;

        let metadata_sections = metadata::list_metadata(&module)
            .iter()
            .map(|metadata| metadata.to_string())
            .collect();

        Ok(metadata_sections)
    }

    fn canidid_service(&self) -> Result<Option<String>, CandidError> {
        let module = parse_wasm(self.bytes(), false)
            .map_err(|err| CandidError::WasmParseError(format!("{err:?}")))?;

        let read_section = |name: &str| -> Option<String> {
            let bytes = metadata::get_metadata(&module, &name).map(|contents| contents.to_vec());
            bytes.map(|bytes| std::str::from_utf8(&bytes).unwrap().to_string())
        };

        let (mut candid_service, mut candid_args) = (None, None);

        for section in metadata::list_metadata(&module) {
            let mut section = section.split(' ').collect::<Vec<&str>>();

            if section.is_empty() {
                // This cannot practically happen, as it would imply that all characters of
                // the section are whitespaces.
                continue;
            }

            // Consume this section's visibility specification, e.g. "icp:public" or "icp:private".
            let _visibility = section.remove(0).to_string();

            // The conjunction of the remaining parts are the section's name.
            let name = section.join(" ");

            if name == "candid:service" {
                candid_service = read_section(&name);
            }
            if name == "candid:args" {
                candid_args = read_section(&name);
            }
        }

        match (candid_service, candid_args) {
            (None, _) => Ok(None),
            (Some(candid_service), None) => Ok(Some(candid_service)),
            (Some(candid_service), Some(candid_args)) => {
                let candid_service = augment_candid_service(&candid_service, &candid_args)
                    .map_err(CandidError::CandidServiceArgValidationError)?;

                Ok(Some(candid_service))
            }
        }
    }

    /// Attempts to validate `args` against the Candid service from `self`'s metadata.
    ///
    /// If `args` is Some, returns the byte encoding of `args` in the Ok result.
    fn encode_candid_args(&self, args: &Option<String>) -> Result<Option<Vec<u8>>, CandidError> {
        let candid_service = self.canidid_service()?;

        let Some(candid_service) = candid_service else {
            return Err(CandidError::NoCandidService);
        };

        let candid_arg_bytes = encode_upgrade_args(candid_service, args)
            .map_err(CandidError::CandidServiceArgValidationError)?;

        Ok(candid_arg_bytes)
    }
}

pub struct WasmFile {
    path: PathBuf,
    bytes: Vec<u8>,
    module_hash: [u8; 32],
}

impl WasmFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Wasm for WasmFile {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn module_hash(&self) -> [u8; 32] {
        self.module_hash
    }
}

pub struct InMemoryWasm {
    bytes: Vec<u8>,
    module_hash: [u8; 32],
}

impl Wasm for InMemoryWasm {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn module_hash(&self) -> [u8; 32] {
        self.module_hash
    }
}

impl TryFrom<&[u8]> for InMemoryWasm {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Smoke test: Is this a ICP Wasm?
        if !bytes.starts_with(&RAW_WASM_HEADER) && !bytes.starts_with(&GZIPPED_WASM_HEADER) {
            return Err("The file does not look like a valid ICP Wasm module.".to_string());
        }

        let module_hash = ic_crypto_sha2::Sha256::hash(bytes);

        let bytes = bytes.to_vec();

        Ok(Self { bytes, module_hash })
    }
}

impl TryFrom<PathBuf> for WasmFile {
    type Error = String;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let mut file = match File::open(&path) {
            Err(err) => {
                return Err(format!(
                    "Cannot open Wasm file under {}: {}",
                    path.display(),
                    err,
                ));
            }
            Ok(file) => file,
        };

        // Create a buffer to store the file's content
        let mut bytes = Vec::new();

        // Read the file's content into the buffer
        if let Err(err) = file.read_to_end(&mut bytes) {
            return Err(format!("Cannot read Wasm file {}: {}", path.display(), err,));
        }

        let InMemoryWasm { bytes, module_hash } = InMemoryWasm::try_from(bytes.as_slice())?;

        Ok(Self {
            path,
            bytes,
            module_hash,
        })
    }
}
