#[cfg(test)]
mod tests;

use crate::types::{CanisterEndpoint, CanisterEndpoints};
use anyhow::{Error, Result};
use flate2::read::GzDecoder;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};
use wasmparser::{Export, ExternalKind, Parser, Payload};

pub struct WasmParser {
    path: PathBuf,
}

impl WasmParser {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn parse(&self) -> Result<CanisterEndpoints> {
        let buf = read_wasm_file(self.path.as_path())?;

        let payloads = Parser::new(0)
            .parse_all(&buf)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::from)?;

        let export_section = payloads
            .into_iter()
            .find_map(|payload| {
                if let Payload::ExportSection(exports) = payload {
                    Some(exports)
                } else {
                    None
                }
            })
            .ok_or(Error::msg("Export section not found in canister WASM"))?;

        let exports = export_section
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::from)?;

        Ok(exports
            .into_iter()
            .filter_map(try_from_wasm_export)
            .collect())
    }
}

fn read_wasm_file(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();

    if path.extension().is_some_and(|ext| ext == "gz") {
        let mut gz = GzDecoder::new(reader);
        gz.read_to_end(&mut buf)?;
    } else {
        reader.read_to_end(&mut buf)?;
    }

    Ok(buf)
}

fn try_from_wasm_export(Export { name, kind, .. }: Export) -> Option<CanisterEndpoint> {
    const CANISTER_QUERY_PREFIX: &str = "canister_query ";
    const CANISTER_UPDATE_PREFIX: &str = "canister_update ";

    if kind != ExternalKind::Func {
        return None;
    }

    name.strip_prefix(CANISTER_QUERY_PREFIX)
        .map(|q| CanisterEndpoint::Query(q.to_string()))
        .or_else(|| {
            name.strip_prefix(CANISTER_UPDATE_PREFIX)
                .map(|u| CanisterEndpoint::Update(u.to_string()))
        })
}
