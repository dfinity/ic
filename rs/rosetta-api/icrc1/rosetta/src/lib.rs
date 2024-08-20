use anyhow::{bail, Context};
use common::storage::storage_client::StorageClient;
use common::storage::types::MetadataEntry;
use ic_base_types::CanisterId;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use num_traits::ToPrimitive;
use rosetta_core::objects::Currency;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;
pub mod common;
pub mod construction_api;
pub mod data_api;
pub mod ledger_blocks_synchronization;

pub struct AppState {
    pub icrc1_agent: Arc<Icrc1Agent>,
    pub ledger_id: CanisterId,
    pub synched: Arc<Mutex<Option<bool>>>,
    pub archive_canister_ids: Arc<AsyncMutex<Vec<ArchiveInfo>>>,
    pub storage: Arc<StorageClient>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub symbol: String,
    pub decimals: u8,
}

impl From<Metadata> for Currency {
    fn from(value: Metadata) -> Self {
        Currency {
            symbol: value.symbol,
            decimals: value.decimals as u32,
            metadata: None,
        }
    }
}

impl Metadata {
    const METADATA_DECIMALS_KEY: &'static str = "icrc1:decimals";
    const METADATA_SYMBOL_KEY: &'static str = "icrc1:symbol";

    pub fn from_args(symbol: String, decimals: u8) -> Self {
        Self { symbol, decimals }
    }

    pub fn from_metadata_entries(entries: &[MetadataEntry]) -> anyhow::Result<Self> {
        let entries = entries
            .iter()
            .map(|entry| {
                let value = entry.value()?;
                Ok((entry.key.clone(), value))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        let decimals = entries
            .get(Self::METADATA_DECIMALS_KEY)
            .context("Could not find decimals in metadata entries.")
            .map(|value| match value {
                MetadataValue::Nat(decimals) => decimals
                    .0
                    .to_u8()
                    .context("Decimals cannot fit into an u8."),
                _ => bail!("Could not extract decimals from metadata."),
            })??;

        let symbol = entries
            .get(Self::METADATA_SYMBOL_KEY)
            .context("Could not find symbol in metadata entries.")
            .map(|value| match value {
                MetadataValue::Text(symbol) => Ok(symbol.clone()),
                _ => bail!("Could not extract symbol from metadata."),
            })??;

        Ok(Self { symbol, decimals })
    }
}
