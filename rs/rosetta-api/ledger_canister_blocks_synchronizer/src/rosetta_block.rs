use std::collections::BTreeMap;

use ic_crypto_sha2::Sha256;
use icp_ledger::{BlockIndex, TimeStamp, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RosettaBlock {
    pub index: BlockIndex,
    pub parent_hash: Option<[u8; 32]>,
    pub timestamp: TimeStamp,
    pub transactions: BTreeMap<BlockIndex, Transaction>,
}

impl RosettaBlock {
    pub fn hash(&self) -> [u8; 32] {
        let mut writer = Sha256::new();
        ciborium::into_writer(&self, &mut writer).unwrap();
        writer.finish()
    }
}
