//! Types that are private to the crate.
use crate::state::UTXO_KEY_SIZE;
use bitcoin::{hashes::Hash, BlockHash, OutPoint, Script, TxOut, Txid};
use ic_btc_types::{Address, Height};
use std::convert::TryInto;

/// Used to signal the cut-off point for returning chunked UTXOs results.
pub struct Page {
    pub tip_block_hash: BlockHash,
    pub height: Height,
    pub outpoint: OutPoint,
}

impl Page {
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.tip_block_hash.to_vec(),
            self.height.to_bytes(),
            OutPoint::to_bytes(&self.outpoint),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, String> {
        // The page consists of 72 bytes and is the concatenation of the following:
        //
        //   1) A `BlockHash` (32 bytes)
        //   2) A `Height` (4 bytes)
        //   3) An `OutPoint` (36 bytes)
        if bytes.len() != 72 {
            return Err(format!("Invalid length {} != 72 for page", bytes.len()));
        }

        let height_offset = 32;
        let outpoint_offset = 36;
        let outpoint_bytes = bytes.split_off(outpoint_offset);
        let height_bytes = bytes.split_off(height_offset);

        let tip_block_hash = BlockHash::from_hash(
            Hash::from_slice(&bytes)
                .map_err(|err| format!("Could not parse tip block hash: {}", err))?,
        );
        // The height is parsed from bytes that are given by the user, so ensure
        // that any errors are handled gracefully instead of using
        // `Height::from_bytes` that can panic.
        let height = u32::from_be_bytes(
            height_bytes
                .into_iter()
                .map(|byte| byte ^ 255)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|err| format!("Could not parse page height: {:?}", err))?,
        );
        Ok(Page {
            tip_block_hash,
            height,
            outpoint: outpoint_from_bytes(outpoint_bytes)?,
        })
    }
}

fn outpoint_from_bytes(bytes: Vec<u8>) -> Result<OutPoint, String> {
    if bytes.len() != 36 {
        return Err(format!("Invalid length {} != 36 for outpoint", bytes.len()));
    }
    let txid = Txid::from_hash(
        Hash::from_slice(&bytes[..32]).map_err(|err| format!("Could not parse txid: {}", err))?,
    );
    let vout = u32::from_le_bytes(
        bytes[32..36]
            .try_into()
            .map_err(|err| format!("Could not parse vout: {}", err))?,
    );
    Ok(OutPoint { txid, vout })
}

/// A trait with convencience methods for storing an element into a stable structure.
pub trait Storable {
    fn to_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: Vec<u8>) -> Self;
}

impl Storable for OutPoint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = self.txid.to_vec(); // Store the txid (32 bytes)
        v.append(&mut self.vout.to_le_bytes().to_vec()); // Then the vout (4 bytes)

        // An outpoint is always exactly to the key size (36 bytes).
        assert_eq!(v.len(), UTXO_KEY_SIZE as usize);

        v
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len(), 36);
        OutPoint {
            txid: Txid::from_hash(Hash::from_slice(&bytes[..32]).unwrap()),
            vout: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
        }
    }
}

impl Storable for (TxOut, Height) {
    fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.1.to_le_bytes().to_vec(),       // Store the height (4 bytes)
            self.0.value.to_le_bytes().to_vec(), // Then the value (8 bytes)
            self.0.script_pubkey.to_bytes(),     // Then the script (size varies)
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let height = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let value = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        (
            TxOut {
                value,
                script_pubkey: Script::from(bytes.split_off(12)),
            },
            height,
        )
    }
}

impl Storable for Address {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self
            .len()
            .try_into()
            .expect("Address length must be <= 255")];
        bytes.append(&mut self.as_bytes().to_vec());
        bytes
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let address_len = bytes[0] as usize;
        String::from_utf8(bytes[1..address_len + 1].to_vec()).expect("Loading address cannot fail.")
    }
}

impl Storable for (Address, Height, OutPoint) {
    fn to_bytes(&self) -> Vec<u8> {
        vec![
            Address::to_bytes(&self.0),
            self.1.to_bytes(),
            OutPoint::to_bytes(&self.2),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let address_len = bytes[0] as usize;
        let height_offset = address_len + 1;
        let outpoint_offset = address_len + 5;
        let outpoint_bytes = bytes.split_off(outpoint_offset);
        let height_bytes = bytes.split_off(height_offset);

        (
            Address::from_bytes(bytes),
            Height::from_bytes(height_bytes),
            OutPoint::from_bytes(outpoint_bytes),
        )
    }
}

impl Storable for Height {
    fn to_bytes(&self) -> Vec<u8> {
        // The height is represented as an XOR'ed big endian byte array
        // so that stored entries are sorted in descending height order.
        self.to_be_bytes().iter().map(|byte| byte ^ 255).collect()
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        u32::from_be_bytes(
            bytes
                .into_iter()
                .map(|byte| byte ^ 255)
                .collect::<Vec<_>>()
                .try_into()
                .expect("height_bytes must of length 4"),
        )
    }
}

impl Storable for (Height, OutPoint) {
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.0.to_bytes(), OutPoint::to_bytes(&self.1)]
            .into_iter()
            .flatten()
            .collect()
    }

    fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let outpoint_offset = 4;
        let outpoint_bytes = bytes.split_off(outpoint_offset);

        (
            Height::from_bytes(bytes),
            OutPoint::from_bytes(outpoint_bytes),
        )
    }
}

#[test]
fn parsing_empty_page_fails() {
    assert!(Page::from_bytes(vec![]).is_err());
}

#[test]
fn parsing_page_with_invalid_length_fails() {
    assert!(Page::from_bytes(vec![1, 2, 3, 4, 5]).is_err());
    assert!(Page::from_bytes(vec![0; 71]).is_err());
    assert!(Page::from_bytes(vec![0; 73]).is_err());
}

#[test]
fn parsing_page_with_exact_length_succeeds() {
    assert!(Page::from_bytes(vec![0; 72]).is_ok());
}
