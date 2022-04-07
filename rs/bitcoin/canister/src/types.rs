//! Types that are private to the crate.
use crate::state::UTXO_KEY_SIZE;
use bitcoin::{hashes::Hash, OutPoint, Script, TxOut, Txid};
use std::convert::TryInto;

pub type Address = String;
pub type Height = u32;

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

impl Storable for (Address, OutPoint) {
    fn to_bytes(&self) -> Vec<u8> {
        vec![Address::to_bytes(&self.0), OutPoint::to_bytes(&self.1)]
            .into_iter()
            .flatten()
            .collect()
    }

    fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let address_len = bytes[0] as usize;
        let outpoint_offset = address_len + 1;
        let outpoint_bytes = bytes.split_off(outpoint_offset);
        (
            Address::from_bytes(bytes),
            OutPoint::from_bytes(outpoint_bytes),
        )
    }
}
