use crate::address::Address;
use crate::state::read_state;
use ethnum::u256;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::DerivationPath;
use rlp::RlpStream;
use serde::Serialize;

const EIP1559_TX_ID: u8 = 2;

pub struct AccessListItem {
    /// Accessed address
    pub address: Address,
    /// Accessed storage keys
    pub storage_keys: Vec<[u8; 32]>,
}

/// https://eips.ethereum.org/EIPS/eip-1559
pub struct TransactionRequest {
    pub chain_id: u64,
    pub to: Address,
    pub nonce: u256,
    pub gas_limit: u256,
    pub max_fee_per_gas: u256,
    pub value: u256,
    pub data: Vec<u8>,
    pub transaction_type: u64,
    pub access_list: Vec<AccessListItem>,
    pub max_priority_fee_per_gas: u256,
}

#[derive(Default, Clone, Serialize, PartialEq, Eq, Debug)]
pub struct Signature {
    pub v: u64,
    pub r: u256,
    pub s: u256,
}

pub fn encode_u256(stream: &mut RlpStream, value: u256) {
    let leading_empty_bytes: usize = value.leading_zeros() as usize / 8;
    stream.append(&value.to_be_bytes()[leading_empty_bytes..].as_ref());
}

impl TransactionRequest {
    pub async fn sign(&self) -> Result<Vec<u8>, (RejectionCode, String)> {
        let hashed_tx = ic_crypto_sha3::Keccak256::hash(self.encode_eip1559_payload(None));
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let (r_bytes, s_bytes) = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(crate::MAIN_DERIVATION_PATH),
            hashed_tx,
        )
        .await
        .expect("failed to sign tx");
        let v = (s_bytes[31] % 2) as u64;
        let r = u256::from_be_bytes(r_bytes);
        let s = u256::from_be_bytes(s_bytes);
        let sig = Signature { v, r, s };

        Ok(self.encode_eip1559_payload(Some(sig)))
    }

    pub fn encode_eip1559_payload(&self, signature: Option<Signature>) -> Vec<u8> {
        const ACCESS_FIELD_COUNT: usize = 2;
        const UNSIGNED_FIELD_COUNT: usize = 9;
        const SIGNED_FIELD_COUNT: usize = UNSIGNED_FIELD_COUNT + 3; // v, r, s

        let mut rlp = RlpStream::new();
        rlp.append_raw(&[EIP1559_TX_ID][..], 0);
        let num_fields = if signature.is_some() {
            SIGNED_FIELD_COUNT
        } else {
            UNSIGNED_FIELD_COUNT
        };
        rlp.begin_list(num_fields);
        rlp.append(&self.chain_id);
        encode_u256(&mut rlp, self.nonce);
        encode_u256(&mut rlp, self.max_priority_fee_per_gas);
        encode_u256(&mut rlp, self.max_fee_per_gas);
        encode_u256(&mut rlp, self.gas_limit);
        rlp.append(&self.to.as_ref());
        encode_u256(&mut rlp, self.value);
        rlp.append(&self.data);
        rlp.begin_list(self.access_list.len());
        for access in self.access_list.iter() {
            rlp.begin_list(ACCESS_FIELD_COUNT);
            rlp.append(&access.address.as_ref());
            rlp.begin_list(access.storage_keys.len());
            for storage_key in access.storage_keys.iter() {
                rlp.append(&storage_key.as_ref());
            }
        }
        if let Some(signature) = signature {
            rlp.append(&signature.v);
            encode_u256(&mut rlp, signature.r);
            encode_u256(&mut rlp, signature.s);
        }
        rlp.out().to_vec()
    }
}
