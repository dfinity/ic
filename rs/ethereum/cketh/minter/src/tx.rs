use crate::address::Address;
use crate::eth_rpc::{FeeHistory, Hash, Quantity};
use crate::numeric::{TransactionNonce, Wei};
use crate::state::read_state;
use ethnum::u256;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::DerivationPath;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};

const EIP1559_TX_ID: u8 = 2;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct AccessListItem {
    /// Accessed address
    pub address: Address,
    /// Accessed storage keys
    pub storage_keys: Vec<[u8; 32]>,
}

/// https://eips.ethereum.org/EIPS/eip-1559
#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct Eip1559TransactionRequest {
    pub chain_id: u64,
    pub nonce: TransactionNonce,
    pub max_priority_fee_per_gas: Wei,
    pub max_fee_per_gas: Wei,
    pub gas_limit: Quantity,
    pub destination: Address,
    pub amount: Wei,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Default, Clone, Serialize, PartialEq, Eq, Debug)]
pub struct Signature {
    pub v: u64,
    pub r: u256,
    pub s: u256,
}

pub fn encode_u256<T: Into<u256>>(stream: &mut RlpStream, value: T) {
    let value = value.into();
    let leading_empty_bytes: usize = value.leading_zeros() as usize / 8;
    stream.append(&value.to_be_bytes()[leading_empty_bytes..].as_ref());
}

impl Eip1559TransactionRequest {
    pub fn new_transfer(
        chain_id: u64,
        nonce: TransactionNonce,
        price: TransactionPrice,
        destination: Address,
        amount: Wei,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas: price.max_priority_fee_per_gas,
            max_fee_per_gas: price.max_fee_per_gas,
            gas_limit: price.gas_limit,
            destination,
            amount,
            data: Vec::new(),
            access_list: Vec::new(),
        }
    }

    pub fn hash(&self) -> Hash {
        Hash(ic_crypto_sha3::Keccak256::hash(
            self.encode_eip1559_payload(None),
        ))
    }

    pub async fn sign(&self) -> Result<Vec<u8>, (RejectionCode, String)> {
        let hashed_tx = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let (r_bytes, s_bytes) = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(crate::MAIN_DERIVATION_PATH),
            hashed_tx.0,
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
        rlp.append(&self.destination.as_ref());
        encode_u256(&mut rlp, self.amount);
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TransactionPrice {
    pub gas_limit: Quantity,
    pub max_fee_per_gas: Wei,
    pub max_priority_fee_per_gas: Wei,
}

impl TransactionPrice {
    pub fn max_transaction_fee(&self) -> Wei {
        self.max_fee_per_gas
            .checked_mul(self.gas_limit)
            .expect("ERROR: max_transaction_fee overflow")
    }
}

pub fn estimate_transaction_price(fee_history: &FeeHistory) -> TransactionPrice {
    // average value between the `minSuggestedMaxPriorityFeePerGas`
    // used by Metamask, see
    // https://github.com/MetaMask/core/blob/f5a4f52e17f407c6411e4ef9bd6685aab184b91d/packages/gas-fee-controller/src/fetchGasEstimatesViaEthFeeHistory/calculateGasFeeEstimatesForPriorityLevels.ts#L14
    const MIN_MAX_PRIORITY_FEE_PER_GAS: Wei = Wei::new(1_500_000_000); //1.5 gwei
    const TRANSACTION_GAS_LIMIT: Quantity = Quantity::new(21_000);
    let base_fee_of_next_finalized_block = *fee_history
        .base_fee_per_gas
        .last()
        .expect("base_fee_per_gas should not be empty to be able to evaluate transaction price");
    let max_priority_fee_per_gas = {
        let mut rewards: Vec<&Wei> = fee_history.reward.iter().flatten().collect();
        let historic_max_priority_fee_per_gas =
            **median(&mut rewards).expect("should be non-empty with rewards of the last 5 blocks");
        std::cmp::max(
            historic_max_priority_fee_per_gas,
            MIN_MAX_PRIORITY_FEE_PER_GAS,
        )
    };
    let max_fee_per_gas = Wei::TWO
        .checked_mul(base_fee_of_next_finalized_block)
        .expect("ERROR: overflow during transaction price estimation")
        .checked_add(max_priority_fee_per_gas)
        .expect("ERROR: overflow during transaction price estimation");
    TransactionPrice {
        gas_limit: TRANSACTION_GAS_LIMIT,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    }
}

fn median<T: Ord>(values: &mut [T]) -> Option<&T> {
    if values.is_empty() {
        return None;
    }
    let (_, item, _) = values.select_nth_unstable(values.len() / 2);
    Some(item)
}
