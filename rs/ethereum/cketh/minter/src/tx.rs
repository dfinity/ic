#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::eth_rpc::{FeeHistory, Hash, Quantity};
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::numeric::{BlockNumber, TransactionNonce, Wei};
use crate::state::{lazy_call_ecdsa_public_key, read_state};
use ethnum::u256;
use ic_crypto_ecdsa_secp256k1::RecoveryId;
use ic_ic00_types::DerivationPath;
use minicbor::{Decode, Encode};
use rlp::RlpStream;
use serde::{Deserialize, Serialize};

const EIP1559_TX_ID: u8 = 2;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq, Encode, Decode)]
#[cbor(transparent)]
pub struct AccessList(#[n(0)] pub Vec<AccessListItem>);

impl AccessList {
    pub fn new() -> Self {
        Self(Vec::new())
    }
}

impl Default for AccessList {
    fn default() -> Self {
        Self::new()
    }
}

impl rlp::Encodable for AccessList {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_list(&self.0);
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq, Encode, Decode)]
#[cbor(transparent)]
pub struct StorageKey(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq, Encode, Decode)]
pub struct AccessListItem {
    /// Accessed address
    #[n(0)]
    pub address: Address,
    /// Accessed storage keys
    #[n(1)]
    pub storage_keys: Vec<StorageKey>,
}

impl rlp::Encodable for AccessListItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        const ACCESS_FIELD_COUNT: usize = 2;

        s.begin_list(ACCESS_FIELD_COUNT);
        s.append(&self.address.as_ref());
        s.begin_list(self.storage_keys.len());
        for storage_key in self.storage_keys.iter() {
            s.append(&storage_key.0.as_ref());
        }
    }
}

/// <https://eips.ethereum.org/EIPS/eip-1559>
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Eip1559TransactionRequest {
    #[n(0)]
    pub chain_id: u64,
    #[n(1)]
    pub nonce: TransactionNonce,
    #[n(2)]
    pub max_priority_fee_per_gas: Wei,
    #[n(3)]
    pub max_fee_per_gas: Wei,
    #[cbor(n(4), with = "crate::cbor::u256")]
    pub gas_limit: Quantity,
    #[n(5)]
    pub destination: Address,
    #[n(6)]
    pub amount: Wei,
    #[cbor(n(7), with = "minicbor::bytes")]
    pub data: Vec<u8>,
    #[n(8)]
    pub access_list: AccessList,
}

impl rlp::Encodable for Eip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
    }
}

#[derive(Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct Eip1559Signature {
    #[n(0)]
    pub signature_y_parity: bool,
    #[cbor(n(1), with = "crate::cbor::u256")]
    pub r: u256,
    #[cbor(n(2), with = "crate::cbor::u256")]
    pub s: u256,
}

impl rlp::Encodable for Eip1559Signature {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.signature_y_parity);
        encode_u256(s, self.r);
        encode_u256(s, self.s);
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SignedEip1559TransactionRequest {
    #[n(0)]
    transaction: Eip1559TransactionRequest,
    #[n(1)]
    signature: Eip1559Signature,
    // TODO FI-984: transaction hash should be computed only once
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Encode, Decode)]
pub struct FinalizedEip1559Transaction {
    #[n(0)]
    transaction: SignedEip1559TransactionRequest,
    #[n(1)]
    receipt: TransactionReceipt,
}

impl FinalizedEip1559Transaction {
    pub fn destination(&self) -> &Address {
        &self.transaction.transaction().destination
    }

    pub fn block_number(&self) -> &BlockNumber {
        &self.receipt.block_number
    }

    pub fn transaction_amount(&self) -> &Wei {
        &self.transaction.transaction().amount
    }

    pub fn transaction_hash(&self) -> &Hash {
        &self.receipt.transaction_hash
    }

    pub fn effective_transaction_fee(&self) -> Wei {
        self.receipt
            .effective_gas_price
            .checked_mul(self.receipt.gas_used)
            .expect("ERROR: overflow during transaction fee calculation")
    }

    pub fn transaction_status(&self) -> &TransactionStatus {
        &self.receipt.status
    }
}

impl From<(Eip1559TransactionRequest, Eip1559Signature)> for SignedEip1559TransactionRequest {
    fn from((transaction, signature): (Eip1559TransactionRequest, Eip1559Signature)) -> Self {
        Self {
            transaction,
            signature,
        }
    }
}

impl rlp::Encodable for SignedEip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.transaction.rlp_inner(s);
        s.append(&self.signature);
        s.finalize_unbounded_list();
    }
}

impl SignedEip1559TransactionRequest {
    /// An EIP-1559 transaction is encoded as follows
    /// 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s]),
    /// where `||` denotes string concatenation.
    pub fn raw_bytes(&self) -> Vec<u8> {
        use rlp::Encodable;
        let mut rlp = self.rlp_bytes().to_vec();
        rlp.insert(0, self.transaction.transaction_type());
        rlp
    }

    pub fn raw_transaction_hex(&self) -> String {
        format!("0x{}", hex::encode(self.raw_bytes()))
    }

    /// If included in a block, this hash value is used as reference to this transaction.
    pub fn hash(&self) -> Hash {
        Hash(ic_crypto_sha3::Keccak256::hash(self.raw_bytes()))
    }

    pub fn transaction(&self) -> &Eip1559TransactionRequest {
        &self.transaction
    }

    pub fn nonce(&self) -> TransactionNonce {
        self.transaction.nonce
    }

    pub fn try_finalize(
        self,
        receipt: TransactionReceipt,
    ) -> Result<FinalizedEip1559Transaction, String> {
        if self.hash() != receipt.transaction_hash {
            return Err(format!(
                "transaction hash mismatch: expected {}, got {}",
                self.hash(),
                receipt.transaction_hash
            ));
        }
        if self.transaction.max_fee_per_gas < receipt.effective_gas_price {
            return Err(format!(
                "transaction max_fee_per_gas {} is smaller than effective_gas_price {}",
                self.transaction.max_fee_per_gas, receipt.effective_gas_price
            ));
        }
        if self.transaction.gas_limit < receipt.gas_used {
            return Err(format!(
                "transaction gas limit {} is smaller than gas used {}",
                self.transaction.gas_limit, receipt.gas_used
            ));
        }
        Ok(FinalizedEip1559Transaction {
            transaction: self,
            receipt,
        })
    }
}

pub fn encode_u256<T: Into<u256>>(stream: &mut RlpStream, value: T) {
    let value = value.into();
    let leading_empty_bytes: usize = value.leading_zeros() as usize / 8;
    stream.append(&value.to_be_bytes()[leading_empty_bytes..].as_ref());
}

impl Eip1559TransactionRequest {
    pub fn transaction_type(&self) -> u8 {
        EIP1559_TX_ID
    }

    pub fn rlp_inner(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id);
        rlp.append(&self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        encode_u256(rlp, self.gas_limit);
        rlp.append(&self.destination.as_ref());
        rlp.append(&self.amount);
        rlp.append(&self.data);
        rlp.append(&self.access_list);
    }

    /// Hash of EIP-1559 transaction is computed as
    /// keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list])),
    /// where `||` denotes string concatenation.
    pub fn hash(&self) -> Hash {
        use rlp::Encodable;
        let mut bytes = self.rlp_bytes().to_vec();
        bytes.insert(0, self.transaction_type());
        Hash(ic_crypto_sha3::Keccak256::hash(bytes))
    }

    pub fn transaction_price(&self) -> TransactionPrice {
        TransactionPrice {
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
        }
    }

    pub async fn sign(self) -> Result<SignedEip1559TransactionRequest, String> {
        let hash = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let signature = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(crate::MAIN_DERIVATION_PATH),
            hash.0,
        )
        .await
        .map_err(|e| format!("failed to sign tx: {}", e))?;
        let recid = compute_recovery_id(&hash, &signature).await;
        if recid.is_x_reduced() {
            return Err("BUG: affine x-coordinate of r is reduced which is so unlikely to happen that it's probably a bug".to_string());
        }
        let (r_bytes, s_bytes) = split_in_two(signature);
        let r = u256::from_be_bytes(r_bytes);
        let s = u256::from_be_bytes(s_bytes);
        let sig = Eip1559Signature {
            signature_y_parity: recid.is_y_odd(),
            r,
            s,
        };

        Ok(SignedEip1559TransactionRequest {
            transaction: self,
            signature: sig,
        })
    }
}

async fn compute_recovery_id(digest: &Hash, signature: &[u8]) -> RecoveryId {
    let ecdsa_public_key = lazy_call_ecdsa_public_key().await;
    debug_assert!(
        ecdsa_public_key.verify_signature_prehashed(&digest.0, signature),
        "failed to verify signature prehashed, digest: {:?}, signature: {:?}, public_key: {:?}",
        hex::encode(digest.0),
        hex::encode(signature),
        hex::encode(ecdsa_public_key.serialize_sec1(true)),
    );
    ecdsa_public_key
        .try_recovery_from_digest(&digest.0, signature)
        .unwrap_or_else(|e| {
            panic!(
                "BUG: failed to recover public key {:?} from digest {:?} and signature {:?}: {:?}",
                hex::encode(ecdsa_public_key.serialize_sec1(true)),
                hex::encode(digest.0),
                hex::encode(signature),
                e
            )
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

    /// Increase current transaction price by at least 10%
    pub fn increase_by_10_percent(self) -> Self {
        let plus_10_percent = |amount: Wei| {
            amount
                .checked_add(
                    amount
                        .checked_div_ceil(10_u8)
                        .expect("BUG: must be Some() because divisor is non-zero"),
                )
                .unwrap_or(Wei::MAX)
        };
        Self {
            gas_limit: self.gas_limit,
            max_fee_per_gas: plus_10_percent(self.max_fee_per_gas),
            max_priority_fee_per_gas: plus_10_percent(self.max_priority_fee_per_gas),
        }
    }

    /// Returns true if the new transaction fee is higher than the current one
    pub fn is_fee_increased(&self, new: &Self) -> bool {
        self.max_fee_per_gas < new.max_fee_per_gas
            || self.max_priority_fee_per_gas < new.max_priority_fee_per_gas
    }

    pub fn max(self, other: Self) -> Self {
        use std::cmp::max;
        Self {
            gas_limit: max(self.gas_limit, other.gas_limit),
            max_fee_per_gas: max(self.max_fee_per_gas, other.max_fee_per_gas),
            max_priority_fee_per_gas: max(
                self.max_priority_fee_per_gas,
                other.max_priority_fee_per_gas,
            ),
        }
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
    let max_fee_per_gas = base_fee_of_next_finalized_block
        .checked_mul(2_u8)
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

fn split_in_two(array: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&array[..32]);
    s.copy_from_slice(&array[32..]);
    (r, s)
}
