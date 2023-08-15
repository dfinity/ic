use crate::address::Address;
use crate::eth_rpc::{FeeHistory, Hash, Quantity};
use crate::numeric::{TransactionNonce, Wei};
use crate::state::read_state;
use ethnum::u256;
use ic_ic00_types::DerivationPath;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};

const EIP1559_TX_ID: u8 = 2;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct AccessList(pub Vec<AccessListItem>);

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

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct AccessListItem {
    /// Accessed address
    pub address: Address,
    /// Accessed storage keys
    pub storage_keys: Vec<[u8; 32]>,
}

impl rlp::Encodable for AccessListItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        const ACCESS_FIELD_COUNT: usize = 2;

        s.begin_list(ACCESS_FIELD_COUNT);
        s.append(&self.address.as_ref());
        s.begin_list(self.storage_keys.len());
        for storage_key in self.storage_keys.iter() {
            s.append(&storage_key.as_ref());
        }
    }
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
    pub access_list: AccessList,
}

impl rlp::Encodable for Eip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
    }
}

#[derive(Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct Signature {
    pub v: u64,
    pub r: u256,
    pub s: u256,
}

impl rlp::Encodable for Signature {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.v);
        encode_u256(s, self.r);
        encode_u256(s, self.s);
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct SignedEip1559TransactionRequest {
    transaction: Eip1559TransactionRequest,
    signature: Signature,
}

impl From<(Eip1559TransactionRequest, Signature)> for SignedEip1559TransactionRequest {
    fn from((transaction, signature): (Eip1559TransactionRequest, Signature)) -> Self {
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

    pub fn nonce(&self) -> TransactionNonce {
        self.transaction.nonce
    }
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
            access_list: AccessList::new(),
        }
    }

    pub fn transaction_type(&self) -> u8 {
        EIP1559_TX_ID
    }

    pub fn rlp_inner(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id);
        encode_u256(rlp, self.nonce);
        encode_u256(rlp, self.max_priority_fee_per_gas);
        encode_u256(rlp, self.max_fee_per_gas);
        encode_u256(rlp, self.gas_limit);
        rlp.append(&self.destination.as_ref());
        encode_u256(rlp, self.amount);
        rlp.append(&self.data);
        rlp.append(&self.access_list);
    }

    /// Hash of EIP-1559 transaction is computed as
    /// keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list])),
    /// where `||` denotes string concatenation.
    pub fn hash(&self) -> Hash {
        use rlp::Encodable;
        let mut rlp = self.rlp_bytes().to_vec();
        let mut bytes: Vec<u8> = Vec::with_capacity(rlp.len() + 1);
        bytes.push(self.transaction_type());
        bytes.append(&mut rlp);
        Hash(ic_crypto_sha3::Keccak256::hash(bytes))
    }

    pub async fn sign(self) -> Result<SignedEip1559TransactionRequest, String> {
        let hash = self.hash();
        let key_name = read_state(|s| s.ecdsa_key_name.clone());
        let (r_bytes, s_bytes) = crate::management::sign_with_ecdsa(
            key_name,
            DerivationPath::new(crate::MAIN_DERIVATION_PATH),
            hash.0,
        )
        .await
        .map_err(|e| format!("failed to sign tx: {}", e))?;
        let v = (s_bytes[31] % 2) as u64;
        let r = u256::from_be_bytes(r_bytes);
        let s = u256::from_be_bytes(s_bytes);
        let sig = Signature { v, r, s };

        Ok(SignedEip1559TransactionRequest {
            transaction: self,
            signature: sig,
        })
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
