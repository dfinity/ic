use super::{
    AccessList, GasFeeEstimate, ResubmissionStrategy, ResubmitTransactionError, Resubmittable,
    TransactionPrice, compute_recovery_id, encode_u256, split_in_two,
};
use crate::{
    eth_rpc::Hash,
    eth_rpc_client::responses::{TransactionReceipt, TransactionStatus},
    numeric::{BlockNumber, GasAmount, TransactionNonce, Wei, WeiPerGas},
    state::read_state,
};
use ethnum::u256;
use ic_ethereum_types::Address;
use ic_management_canister_types_private::DerivationPath;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

const EIP1559_TX_ID: u8 = 2;

pub type TransactionRequest = Resubmittable<Eip1559TransactionRequest>;
pub type SignedTransactionRequest = Resubmittable<SignedEip1559TransactionRequest>;

/// <https://eips.ethereum.org/EIPS/eip-1559>
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct Eip1559TransactionRequest {
    #[n(0)]
    pub chain_id: u64,
    #[n(1)]
    pub nonce: TransactionNonce,
    #[n(2)]
    pub max_priority_fee_per_gas: WeiPerGas,
    #[n(3)]
    pub max_fee_per_gas: WeiPerGas,
    #[n(4)]
    pub gas_limit: GasAmount,
    #[n(5)]
    pub destination: Address,
    #[n(6)]
    pub amount: Wei,
    #[cbor(n(7), with = "minicbor::bytes")]
    pub data: Vec<u8>,
    #[n(8)]
    pub access_list: AccessList,
}

impl AsRef<Eip1559TransactionRequest> for Eip1559TransactionRequest {
    fn as_ref(&self) -> &Eip1559TransactionRequest {
        self
    }
}

impl SignedTransactionRequest {
    pub fn resubmit(
        &self,
        new_gas_fee: GasFeeEstimate,
    ) -> Result<Option<Eip1559TransactionRequest>, ResubmitTransactionError> {
        let transaction_request = self.transaction.transaction();
        let last_tx_price = transaction_request.transaction_price();
        let new_tx_price = last_tx_price
            .clone()
            .resubmit_transaction_price(new_gas_fee);
        if new_tx_price == last_tx_price {
            return Ok(None);
        }

        if new_tx_price.max_transaction_fee() > self.resubmission.allowed_max_transaction_fee() {
            return Err(ResubmitTransactionError::InsufficientTransactionFee {
                allowed_max_transaction_fee: self.resubmission.allowed_max_transaction_fee(),
                actual_max_transaction_fee: new_tx_price.max_transaction_fee(),
            });
        }
        let new_amount = match self.resubmission {
            ResubmissionStrategy::ReduceEthAmount { withdrawal_amount } => {
                withdrawal_amount.checked_sub(new_tx_price.max_transaction_fee())
                    .expect("BUG: withdrawal_amount covers new transaction fee because it was checked before")
            }
            ResubmissionStrategy::GuaranteeEthAmount { .. } => transaction_request.amount,
        };
        Ok(Some(Eip1559TransactionRequest {
            max_priority_fee_per_gas: new_tx_price.max_priority_fee_per_gas,
            max_fee_per_gas: new_tx_price.max_fee_per_gas,
            gas_limit: new_tx_price.gas_limit,
            amount: new_amount,
            ..transaction_request.clone()
        }))
    }
}

impl rlp::Encodable for Eip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.rlp_inner(s);
        s.finalize_unbounded_list();
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Decode, Encode)]
pub struct Eip1559Signature {
    #[n(0)]
    pub signature_y_parity: bool,
    #[cbor(n(1), with = "icrc_cbor::u256")]
    pub r: u256,
    #[cbor(n(2), with = "icrc_cbor::u256")]
    pub s: u256,
}

impl rlp::Encodable for Eip1559Signature {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.signature_y_parity);
        encode_u256(s, self.r);
        encode_u256(s, self.s);
    }
}

/// Immutable signed EIP-1559 transaction.
/// Use `Eip1559TransactionRequest::sign()` to create a newly signed transaction or
/// `SignedEip1559TransactionRequest::from()` if the signature is already known
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignedEip1559TransactionRequest {
    inner: InnerSignedTransactionRequest,
    /// Hash of the signed transaction. Since computation of the hash is an expensive operation,
    /// which involves RLP encoding and Keccak256, the value is computed once upon instantiation
    /// and memoized. It is safe to memoize the hash because the transaction is immutable.
    /// Note: Serialization should ignore this field and deserialization should call
    /// the constructor to create the correct value.
    memoized_hash: Hash,
}

impl AsRef<Eip1559TransactionRequest> for SignedEip1559TransactionRequest {
    fn as_ref(&self) -> &Eip1559TransactionRequest {
        &self.inner.transaction
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
struct InnerSignedTransactionRequest {
    #[n(0)]
    transaction: Eip1559TransactionRequest,
    #[n(1)]
    signature: Eip1559Signature,
}

impl rlp::Encodable for InnerSignedTransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        self.transaction.rlp_inner(s);
        s.append(&self.signature);
        //ignore memoized_hash
        s.finalize_unbounded_list();
    }
}

impl InnerSignedTransactionRequest {
    /// An EIP-1559 transaction is encoded as follows
    /// 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s]),
    /// where `||` denotes string concatenation.
    pub fn raw_bytes(&self) -> Vec<u8> {
        use rlp::Encodable;
        let mut rlp = self.rlp_bytes().to_vec();
        rlp.insert(0, self.transaction.transaction_type());
        rlp
    }
}

impl<C> minicbor::Encode<C> for SignedEip1559TransactionRequest {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.encode_with(&self.inner, ctx)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for SignedEip1559TransactionRequest {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.decode_with(ctx)
            .map(|inner: InnerSignedTransactionRequest| {
                Self::new(inner.transaction, inner.signature)
            })
    }
}

/// Immutable finalized transaction.
/// Use `SignedEip1559TransactionRequest::try_finalize()` to create a finalized transaction.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct FinalizedEip1559Transaction {
    #[n(0)]
    transaction: SignedEip1559TransactionRequest,
    #[n(1)]
    receipt: TransactionReceipt,
}

impl AsRef<Eip1559TransactionRequest> for FinalizedEip1559Transaction {
    fn as_ref(&self) -> &Eip1559TransactionRequest {
        self.transaction.as_ref()
    }
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

    pub fn transaction_data(&self) -> &[u8] {
        &self.transaction.transaction().data
    }

    pub fn transaction(&self) -> &Eip1559TransactionRequest {
        self.transaction.transaction()
    }

    pub fn transaction_price(&self) -> TransactionPrice {
        self.transaction.transaction().transaction_price()
    }

    pub fn effective_transaction_fee(&self) -> Wei {
        self.receipt.effective_transaction_fee()
    }

    pub fn transaction_status(&self) -> &TransactionStatus {
        &self.receipt.status
    }
}

impl From<(Eip1559TransactionRequest, Eip1559Signature)> for SignedEip1559TransactionRequest {
    fn from((transaction, signature): (Eip1559TransactionRequest, Eip1559Signature)) -> Self {
        Self::new(transaction, signature)
    }
}

impl rlp::Encodable for SignedEip1559TransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.inner);
    }
}

impl SignedEip1559TransactionRequest {
    pub fn new(transaction: Eip1559TransactionRequest, signature: Eip1559Signature) -> Self {
        let inner = InnerSignedTransactionRequest {
            transaction,
            signature,
        };
        let hash = Hash(ic_sha3::Keccak256::hash(inner.raw_bytes()));
        Self {
            inner,
            memoized_hash: hash,
        }
    }

    pub fn raw_transaction_hex(&self) -> Vec<u8> {
        self.inner.raw_bytes()
    }

    pub fn raw_transaction_hex_string(&self) -> String {
        format!("0x{}", hex::encode(self.raw_transaction_hex()))
    }

    /// If included in a block, this hash value is used as reference to this transaction.
    pub fn hash(&self) -> Hash {
        self.memoized_hash
    }

    pub fn transaction(&self) -> &Eip1559TransactionRequest {
        &self.inner.transaction
    }

    pub fn nonce(&self) -> TransactionNonce {
        self.transaction().nonce
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
        if self.transaction().max_fee_per_gas < receipt.effective_gas_price {
            return Err(format!(
                "transaction max_fee_per_gas {} is smaller than effective_gas_price {}",
                self.transaction().max_fee_per_gas,
                receipt.effective_gas_price
            ));
        }
        if self.transaction().gas_limit < receipt.gas_used {
            return Err(format!(
                "transaction gas limit {} is smaller than gas used {}",
                self.transaction().gas_limit,
                receipt.gas_used
            ));
        }
        Ok(FinalizedEip1559Transaction {
            transaction: self,
            receipt,
        })
    }
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
        rlp.append(&self.gas_limit);
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
        Hash(ic_sha3::Keccak256::hash(bytes))
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
        .map_err(|e| format!("failed to sign tx: {e}"))?;
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

        Ok(SignedEip1559TransactionRequest::new(self, sig))
    }
}
