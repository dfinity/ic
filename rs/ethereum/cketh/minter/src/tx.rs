#[cfg(test)]
mod tests;

use crate::eth_rpc::{BlockSpec, BlockTag, FeeHistory, FeeHistoryParams, Hash, Quantity};
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::eth_rpc_client::{EthRpcClient, MultiCallError};
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, GasAmount, TransactionNonce, Wei, WeiPerGas};
use crate::state::{lazy_call_ecdsa_public_key, mutate_state, read_state, TaskType};
use ethnum::u256;
use ic_canister_log::log;
use ic_crypto_secp256k1::RecoveryId;
use ic_ethereum_types::Address;
use ic_management_canister_types::DerivationPath;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

const EIP1559_TX_ID: u8 = 2;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Encode, Decode)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Encode, Decode)]
#[cbor(transparent)]
pub struct StorageKey(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Encode, Decode)]
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
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resubmittable<T> {
    pub transaction: T,
    pub resubmission: ResubmissionStrategy,
}

pub type TransactionRequest = Resubmittable<Eip1559TransactionRequest>;
pub type SignedTransactionRequest = Resubmittable<SignedEip1559TransactionRequest>;

impl<T> Resubmittable<T> {
    pub fn clone_resubmission_strategy<V>(&self, other: V) -> Resubmittable<V> {
        Resubmittable {
            transaction: other,
            resubmission: self.resubmission.clone(),
        }
    }
}

impl<T> AsRef<T> for Resubmittable<T> {
    fn as_ref(&self) -> &T {
        &self.transaction
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResubmissionStrategy {
    ReduceEthAmount { withdrawal_amount: Wei },
    GuaranteeEthAmount { allowed_max_transaction_fee: Wei },
}

impl ResubmissionStrategy {
    pub fn allowed_max_transaction_fee(&self) -> Wei {
        match self {
            ResubmissionStrategy::ReduceEthAmount { withdrawal_amount } => *withdrawal_amount,
            ResubmissionStrategy::GuaranteeEthAmount {
                allowed_max_transaction_fee,
            } => *allowed_max_transaction_fee,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResubmitTransactionError {
    InsufficientTransactionFee {
        allowed_max_transaction_fee: Wei,
        actual_max_transaction_fee: Wei,
    },
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

#[derive(Default, Clone, PartialEq, Eq, Hash, Debug, Encode, Decode)]
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

/// Immutable signed EIP-1559 transaction.
/// Use `Eip1559TransactionRequest::sign()` to create a newly signed transaction or
/// `SignedEip1559TransactionRequest::from()` if the signature is already known
#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
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
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
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
        let hash = Hash(ic_crypto_sha3::Keccak256::hash(inner.raw_bytes()));
        Self {
            inner,
            memoized_hash: hash,
        }
    }

    pub fn raw_transaction_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.raw_bytes()))
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

        Ok(SignedEip1559TransactionRequest::new(self, sig))
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
pub struct GasFeeEstimate {
    pub base_fee_per_gas: WeiPerGas,
    pub max_priority_fee_per_gas: WeiPerGas,
}

impl GasFeeEstimate {
    pub fn checked_estimate_max_fee_per_gas(&self) -> Option<WeiPerGas> {
        self.base_fee_per_gas
            .checked_mul(2_u8)
            .and_then(|base_fee_estimate| {
                base_fee_estimate.checked_add(self.max_priority_fee_per_gas)
            })
    }

    pub fn estimate_max_fee_per_gas(&self) -> WeiPerGas {
        self.checked_estimate_max_fee_per_gas()
            .unwrap_or(WeiPerGas::MAX)
    }

    pub fn to_price(self, gas_limit: GasAmount) -> TransactionPrice {
        TransactionPrice {
            gas_limit,
            max_fee_per_gas: self.estimate_max_fee_per_gas(),
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
        }
    }

    pub fn min_max_fee_per_gas(&self) -> WeiPerGas {
        self.base_fee_per_gas
            .checked_add(self.max_priority_fee_per_gas)
            .unwrap_or(WeiPerGas::MAX)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPrice {
    pub gas_limit: GasAmount,
    pub max_fee_per_gas: WeiPerGas,
    pub max_priority_fee_per_gas: WeiPerGas,
}

impl TransactionPrice {
    pub fn max_transaction_fee(&self) -> Wei {
        self.max_fee_per_gas
            .transaction_cost(self.gas_limit)
            .unwrap_or(Wei::MAX)
    }

    /// Estimate the transaction price to resubmit a transaction with the new gas fee.
    ///
    /// If the current transaction price is still actual, then the return price will be the same.
    /// Otherwise, the new `max_priority_fee_per_gas` will be at least 10% higher than the current one to ensure that
    /// the transaction can be resubmitted (See [Retrying an EIP 1559 transaction](https://docs.alchemy.com/docs/retrying-an-eip-1559-transaction)).
    /// The current `max_fee_per_gas` will be kept as long as it is enough to cover the new `max_priority_fee_per_gas + base_fee_per_gas_next_block`.
    pub fn resubmit_transaction_price(self, new_gas_fee: GasFeeEstimate) -> Self {
        let plus_10_percent = |amount: WeiPerGas| {
            amount
                .checked_add(
                    amount
                        .checked_div_ceil(10_u8)
                        .expect("BUG: must be Some() because divisor is non-zero"),
                )
                .unwrap_or(WeiPerGas::MAX)
        };

        if self.max_fee_per_gas >= new_gas_fee.min_max_fee_per_gas()
            && self.max_priority_fee_per_gas >= new_gas_fee.max_priority_fee_per_gas
        {
            self
        } else {
            // At this point the transaction price needs to be updated
            // which involves a minimum increase of 10% in the max_priority_fee_per_gas.
            // We also need to ensure that the new max_fee_per_gas covers the new max_priority_fee_per_gas,
            // but it would be counter-productive to increase it further than the minimum required.
            // The reason is that any increase in the max_fee_per_gas may render the corresponding transaction
            // not resubmittable due to the user not having enough funds to cover the new transaction price,
            // which could potentially block the minter further. In other words, having a stuck transaction with a higher
            // max_priority_fee_per_gas, is better than having a stuck transaction with a lower max_priority_fee_per_gas,
            // since the first one will go through sooner than the second one when the transaction prices decrease.
            // In case of steep increasing transaction fees, several resubmissions each involving costly operations
            // (various HTTPs outcalls, tECDSA signatures, etc.) might be required, which potentially could be avoided,
            // if one were to increase the max_fee_per_gas more than the minimum required. However,
            // this seems less important than getting the minter unstuck as soon as possible.
            let updated_max_priority_fee_per_gas = plus_10_percent(self.max_priority_fee_per_gas)
                .max(new_gas_fee.max_priority_fee_per_gas);
            let new_gas_fee = GasFeeEstimate {
                max_priority_fee_per_gas: updated_max_priority_fee_per_gas,
                ..new_gas_fee
            };
            let new_max_fee_per_gas = new_gas_fee.min_max_fee_per_gas().max(self.max_fee_per_gas);
            TransactionPrice {
                gas_limit: self.gas_limit,
                max_fee_per_gas: new_max_fee_per_gas,
                max_priority_fee_per_gas: updated_max_priority_fee_per_gas,
            }
        }
    }
}

pub async fn lazy_refresh_gas_fee_estimate() -> Option<GasFeeEstimate> {
    const MAX_AGE_NS: u64 = 60_000_000_000_u64; //60 seconds

    async fn do_refresh() -> Option<GasFeeEstimate> {
        let _guard = match TimerGuard::new(TaskType::RefreshGasFeeEstimate) {
            Ok(guard) => guard,
            Err(e) => {
                log!(
                    DEBUG,
                    "[refresh_gas_fee_estimate]: Failed retrieving guard: {e:?}",
                );
                return None;
            }
        };

        let fee_history = match eth_fee_history().await {
            Ok(fee_history) => fee_history,
            Err(e) => {
                log!(
                    INFO,
                    "[refresh_gas_fee_estimate]: Failed retrieving fee history: {e:?}",
                );
                return None;
            }
        };

        let gas_fee_estimate = match estimate_transaction_fee(&fee_history) {
            Ok(estimate) => {
                mutate_state(|s| {
                    s.last_transaction_price_estimate =
                        Some((ic_cdk::api::time(), estimate.clone()));
                });
                estimate
            }
            Err(e) => {
                log!(
                    INFO,
                    "[refresh_gas_fee_estimate]: Failed estimating gas fee: {e:?}",
                );
                return None;
            }
        };
        log!(
            INFO,
            "[refresh_gas_fee_estimate]: Estimated transaction fee: {:?}",
            gas_fee_estimate,
        );
        Some(gas_fee_estimate)
    }

    async fn eth_fee_history() -> Result<FeeHistory, MultiCallError<FeeHistory>> {
        read_state(EthRpcClient::from_state)
            .eth_fee_history(FeeHistoryParams {
                block_count: Quantity::from(5_u8),
                highest_block: BlockSpec::Tag(BlockTag::Latest),
                reward_percentiles: vec![20],
            })
            .await
    }

    let now_ns = ic_cdk::api::time();
    match read_state(|s| s.last_transaction_price_estimate.clone()) {
        Some((last_estimate_timestamp_ns, estimate))
            if now_ns < last_estimate_timestamp_ns.saturating_add(MAX_AGE_NS) =>
        {
            Some(estimate)
        }
        _ => do_refresh().await,
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum TransactionFeeEstimationError {
    InvalidFeeHistory(String),
    Overflow(String),
}

/// Estimate the transaction fee based on the fee history.
///
/// From the fee history, the current base fee per gas and the max priority fee per gas are determined.
/// Then, the max fee per gas is computed as `2 * base_fee_per_gas + max_priority_fee_per_gas` to ensure that
/// the estimate remains valid for the next few blocks, see `<https://www.blocknative.com/blog/eip-1559-fees>`.
pub fn estimate_transaction_fee(
    fee_history: &FeeHistory,
) -> Result<GasFeeEstimate, TransactionFeeEstimationError> {
    // average value between the `minSuggestedMaxPriorityFeePerGas`
    // used by Metamask, see
    // https://github.com/MetaMask/core/blob/f5a4f52e17f407c6411e4ef9bd6685aab184b91d/packages/gas-fee-controller/src/fetchGasEstimatesViaEthFeeHistory/calculateGasFeeEstimatesForPriorityLevels.ts#L14
    const MIN_MAX_PRIORITY_FEE_PER_GAS: WeiPerGas = WeiPerGas::new(1_500_000_000); //1.5 gwei
    let base_fee_per_gas_next_block = *fee_history.base_fee_per_gas.last().ok_or(
        TransactionFeeEstimationError::InvalidFeeHistory(
            "base_fee_per_gas should not be empty to be able to evaluate transaction price"
                .to_string(),
        ),
    )?;
    let max_priority_fee_per_gas = {
        let mut rewards: Vec<&WeiPerGas> = fee_history.reward.iter().flatten().collect();
        let historic_max_priority_fee_per_gas =
            **median(&mut rewards).ok_or(TransactionFeeEstimationError::InvalidFeeHistory(
                "should be non-empty with rewards of the last 5 blocks".to_string(),
            ))?;
        historic_max_priority_fee_per_gas.max(MIN_MAX_PRIORITY_FEE_PER_GAS)
    };
    let gas_fee_estimate = GasFeeEstimate {
        base_fee_per_gas: base_fee_per_gas_next_block,
        max_priority_fee_per_gas,
    };
    if gas_fee_estimate
        .checked_estimate_max_fee_per_gas()
        .is_none()
    {
        return Err(TransactionFeeEstimationError::Overflow(
            "max_fee_per_gas overflowed".to_string(),
        ));
    }
    Ok(gas_fee_estimate)
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
