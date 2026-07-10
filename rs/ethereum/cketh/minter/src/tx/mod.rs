#[cfg(test)]
mod tests;

mod eip_1559;
mod eip_7702;
mod signed;

pub use eip_1559::{
    Eip1559TransactionRequest, FinalizedEip1559Transaction, SignedEip1559TransactionRequest,
    SignedTransactionRequest, TransactionRequest,
};
pub use eip_7702::{
    Authorization, Eip7702TransactionRequest, SignedAuthorization, SignedEip7702TransactionRequest,
};
pub use signed::{SignableTransaction, Signed, TransactionSignature, sign};

use crate::{
    eth_rpc::Hash,
    eth_rpc_client::{
        MIN_ATTACHED_CYCLES, MultiCallError, StrictMajorityByKey, ToReducedWithStrategy, rpc_client,
    },
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{GasAmount, Wei, WeiPerGas},
    state::{TaskType, lazy_call_ecdsa_public_key, mutate_state, read_state},
};
use candid::Nat;
use ethnum::u256;
use evm_rpc_types::{BlockTag, FeeHistory};
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_secp256k1::RecoveryId;
use minicbor::{Decode, Encode};
use rlp::RlpStream;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Decode, Encode)]
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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Decode, Encode)]
#[cbor(transparent)]
pub struct StorageKey(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Decode, Encode)]
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

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Resubmittable<T> {
    pub transaction: T,
    pub resubmission: ResubmissionStrategy,
}

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

#[derive(Clone, Eq, PartialEq, Debug)]
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

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ResubmitTransactionError {
    InsufficientTransactionFee {
        allowed_max_transaction_fee: Wei,
        actual_max_transaction_fee: Wei,
    },
}

pub fn encode_u256<T: Into<u256>>(stream: &mut RlpStream, value: T) {
    let value = value.into();
    let leading_empty_bytes: usize = value.leading_zeros() as usize / 8;
    stream.append(&value.to_be_bytes()[leading_empty_bytes..].as_ref());
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

#[derive(Clone, Eq, PartialEq, Debug)]
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

#[derive(Clone, Eq, PartialEq, Debug)]
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
        read_state(rpc_client)
            .fee_history((5_u8, BlockTag::Latest))
            .with_reward_percentiles(vec![20])
            .with_cycles(MIN_ATTACHED_CYCLES)
            .try_send()
            .await
            .reduce_with_strategy(StrictMajorityByKey::new(|fee_history: &FeeHistory| {
                Nat::from(fee_history.oldest_block.clone())
            }))
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
#[derive(Eq, PartialEq, Debug)]
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
    let base_fee_per_gas_next_block = fee_history
        .base_fee_per_gas
        .last()
        .ok_or(TransactionFeeEstimationError::InvalidFeeHistory(
            "base_fee_per_gas should not be empty to be able to evaluate transaction price"
                .to_string(),
        ))?
        .clone();
    let max_priority_fee_per_gas = {
        let mut rewards: Vec<WeiPerGas> = fee_history
            .reward
            .iter()
            .flatten()
            .map(|nat| WeiPerGas::from(nat.clone()))
            .collect();
        let historic_max_priority_fee_per_gas =
            *median(&mut rewards).ok_or(TransactionFeeEstimationError::InvalidFeeHistory(
                "should be non-empty with rewards of the last 5 blocks".to_string(),
            ))?;
        historic_max_priority_fee_per_gas.max(MIN_MAX_PRIORITY_FEE_PER_GAS)
    };
    let gas_fee_estimate = GasFeeEstimate {
        base_fee_per_gas: base_fee_per_gas_next_block.into(),
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
    let mut r = [0_u8; 32];
    let mut s = [0_u8; 32];
    r.copy_from_slice(&array[..32]);
    s.copy_from_slice(&array[32..]);
    (r, s)
}
