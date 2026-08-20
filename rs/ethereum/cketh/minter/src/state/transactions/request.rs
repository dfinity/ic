//! What it takes for a request to travel a [`TransactionPipeline`], and the minter's own
//! implementation of it.

use super::{
    CreateTransactionError, EthWithdrawalRequest, SweepId, SweepRequest, TransactionCallData,
    WithdrawalRequest,
};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{GasAmount, LedgerBurnIndex, TransactionNonce, Wei};
use crate::tx::{
    Eip1559TransactionRequest, GasFeeEstimate, ResubmissionStrategy, SignableTransaction,
};
use std::convert::Infallible;
use std::fmt;

/// A request that can flow through a [`TransactionPipeline`]: it carries an identity used as the
/// pipeline's alternate map key, and knows the transaction it turns into.
///
/// Implemented by [`WithdrawalRequest`] — the minter's **main address** pipeline
/// (`Id = LedgerBurnIndex`) — and by [`SweepRequest`] — the dedicated **sweeper address** pipeline
/// (`Id = SweepId`), which burns no ckETH and is therefore never reimbursed.
pub trait PipelineRequest {
    /// The pipeline's alternate map key: a ckETH `LedgerBurnIndex` for withdrawals, a `SweepId`
    /// for sweeps.
    type Id: Copy + Ord + fmt::Debug;

    /// The transaction this request turns into.
    type Transaction: SignableTransaction;

    /// Why [`Self::create_transaction`] could not build a transaction. A request that always funds
    /// its own fee can set this to [`std::convert::Infallible`], making the failure unrepresentable
    /// rather than merely unreachable.
    type Error;

    /// The identity of this request, used as the pipeline's alternate map key.
    fn id(&self) -> Self::Id;

    /// IC time at which the request was created, if tracked.
    fn created_at(&self) -> Option<u64>;

    /// The fee-bump strategy for this request's resubmitted transactions.
    fn resubmission_strategy(&self) -> ResubmissionStrategy;

    /// Assert that a freshly created transaction is consistent with the request: it goes to the
    /// right address, and moves the right amount.
    fn assert_created_transaction(&self, transaction: &Self::Transaction);

    /// Creates the transaction that fulfils this request.
    ///
    /// # Errors
    /// * [`Self::Error`] if the request cannot cover the transaction fee.
    fn create_transaction(
        &self,
        nonce: TransactionNonce,
        gas_fee_estimate: GasFeeEstimate,
        gas_limit: GasAmount,
        ethereum_network: EthereumNetwork,
    ) -> Result<Self::Transaction, Self::Error>;
}

impl PipelineRequest for WithdrawalRequest {
    type Id = LedgerBurnIndex;
    type Transaction = Eip1559TransactionRequest;
    type Error = CreateTransactionError;

    fn id(&self) -> LedgerBurnIndex {
        self.cketh_ledger_burn_index()
    }

    fn created_at(&self) -> Option<u64> {
        WithdrawalRequest::created_at(self)
    }

    fn resubmission_strategy(&self) -> ResubmissionStrategy {
        match self {
            WithdrawalRequest::CkEth(cketh) | WithdrawalRequest::SweeperFunding(cketh) => {
                ResubmissionStrategy::ReduceEthAmount {
                    withdrawal_amount: cketh.withdrawal_amount,
                }
            }
            WithdrawalRequest::CkErc20(ckerc20) => ResubmissionStrategy::GuaranteeEthAmount {
                allowed_max_transaction_fee: ckerc20.max_transaction_fee,
            },
        }
    }

    fn assert_created_transaction(&self, transaction: &Eip1559TransactionRequest) {
        assert_eq!(
            self.destination(),
            transaction.destination,
            "BUG: request and transaction destination mismatch"
        );
        match self {
            WithdrawalRequest::CkEth(req) | WithdrawalRequest::SweeperFunding(req) => {
                assert!(
                    req.withdrawal_amount > transaction.amount,
                    "BUG: transaction amount should be the withdrawal amount deducted from transaction fees"
                );
            }
            WithdrawalRequest::CkErc20(_req) => {
                assert_eq!(
                    Wei::ZERO,
                    transaction.amount,
                    "BUG: ERC-20 transaction amount should be zero"
                );
            }
        }
    }

    /// The transaction fees are paid by the beneficiary, meaning that the fees will be deducted
    /// from the withdrawal amount.
    fn create_transaction(
        &self,
        nonce: TransactionNonce,
        gas_fee_estimate: GasFeeEstimate,
        gas_limit: GasAmount,
        ethereum_network: EthereumNetwork,
    ) -> Result<Eip1559TransactionRequest, CreateTransactionError> {
        assert!(
            gas_limit > GasAmount::ZERO,
            "BUG: gas limit should be non-zero"
        );
        match self {
            WithdrawalRequest::CkEth(EthWithdrawalRequest {
                withdrawal_amount,
                destination,
                ledger_burn_index,
                ..
            })
            | WithdrawalRequest::SweeperFunding(EthWithdrawalRequest {
                withdrawal_amount,
                destination,
                ledger_burn_index,
                ..
            }) => {
                let transaction_price = gas_fee_estimate.to_price(gas_limit);
                let max_transaction_fee = transaction_price.max_transaction_fee();
                let tx_amount = match withdrawal_amount.checked_sub(max_transaction_fee) {
                    Some(tx_amount) => tx_amount,
                    None => {
                        return Err(CreateTransactionError::InsufficientTransactionFee {
                            cketh_ledger_burn_index: *ledger_burn_index,
                            allowed_max_transaction_fee: *withdrawal_amount,
                            actual_max_transaction_fee: max_transaction_fee,
                        });
                    }
                };
                Ok(Eip1559TransactionRequest {
                    chain_id: ethereum_network.chain_id(),
                    nonce,
                    max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                    max_fee_per_gas: transaction_price.max_fee_per_gas,
                    gas_limit: transaction_price.gas_limit,
                    destination: *destination,
                    amount: tx_amount,
                    data: Vec::new(),
                    access_list: Default::default(),
                })
            }
            WithdrawalRequest::CkErc20(request) => {
                // The transaction fee is already paid and must be at most
                // the `max_transaction_fee` in the withdrawal request, which, given a gas limit, gives us an upper bound on
                // the `max_fee_per_gas`. We allocate the maximum from the beginning to minimize
                // transaction resubmissions: even if the `base_fee_per_gas` increases considerably,
                // the transaction could still make it as long as `transaction.max_fee_per_gas >=  block.base_fee_per_gas`,
                // since the `priority_fee_per_gas` received by the miner is capped to (see https://eips.ethereum.org/EIPS/eip-1559)
                // min(transaction.max_priority_fee_per_gas, transaction.max_fee_per_gas - block.base_fee_per_gas).
                let request_max_fee_per_gas = request
                    .max_transaction_fee
                    .into_wei_per_gas(gas_limit)
                    .expect("BUG: gas_limit should be non-zero");
                let actual_min_max_fee_per_gas = gas_fee_estimate.min_max_fee_per_gas();
                if actual_min_max_fee_per_gas > request_max_fee_per_gas {
                    return Err(CreateTransactionError::InsufficientTransactionFee {
                        cketh_ledger_burn_index: request.cketh_ledger_burn_index,
                        allowed_max_transaction_fee: request.max_transaction_fee,
                        actual_max_transaction_fee: actual_min_max_fee_per_gas
                            .transaction_cost(gas_limit)
                            .unwrap_or(Wei::MAX),
                    });
                }
                Ok(Eip1559TransactionRequest {
                    chain_id: ethereum_network.chain_id(),
                    nonce,
                    max_priority_fee_per_gas: gas_fee_estimate.max_priority_fee_per_gas,
                    max_fee_per_gas: request_max_fee_per_gas,
                    gas_limit,
                    destination: request.erc20_contract_address,
                    amount: Wei::ZERO,
                    data: TransactionCallData::Erc20Transfer {
                        to: request.destination,
                        value: request.withdrawal_amount,
                    }
                    .encode(),
                    access_list: Default::default(),
                })
            }
        }
    }
}

impl PipelineRequest for SweepRequest {
    type Id = SweepId;
    type Transaction = Eip1559TransactionRequest;
    /// A sweep pays its gas from the sweeper's own prepaid balance rather than out of the amount
    /// moved, so there is no fee for it to fail to cover.
    type Error = Infallible;

    fn id(&self) -> SweepId {
        self.id
    }

    fn created_at(&self) -> Option<u64> {
        Some(self.created_at)
    }

    fn resubmission_strategy(&self) -> ResubmissionStrategy {
        ResubmissionStrategy::GuaranteeEthAmount {
            allowed_max_transaction_fee: self.max_transaction_fee,
        }
    }

    fn assert_created_transaction(&self, transaction: &Eip1559TransactionRequest) {
        assert_eq!(
            self.destination, transaction.destination,
            "BUG: request and transaction destination mismatch"
        );
        assert_eq!(
            transaction.amount, self.amount,
            "BUG: sweep transaction amount should equal the request amount"
        );
        assert_eq!(
            transaction.data, self.data,
            "BUG: sweep transaction should carry the request's call data"
        );
    }

    fn create_transaction(
        &self,
        nonce: TransactionNonce,
        gas_fee_estimate: GasFeeEstimate,
        gas_limit: GasAmount,
        ethereum_network: EthereumNetwork,
    ) -> Result<Eip1559TransactionRequest, Infallible> {
        assert!(
            gas_limit > GasAmount::ZERO,
            "BUG: gas limit should be non-zero"
        );
        let transaction_price = gas_fee_estimate.to_price(gas_limit);
        Ok(Eip1559TransactionRequest {
            chain_id: ethereum_network.chain_id(),
            nonce,
            max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
            max_fee_per_gas: transaction_price.max_fee_per_gas,
            gas_limit: transaction_price.gas_limit,
            destination: self.destination,
            amount: self.amount,
            data: self.data.clone(),
            access_list: Default::default(),
        })
    }
}
