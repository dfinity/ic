#[cfg(test)]
mod tests;

use crate::erc20::CkTokenSymbol;
use crate::eth_logs::ReceivedEvent;
use crate::eth_rpc::Hash;
use crate::numeric::{Erc20Value, LogIndex};
use crate::state::transactions::ReimbursementRequest;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::transfer::Memo;
use minicbor::{Decode, Encode, Encoder};

/// Encodes minter memo as a binary blob.
fn encode<T: minicbor::Encode<()>>(t: &T) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.encode(t).expect("minicbor encoding failed");
    encoder.into_writer()
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
pub enum MintMemo {
    #[n(0)]
    /// The minter received some ETH or ERC20 token.
    Convert {
        #[n(0)]
        /// The sender of the ETH or ERC20 token.
        from_address: Address,
        #[n(1)]
        /// Hash of the transaction.
        tx_hash: Hash,
        #[n(2)]
        log_index: LogIndex,
    },
    #[n(1)]
    ReimburseTransaction {
        #[n(0)]
        /// The id corresponding to the withdrawal request.
        withdrawal_id: u64,
        #[n(1)]
        /// Hash of the failed transaction.
        tx_hash: Hash,
    },
    /// The minter failed to process a withdrawal request,
    /// so no transaction was issued, but some reimbursement was made.
    #[n(2)]
    ReimburseWithdrawal {
        #[n(0)]
        /// The id corresponding to the withdrawal request.
        withdrawal_id: u64,
    },
}

impl From<MintMemo> for Memo {
    fn from(value: MintMemo) -> Self {
        Memo::from(encode(&value))
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub enum BurnMemo {
    #[n(0)]
    /// The minter processed a withdrawal request.
    Convert {
        #[n(0)]
        /// The destination of the withdrawal request.
        to_address: Address,
    },
    /// The minter processed a ckERC20 withdrawal request
    /// and that burn pays the transaction fee.
    #[n(1)]
    Erc20GasFee {
        /// ckERC20 token symbol of the withdrawal request.
        #[n(0)]
        ckerc20_token_symbol: CkTokenSymbol,

        /// The amount of the ckERC20 withdrawal request.
        #[n(1)]
        ckerc20_withdrawal_amount: Erc20Value,

        /// The destination of the withdrawal request.
        #[n(2)]
        to_address: Address,
    },
    /// The minter processed a ckERC20 withdrawal request.
    #[n(2)]
    Erc20Convert {
        /// ckETH ledger burn index identifying the burn to pay for the transaction fee.
        #[n(0)]
        ckerc20_withdrawal_id: u64,

        /// The destination of the withdrawal request.
        #[n(1)]
        to_address: Address,
    },
}

impl From<BurnMemo> for Memo {
    fn from(value: BurnMemo) -> Self {
        Memo::from(encode(&value))
    }
}

impl From<&ReceivedEvent> for Memo {
    fn from(event: &ReceivedEvent) -> Self {
        Memo::from(MintMemo::Convert {
            from_address: event.from_address(),
            tx_hash: event.transaction_hash(),
            log_index: event.log_index(),
        })
    }
}

impl From<ReimbursementRequest> for MintMemo {
    fn from(reimbursement_request: ReimbursementRequest) -> Self {
        match reimbursement_request.transaction_hash {
            Some(tx_hash) => MintMemo::ReimburseTransaction {
                withdrawal_id: reimbursement_request.ledger_burn_index.get(),
                tx_hash,
            },
            None => MintMemo::ReimburseWithdrawal {
                withdrawal_id: reimbursement_request.ledger_burn_index.get(),
            },
        }
    }
}

impl From<ReimbursementRequest> for Memo {
    fn from(reimbursement_request: ReimbursementRequest) -> Self {
        Memo::from(MintMemo::from(reimbursement_request))
    }
}
