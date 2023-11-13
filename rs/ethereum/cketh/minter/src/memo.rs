#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::eth_logs::ReceivedEthEvent;
use crate::eth_rpc::Hash;
use crate::numeric::LogIndex;
use crate::state::transactions::ReimbursementRequest;
use icrc_ledger_types::icrc1::transfer::Memo;
use minicbor::{Decode, Encode, Encoder};
use serde_bytes::ByteBuf;

/// Encodes minter memo as a binary blob.
pub fn encode<T: minicbor::Encode<()>>(t: &T) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.encode(t).expect("minicbor encoding failed");
    encoder.into_writer()
}

#[derive(Decode, Encode, Debug, Eq, PartialEq)]
pub enum MintMemo {
    #[n(0)]
    /// The minter received some ETH.
    Convert {
        #[n(0)]
        /// The sender of the ETH.
        from_address: Address,
        #[n(1)]
        /// Hash of the transaction.
        tx_hash: Hash,
        #[n(2)]
        log_index: LogIndex,
    },
    #[n(1)]
    Reimburse {
        #[n(0)]
        /// The id corresponding to the withdrawal request.
        withdrawal_id: u64,
        #[n(1)]
        /// Hash of the failed transaction.
        tx_hash: Hash,
    },
}

#[derive(Decode, Encode, Debug, Eq, PartialEq)]
pub enum BurnMemo {
    #[n(0)]
    /// The minter processed a withdraw request.
    Convert {
        #[n(0)]
        /// The destination of the withdraw request.
        to_address: Address,
    },
}

impl From<ReceivedEthEvent> for Memo {
    fn from(event: ReceivedEthEvent) -> Self {
        let memo = MintMemo::Convert {
            from_address: event.from_address,
            tx_hash: event.transaction_hash,
            log_index: event.log_index,
        };
        let memo_bytes = encode(&memo);
        Memo(ByteBuf::from(memo_bytes))
    }
}

impl From<ReimbursementRequest> for Memo {
    fn from(reimbursement_request: ReimbursementRequest) -> Self {
        let memo = MintMemo::Reimburse {
            withdrawal_id: reimbursement_request.withdrawal_id.get(),
            tx_hash: reimbursement_request
                .transaction_hash
                .expect("A hash should be set for reimbursement memos."),
        };
        let memo_bytes = encode(&memo);
        Memo(ByteBuf::from(memo_bytes))
    }
}

impl From<Address> for Memo {
    fn from(address: Address) -> Self {
        let memo = BurnMemo::Convert {
            to_address: address,
        };
        let memo_bytes = encode(&memo);
        Memo(ByteBuf::from(memo_bytes))
    }
}
