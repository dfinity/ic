use crate::endpoints::InitArg;
use crate::eth_rpc::BlockNumber;
use crate::eth_rpc::Hash;
use crate::numeric::TransactionNonce;
use crate::transactions::PendingEthTransactions;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    pub static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub ecdsa_key_name: String,
    pub last_seen_block_number: BlockNumber,
    pub minted_transactions: BTreeSet<Hash>,
    pub invalid_transactions: BTreeSet<Hash>,
    pub num_issued_transactions: TransactionNonce,
    pub pending_retrieve_eth_requests: PendingEthTransactions,
}

impl Default for State {
    fn default() -> Self {
        let initial_nonce = TransactionNonce::from(3);
        Self {
            ecdsa_key_name: "test_key_1".to_string(),
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_seen_block_number: BlockNumber::new(3_956_206),
            minted_transactions: BTreeSet::new(),
            invalid_transactions: BTreeSet::new(),
            num_issued_transactions: initial_nonce,
            pending_retrieve_eth_requests: PendingEthTransactions::new(
                initial_nonce
                    .checked_increment()
                    .expect("transaction nonce overflow"),
            ),
        }
    }
}

impl From<InitArg> for State {
    fn from(InitArg { ecdsa_key_name }: InitArg) -> Self {
        Self {
            ecdsa_key_name,
            ..Self::default()
        }
    }
}

impl State {
    pub fn increment_and_get_nonce(&mut self) -> TransactionNonce {
        let incremented_nonce = self
            .num_issued_transactions
            .checked_increment()
            .expect("transaction nonce overflow");
        self.num_issued_transactions = incremented_nonce;
        incremented_nonce
    }
}

pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("BUG: state is not initialized")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| {
        f(s.borrow_mut()
            .as_mut()
            .expect("BUG: state is not initialized"))
    })
}
